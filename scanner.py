#!/usr/bin/env python3
"""Dependency-free CycloneDX SBOM and AI supply-chain research scanner."""
import argparse
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

VERSION = "2.0.0"
SEVERITIES = ("info", "low", "medium", "high", "critical")
SEVERITY_VALUE = {value: index for index, value in enumerate(SEVERITIES)}
HASH_LENGTHS = {"SHA-1": 40, "SHA-256": 64, "SHA-384": 96, "SHA-512": 128}
AI_COMPONENT_TYPES = {"machine-learning-model", "model", "dataset", "data"}
AI_PROPERTY_MARKERS = ("ai:", "ml:", "model", "dataset", "training-data", "data-source")
MOVING_REVISIONS = {"latest", "main", "master", "head", "dev", "snapshot"}
UNSAFE_MODEL_SUFFIXES = (".pt", ".pth", ".ckpt", ".pkl", ".pickle")
UNSAFE_MODEL_FILENAMES = {"pytorch_model.bin", "pytorch_model.bin.index.json"}
OSV_ECOSYSTEMS = {"apk", "cargo", "composer", "deb", "gem", "go", "hex", "maven", "npm", "nuget", "pypi", "rpm"}
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
MAX_VULNERABILITIES = 100


class SBOMIntegrityAuditor:
    """Validate CycloneDX metadata and optionally corroborate package hashes."""
    def __init__(self, sbom_path: str, offline: bool = False, timeout: float = 5.0, vulnerabilities: bool = False):
        self.sbom_path, self.offline, self.timeout, self.vulnerabilities_requested = Path(sbom_path), offline, timeout, vulnerabilities
        self.findings: List[Dict[str, Any]] = []
        self.components: List[Dict[str, Any]] = []
        self.ai_assets: List[Dict[str, Any]] = []
        self.vulnerabilities: List[Dict[str, Any]] = []

    def finding(self, severity: str, code: str, message: str, component: Optional[Dict[str, Any]] = None,
                evidence: Optional[Dict[str, Any]] = None) -> None:
        item: Dict[str, Any] = {"severity": severity, "code": code, "message": message}
        if component:
            item["component"] = {key: component.get(key, "<unknown>") for key in ("name", "version", "purl")}
        if evidence:
            item["evidence"] = evidence
        self.findings.append(item)

    def audit(self) -> Dict[str, Any]:
        try:
            with self.sbom_path.open(encoding="utf-8") as source:
                document = json.load(source)
        except (OSError, json.JSONDecodeError) as exc:
            self.finding("critical", "SBOM_UNREADABLE", f"Cannot read valid JSON: {exc}")
            return self.report()
        if not isinstance(document, dict):
            self.finding("critical", "SBOM_INVALID", "Top-level SBOM value must be an object")
            return self.report()
        if document.get("bomFormat") != "CycloneDX":
            self.finding("high", "UNEXPECTED_FORMAT", "Expected bomFormat to be CycloneDX")
        raw_components = document.get("components")
        if not isinstance(raw_components, list):
            self.finding("critical", "COMPONENTS_MISSING", "CycloneDX SBOM must contain a components array")
            return self.report()
        self.components = [item for item in raw_components if isinstance(item, dict)]
        for item in raw_components:
            if not isinstance(item, dict):
                self.finding("high", "COMPONENT_INVALID", "A component must be an object")
        identities = [self.identity(item) for item in self.components]
        for identity, count in Counter(x for x in identities if x).items():
            if count > 1:
                self.finding("medium", "DUPLICATE_COMPONENT", f"Component appears {count} times: {identity}")
        for component in self.components:
            self.audit_component(component)
        if self.vulnerabilities_requested and not self.offline:
            self.enrich_vulnerabilities()
        return self.report()

    @staticmethod
    def identity(component: Dict[str, Any]) -> str:
        return str(component.get("purl") or "@".join(str(component.get(k, "")) for k in ("name", "version")))

    def audit_component(self, component: Dict[str, Any]) -> None:
        name, version = component.get("name"), component.get("version")
        if not isinstance(name, str) or not name.strip():
            self.finding("high", "NAME_MISSING", "Component has no usable name", component)
        if not isinstance(version, str) or not version.strip():
            self.finding("high", "VERSION_MISSING", "Component has no usable version", component)
        ecosystem, package_name, package_version = self.parse_purl(component.get("purl"))
        if component.get("purl") and not ecosystem:
            self.finding("medium", "PURL_INVALID", "Package URL is not a supported valid purl", component)
        if ecosystem and package_version != version:
            self.finding("medium", "PURL_VERSION_MISMATCH", "purl version differs from component version", component)
        hashes = component.get("hashes", [])
        if not isinstance(hashes, list):
            self.finding("high", "HASHES_INVALID", "hashes must be an array", component)
            hashes = []
        if not hashes:
            self.finding("medium", "HASH_MISSING", "No cryptographic hash is declared", component)
        self.validate_hashes(component, hashes)
        asset_type = self.ai_asset_type(component, ecosystem)
        if asset_type:
            self.audit_ai_asset(component, asset_type, hashes, ecosystem, package_name, package_version)
        if ecosystem and package_name and package_version and not self.offline:
            self.verify_registry(component, ecosystem, package_name, package_version, hashes)

    @staticmethod
    def properties(component: Dict[str, Any]) -> Dict[str, str]:
        """Return CycloneDX properties in a convenient, case-insensitive form."""
        raw = component.get("properties", [])
        if not isinstance(raw, list):
            return {}
        return {str(item.get("name", "")).lower(): str(item.get("value", ""))
                for item in raw if isinstance(item, dict) and item.get("name")}

    def ai_asset_type(self, component: Dict[str, Any], ecosystem: Optional[str]) -> Optional[str]:
        component_type = str(component.get("type", "")).lower()
        props = self.properties(component)
        declared = props.get("ai:asset-type", props.get("cdx:ai:asset-type", "")).lower()
        if declared in {"model", "dataset"}:
            return declared
        if component_type in {"machine-learning-model", "model"} or ecosystem == "huggingface":
            return "model"
        if component_type in {"dataset", "data"}:
            return "dataset"
        if any(marker in key for key in props for marker in AI_PROPERTY_MARKERS):
            return "model" if "model" in " ".join(props) else "dataset"
        return None

    @staticmethod
    def external_urls(component: Dict[str, Any]) -> List[str]:
        refs = component.get("externalReferences", [])
        if not isinstance(refs, list):
            return []
        return [str(ref.get("url")) for ref in refs if isinstance(ref, dict) and isinstance(ref.get("url"), str)]

    @staticmethod
    def has_license(component: Dict[str, Any]) -> bool:
        licenses = component.get("licenses", [])
        if not isinstance(licenses, list):
            return False
        return any(isinstance(item, dict) and (item.get("expression") or
                   (isinstance(item.get("license"), dict) and (item["license"].get("id") or item["license"].get("name"))))
                   for item in licenses)

    def audit_ai_asset(self, component: Dict[str, Any], asset_type: str, hashes: List[Any],
                       ecosystem: Optional[str], package_name: Optional[str], version: Optional[str]) -> None:
        """Check the provenance, reproducibility, and unsafe-format signals unique to AI assets."""
        props, urls = self.properties(component), self.external_urls(component)
        self.ai_assets.append({"name": component.get("name", "<unknown>"), "version": component.get("version", "<unknown>"),
                               "type": asset_type, "purl": component.get("purl"), "sources": urls})
        if not urls and not component.get("purl"):
            self.finding("high", "AI_PROVENANCE_MISSING", "AI asset has no purl or external provenance reference", component)
        if not self.has_license(component):
            self.finding("medium", "AI_LICENSE_MISSING", "AI asset has no declared license; redistribution and use cannot be assessed", component)
        if not hashes:
            self.finding("high", "AI_ARTIFACT_HASH_MISSING", "AI artifacts should include a cryptographic hash for reproducibility", component)
        revision = str(component.get("version", "")).strip().lower()
        if revision in MOVING_REVISIONS:
            self.finding("high", "AI_MUTABLE_REVISION", f"AI asset uses mutable revision '{revision}'; pin a release or commit digest", component)
        if asset_type == "model":
            has_card = any("huggingface.co" in url or "modelcard" in url.lower() for url in urls)
            if not has_card:
                self.finding("medium", "MODEL_CARD_MISSING", "Model has no model-card or repository reference", component)
            lineage_keys = ("ai:training-data", "cdx:ai:training-data", "ml:training-data", "dataset", "data-source")
            if not any(key in props and props[key].strip() for key in lineage_keys):
                self.finding("low", "TRAINING_DATA_LINEAGE_MISSING", "Model does not identify its training-data lineage", component)
        if ecosystem == "huggingface" and package_name and version and not self.offline:
            self.verify_huggingface(component, package_name, version)

    @staticmethod
    def parse_purl(purl: Any) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        if not isinstance(purl, str): return None, None, None
        match = re.match(r"^pkg:([a-zA-Z0-9.+-]+)/(.+)@([^?#]+)(?:[?#].*)?$", purl)
        if not match: return None, None, None
        return match.group(1).lower(), urllib.parse.unquote(match.group(2)), urllib.parse.unquote(match.group(3))

    def validate_hashes(self, component: Dict[str, Any], hashes: Iterable[Any]) -> None:
        for entry in hashes:
            if not isinstance(entry, dict):
                self.finding("high", "HASH_INVALID", "Hash entry must be an object", component); continue
            algorithm, content = str(entry.get("alg", "")).upper(), str(entry.get("content", ""))
            length = HASH_LENGTHS.get(algorithm)
            if length is None:
                self.finding("medium", "HASH_ALGORITHM_UNKNOWN", f"Unsupported hash algorithm: {algorithm or '<empty>'}", component)
            elif not re.fullmatch(r"[0-9a-fA-F]+", content) or len(content) != length:
                self.finding("high", "HASH_MALFORMED", f"{algorithm} hash must be {length} hexadecimal characters", component)
            elif algorithm == "SHA-1":
                self.finding("low", "WEAK_HASH", "SHA-1 is weak; include SHA-256 or stronger", component)

    def get_json(self, url: str) -> Optional[Dict[str, Any]]:
        request = urllib.request.Request(url, headers={"User-Agent": f"sbom-integrity-scanner/{VERSION}", "Accept": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                data = json.loads(response.read().decode("utf-8")) if response.status == 200 else None
                return data if isinstance(data, dict) else None
        except urllib.error.HTTPError as exc:
            if exc.code == 404: raise LookupError("Registry returned 404") from exc
            raise ConnectionError(f"Registry returned HTTP {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise ConnectionError(str(exc)) from exc

    def get_text(self, url: str) -> str:
        request = urllib.request.Request(url, headers={"User-Agent": f"sbom-integrity-scanner/{VERSION}"})
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                if response.status != 200:
                    raise ConnectionError(f"Registry returned HTTP {response.status}")
                return response.read().decode("utf-8").strip()
        except urllib.error.HTTPError as exc:
            if exc.code == 404: raise LookupError("Registry returned 404") from exc
            raise ConnectionError(f"Registry returned HTTP {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            raise ConnectionError(str(exc)) from exc

    def post_json(self, url: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        request = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), method="POST",
                                         headers={"User-Agent": f"sbom-integrity-scanner/{VERSION}", "Content-Type": "application/json", "Accept": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                data = json.loads(response.read().decode("utf-8")) if response.status == 200 else None
                return data if isinstance(data, dict) else {}
        except urllib.error.HTTPError as exc:
            raise ConnectionError(f"Registry returned HTTP {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise ConnectionError(str(exc)) from exc

    def enrich_vulnerabilities(self) -> None:
        """Query OSV by versioned purl, then elevate CVEs in CISA's KEV catalog."""
        query_components = []
        for component in self.components:
            ecosystem, _, _ = self.parse_purl(component.get("purl"))
            if ecosystem in OSV_ECOSYSTEMS:
                query_components.append(component)
        if not query_components:
            return
        try:
            results = self.post_json(OSV_BATCH_URL, {"queries": [{"package": {"purl": component["purl"]}} for component in query_components]}).get("results", [])
            kev_data = self.get_json(CISA_KEV_URL) or {}
            kev_cves = {str(item.get("cveID", "")) for item in kev_data.get("vulnerabilities", []) if isinstance(item, dict)}
        except ConnectionError as exc:
            self.finding("info", "VULNERABILITY_DATABASE_UNAVAILABLE", f"Could not query OSV/CISA KEV: {exc}")
            return
        candidates = []
        for component, result in zip(query_components, results):
            if not isinstance(result, dict):
                continue
            for vuln in result.get("vulns", []):
                if isinstance(vuln, dict) and vuln.get("id"):
                    candidates.append((component, str(vuln["id"])))
        if len(candidates) > MAX_VULNERABILITIES:
            self.finding("info", "VULNERABILITY_RESULTS_TRUNCATED", f"Limited enrichment to the first {MAX_VULNERABILITIES} advisories")
            candidates = candidates[:MAX_VULNERABILITIES]
        seen_vulnerabilities = set()
        for component, osv_id in candidates:
            try:
                detail = self.get_json(f"https://api.osv.dev/v1/vulns/{urllib.parse.quote(osv_id, safe='')}") or {}
            except (ConnectionError, LookupError) as exc:
                self.finding("info", "VULNERABILITY_DATABASE_UNAVAILABLE", f"Could not retrieve {osv_id}: {exc}", component)
                continue
            aliases = [str(alias) for alias in detail.get("aliases", []) if isinstance(alias, str)]
            cves = [alias for alias in aliases if alias.startswith("CVE-")]
            # OSV often contains both GHSA and ecosystem-specific records for a
            # single CVE. Keep one finding per component/CVE set to make the
            # remediation queue readable.
            identity = (str(component.get("purl", "")), tuple(sorted(cves)) or (osv_id,))
            if identity in seen_vulnerabilities:
                continue
            seen_vulnerabilities.add(identity)
            kev = bool(set(cves) & kev_cves)
            database = detail.get("database_specific", {}) if isinstance(detail.get("database_specific"), dict) else {}
            declared_severity = str(database.get("severity", "")).upper()
            severity = "high" if kev or declared_severity in {"HIGH", "CRITICAL"} else "medium"
            fixed = self.fixed_versions(detail)
            record = {"id": osv_id, "aliases": aliases, "kev": kev, "severity": declared_severity or None,
                      "fixed_versions": fixed, "component": {key: component.get(key) for key in ("name", "version", "purl")},
                      "source": f"https://osv.dev/vulnerability/{osv_id}"}
            self.vulnerabilities.append(record)
            message = f"{osv_id}" + (f" ({', '.join(cves)})" if cves else "")
            if kev:
                message += " is listed in CISA KEV as exploited in the wild"
            elif fixed:
                message += f"; fixed version: {', '.join(fixed)}"
            self.finding(severity, "VULNERABILITY_KEV" if kev else "VULNERABILITY_FOUND", message, component,
                         {"source": record["source"], "fixed_versions": fixed, "kev": kev})

    @staticmethod
    def fixed_versions(vulnerability: Dict[str, Any]) -> List[str]:
        fixed = set()
        for affected in vulnerability.get("affected", []):
            if not isinstance(affected, dict):
                continue
            for range_item in affected.get("ranges", []):
                if not isinstance(range_item, dict):
                    continue
                for event in range_item.get("events", []):
                    if isinstance(event, dict) and event.get("fixed"):
                        fixed.add(str(event["fixed"]))
        return sorted(fixed)

    def verify_registry(self, component: Dict[str, Any], ecosystem: str, name: str, version: str, hashes: List[Any]) -> None:
        try:
            if ecosystem == "pypi":
                url = "https://pypi.org/pypi/{}/{}/json".format(urllib.parse.quote(name, safe=""), urllib.parse.quote(version, safe=""))
                data = self.get_json(url) or {}
                official = {str(item.get("digests", {}).get("sha256", "")).lower() for item in data.get("urls", [])}
                declared = {str(h.get("content", "")).lower() for h in hashes if isinstance(h, dict) and str(h.get("alg", "")).upper() == "SHA-256"}
                if declared and official and not declared & official:
                    self.finding("critical", "REGISTRY_HASH_MISMATCH", "No declared SHA-256 matches any PyPI distribution", component)
            elif ecosystem == "npm":
                url = "https://registry.npmjs.org/{}/{}".format(urllib.parse.quote(name, safe="@/"), urllib.parse.quote(version, safe=""))
                data = self.get_json(url) or {}
                official = str(data.get("dist", {}).get("shasum", "")).lower()
                declared = {str(h.get("content", "")).lower() for h in hashes if isinstance(h, dict) and str(h.get("alg", "")).upper() == "SHA-1"}
                if declared and official and official not in declared:
                    self.finding("critical", "REGISTRY_HASH_MISMATCH", "Declared SHA-1 does not match npm registry shasum", component)
            elif ecosystem == "nuget":
                self.verify_nuget(component, name, version, hashes)
            elif ecosystem in {"brew", "homebrew"}:
                self.verify_homebrew(component, name, version)
            elif ecosystem == "deb":
                self.verify_debian(component, name, version)
            elif ecosystem in {"rpm", "apk", "choco", "winget"}:
                self.finding("info", "REPOSITORY_CONTEXT_REQUIRED",
                             f"{ecosystem} packages require a configured repository/distribution reference for online corroboration", component)
        except LookupError as exc:
            self.finding("high", "REGISTRY_NOT_FOUND", str(exc), component)
        except ConnectionError as exc:
            self.finding("info", "REGISTRY_UNAVAILABLE", f"Could not corroborate package: {exc}", component)

    @staticmethod
    def registry_name(name: str) -> str:
        """Remove an optional purl namespace (e.g. deb/debian/bash -> bash)."""
        return name.rsplit("/", 1)[-1]

    def verify_nuget(self, component: Dict[str, Any], name: str, version: str, hashes: List[Any]) -> None:
        package = self.registry_name(name).lower()
        try:
            # The public PackageBaseAddress API exposes a package's content and
            # manifest, but not an authoritative standalone checksum.  Fetching
            # the small manifest establishes existence without downloading an
            # artifact just to calculate a digest.
            self.get_text("https://api.nuget.org/v3-flatcontainer/{0}/{1}/{0}.nuspec".format(
                urllib.parse.quote(package, safe=""), urllib.parse.quote(version.lower(), safe="")))
        except LookupError as exc:
            self.finding("high", "REGISTRY_NOT_FOUND", str(exc), component)
        except ConnectionError as exc:
            self.finding("info", "REGISTRY_UNAVAILABLE", f"Could not corroborate package: {exc}", component)

    def verify_homebrew(self, component: Dict[str, Any], name: str, version: str) -> None:
        formula = self.registry_name(name)
        try:
            data = self.get_json("https://formulae.brew.sh/api/formula/{}.json".format(urllib.parse.quote(formula, safe=""))) or {}
            current = str(data.get("versions", {}).get("stable", ""))
            if current and current != version:
                self.finding("info", "BREW_VERSION_NOT_CURRENT", f"Homebrew core currently reports version {current}; retain a repository snapshot for historical versions", component)
        except LookupError as exc:
            self.finding("high", "REGISTRY_NOT_FOUND", str(exc), component)
        except ConnectionError as exc:
            self.finding("info", "REGISTRY_UNAVAILABLE", f"Could not corroborate package: {exc}", component)

    def verify_debian(self, component: Dict[str, Any], name: str, version: str) -> None:
        package = self.registry_name(name)
        try:
            self.get_json("https://sources.debian.org/api/src/{}/{}/".format(
                urllib.parse.quote(package, safe=""), urllib.parse.quote(version, safe="")))
        except LookupError as exc:
            self.finding("high", "REGISTRY_NOT_FOUND", str(exc), component)
        except ConnectionError as exc:
            self.finding("info", "REGISTRY_UNAVAILABLE", f"Could not corroborate package: {exc}", component)

    def verify_huggingface(self, component: Dict[str, Any], model_id: str, revision: str) -> None:
        """Corroborate a public Hugging Face model revision and flag pickle-based artifacts.

        This does not execute, download, or deserialize model files.  It only reads
        the public metadata returned by the Hub API.
        """
        try:
            url = "https://huggingface.co/api/models/{}/revision/{}".format(
                urllib.parse.quote(model_id, safe="/"), urllib.parse.quote(revision, safe=""))
            data = self.get_json(url) or {}
            resolved = str(data.get("sha", ""))
            if re.fullmatch(r"[0-9a-fA-F]{7,40}", revision) and resolved and not resolved.lower().startswith(revision.lower()):
                self.finding("high", "MODEL_REVISION_MISMATCH", "Hub resolved a different commit than the SBOM revision", component)
            if data.get("gated"):
                self.finding("info", "MODEL_ACCESS_GATED", "Model is access-gated; acquisition requires an approved account", component)
            siblings = data.get("siblings", [])
            filenames = [str(item.get("rfilename", "")) for item in siblings if isinstance(item, dict)]
            unsafe = [name for name in filenames if Path(name).name.lower().endswith(UNSAFE_MODEL_SUFFIXES)
                      or Path(name).name.lower() in UNSAFE_MODEL_FILENAMES]
            if unsafe:
                self.finding("medium", "UNSAFE_MODEL_SERIALIZATION", "Registry lists potentially unsafe serialized model artifact(s): " + ", ".join(unsafe[:3]), component)
        except LookupError as exc:
            self.finding("high", "MODEL_REGISTRY_NOT_FOUND", str(exc), component)
        except ConnectionError as exc:
            self.finding("info", "MODEL_REGISTRY_UNAVAILABLE", f"Could not corroborate model: {exc}", component)

    def report(self) -> Dict[str, Any]:
        counts = {severity: 0 for severity in SEVERITIES}
        for finding in self.findings: counts[finding["severity"]] += 1
        maximum = max((x["severity"] for x in self.findings), key=SEVERITY_VALUE.get, default="info")
        asset_counts = Counter(asset["type"] for asset in self.ai_assets)
        return {"tool": "ai-supply-chain-scanner", "version": VERSION,
                "scanned_at": datetime.now(timezone.utc).isoformat(), "sbom": str(self.sbom_path),
                "components_scanned": len(self.components), "offline": self.offline,
                "ai_assets": {"total": len(self.ai_assets), "by_type": dict(asset_counts), "assets": self.ai_assets},
                "vulnerability_enrichment": {"requested": self.vulnerabilities_requested, "findings": self.vulnerabilities},
                "summary": {"findings": len(self.findings), "by_severity": counts, "max_severity": maximum}, "findings": self.findings}


def render_text(report: Dict[str, Any]) -> str:
    summary = report["summary"]
    ai_assets = report["ai_assets"]
    types = ", ".join(f"{kind}: {count}" for kind, count in sorted(ai_assets["by_type"].items())) or "none"
    lines = [f"AI supply-chain scan: {report['sbom']}",
             f"Components: {report['components_scanned']} | AI assets: {ai_assets['total']} ({types}) | Findings: {summary['findings']} | Maximum severity: {summary['max_severity']}"]
    for item in report["findings"]:
        target = item.get("component", {})
        suffix = f" [{target.get('name')}@{target.get('version')}]" if target else ""
        lines.append(f"{item['severity'].upper():8} {item['code']}: {item['message']}{suffix}")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate CycloneDX SBOM integrity and registry provenance")
    parser.add_argument("sbom", nargs="?", help="CycloneDX JSON SBOM to scan")
    parser.add_argument("--offline", action="store_true", help="Do not contact PyPI or npm")
    parser.add_argument("--vulns", action="store_true", help="Query OSV and CISA KEV for known vulnerabilities")
    parser.add_argument("--timeout", type=float, default=5.0, help="Registry request timeout in seconds")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--output", help="Write report to this path instead of stdout")
    parser.add_argument("--fail-on", choices=("none",) + SEVERITIES, default="high")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    args = parser.parse_args()
    if not args.sbom: parser.print_help(sys.stderr); return 2
    if args.timeout <= 0: parser.error("--timeout must be positive")
    report = SBOMIntegrityAuditor(args.sbom, args.offline, args.timeout, args.vulns).audit()
    payload = json.dumps(report, indent=2, sort_keys=True) if args.format == "json" else render_text(report)
    if args.output: Path(args.output).write_text(payload + "\n", encoding="utf-8")
    else: print(payload)
    return int(args.fail_on != "none" and SEVERITY_VALUE[report["summary"]["max_severity"]] >= SEVERITY_VALUE[args.fail_on])


if __name__ == "__main__": raise SystemExit(main())
