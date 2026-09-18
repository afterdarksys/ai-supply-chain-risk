#!/usr/bin/env python3
"""Dependency-free CycloneDX SBOM integrity scanner."""
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


class SBOMIntegrityAuditor:
    """Validate CycloneDX metadata and optionally corroborate package hashes."""
    def __init__(self, sbom_path: str, offline: bool = False, timeout: float = 5.0):
        self.sbom_path, self.offline, self.timeout = Path(sbom_path), offline, timeout
        self.findings: List[Dict[str, Any]] = []
        self.components: List[Dict[str, Any]] = []

    def finding(self, severity: str, code: str, message: str, component: Optional[Dict[str, Any]] = None) -> None:
        item: Dict[str, Any] = {"severity": severity, "code": code, "message": message}
        if component:
            item["component"] = {key: component.get(key, "<unknown>") for key in ("name", "version", "purl")}
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
        if ecosystem and package_name and package_version and not self.offline:
            self.verify_registry(component, ecosystem, package_name, package_version, hashes)

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
        except LookupError as exc:
            self.finding("high", "REGISTRY_NOT_FOUND", str(exc), component)
        except ConnectionError as exc:
            self.finding("info", "REGISTRY_UNAVAILABLE", f"Could not corroborate package: {exc}", component)

    def report(self) -> Dict[str, Any]:
        counts = {severity: 0 for severity in SEVERITIES}
        for finding in self.findings: counts[finding["severity"]] += 1
        maximum = max((x["severity"] for x in self.findings), key=SEVERITY_VALUE.get, default="info")
        return {"tool": "sbom-integrity-scanner", "version": VERSION, "scanned_at": datetime.now(timezone.utc).isoformat(), "sbom": str(self.sbom_path), "components_scanned": len(self.components), "offline": self.offline, "summary": {"findings": len(self.findings), "by_severity": counts, "max_severity": maximum}, "findings": self.findings}


def render_text(report: Dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [f"SBOM integrity scan: {report['sbom']}", f"Components: {report['components_scanned']} | Findings: {summary['findings']} | Maximum severity: {summary['max_severity']}"]
    for item in report["findings"]:
        target = item.get("component", {})
        suffix = f" [{target.get('name')}@{target.get('version')}]" if target else ""
        lines.append(f"{item['severity'].upper():8} {item['code']}: {item['message']}{suffix}")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate CycloneDX SBOM integrity and registry provenance")
    parser.add_argument("sbom", nargs="?", help="CycloneDX JSON SBOM to scan")
    parser.add_argument("--offline", action="store_true", help="Do not contact PyPI or npm")
    parser.add_argument("--timeout", type=float, default=5.0, help="Registry request timeout in seconds")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--output", help="Write report to this path instead of stdout")
    parser.add_argument("--fail-on", choices=("none",) + SEVERITIES, default="high")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    args = parser.parse_args()
    if not args.sbom: parser.print_help(sys.stderr); return 2
    if args.timeout <= 0: parser.error("--timeout must be positive")
    report = SBOMIntegrityAuditor(args.sbom, args.offline, args.timeout).audit()
    payload = json.dumps(report, indent=2, sort_keys=True) if args.format == "json" else render_text(report)
    if args.output: Path(args.output).write_text(payload + "\n", encoding="utf-8")
    else: print(payload)
    return int(args.fail_on != "none" and SEVERITY_VALUE[report["summary"]["max_severity"]] >= SEVERITY_VALUE[args.fail_on])


if __name__ == "__main__": raise SystemExit(main())
