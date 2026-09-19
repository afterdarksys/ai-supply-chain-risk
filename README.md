# AI Supply-Chain Scanner

A dependency-free CLI that turns CycloneDX JSON SBOMs into actionable AI
supply-chain research. It validates standard SBOM integrity, identifies model
and dataset assets, and checks their provenance, reproducibility, licensing,
training-data lineage, and model-artifact format. When online, it corroborates
PyPI/npm package hashes and public Hugging Face model revisions without
downloading or executing artifacts.

Findings are evidence-based signals, not a claim that a model, publisher, or
SBOM author is malicious.

```sh
# Deterministic validation for CI and air-gapped builds
python3 scanner.py ai_model_sbom.json --offline --format json --fail-on high

# Also corroborate PyPI/npm packages and Hugging Face models
python3 scanner.py my-bom.json --format text --fail-on medium

# Enrich package findings with OSV and CISA KEV vulnerability intelligence
python3 scanner.py my-bom.json --vulns --format json --output report.json
```

Exit status is `1` when a finding meets `--fail-on`, `0` otherwise, and `2` for
invalid CLI usage. Use `--output report.json` to save a report. PyPI SHA-256
values are compared to every published distribution, not an arbitrary first file.

## Describing AI assets

Use normal CycloneDX components with `type: machine-learning-model` or
`type: dataset` (or `properties: [{"name":"ai:asset-type","value":"model"}]`).
Include a pinned version, a purl, artifact hashes, a license, and external
references. For a model, use `ai:training-data` to record its dataset lineage.
Hugging Face models use `pkg:huggingface/<org>/<model>@<revision>`.

```json
{
  "type": "machine-learning-model",
  "name": "example-model",
  "version": "8f2c123",
  "purl": "pkg:huggingface/acme/example-model@8f2c123",
  "hashes": [{"alg": "SHA-256", "content": "<64 hex chars>"}],
  "licenses": [{"license": {"id": "Apache-2.0"}}],
  "properties": [{"name": "ai:training-data", "value": "acme/curated-data@2026-01"}],
  "externalReferences": [{"type": "documentation", "url": "https://huggingface.co/acme/example-model"}]
}
```

## Operating-system package SBOMs

CycloneDX validation and AI-asset research work on SBOMs from Linux, macOS, and
Windows. Online corroboration recognizes these purl ecosystems:

| Platform | purl type | Online evidence |
| --- | --- | --- |
| Debian Linux | `deb` | Debian Sources package/version existence |
| macOS or Linux Homebrew | `brew` / `homebrew` | Homebrew formula metadata and current version |
| Windows/.NET | `nuget` | NuGet package/version existence |
| RPM, Alpine, Chocolatey, winget | `rpm`, `apk`, `choco`, `winget` | Requires a repository/distribution reference; the scanner reports this rather than guessing a registry |

Use the namespace specified by the purl, for example
`pkg:deb/debian/curl@7.88.1-10+deb12u14`, `pkg:brew/wget@1.25.0`, or
`pkg:nuget/Newtonsoft.Json@13.0.3`. For RPM/APK and Windows package sources,
add an `externalReferences` entry identifying the approved repository snapshot
to make the source auditable.

## Vulnerability intelligence

Pass `--vulns` to query OSV with versioned purls and cross-reference returned
CVE aliases against CISA's Known Exploited Vulnerabilities catalog. The report
preserves the advisory ID, aliases, OSV source URL, KEV status, and known fixed
versions. This is opt-in; `--offline` makes no network calls even if `--vulns`
is supplied. Model and dataset records are not queried as software packages;
their runtime and serving dependencies are.
