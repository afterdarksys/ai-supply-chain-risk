# SBOM Integrity Scanner

A dependency-free CLI that checks CycloneDX JSON SBOMs for malformed metadata,
weak or missing hashes, duplicate components, and (when online) package-registry
corroboration. Findings are evidence-based; it does not infer who authored an SBOM.

```sh
# Deterministic validation for CI and air-gapped builds
python3 scanner.py legit_sbom.json --offline --format json --fail-on high

# Also corroborate PyPI/npm package hashes
python3 scanner.py my-bom.json --format text --fail-on medium
```

Exit status is `1` when a finding meets `--fail-on`, `0` otherwise, and `2` for
invalid CLI usage. Use `--output report.json` to save a report. PyPI SHA-256
values are compared to every published distribution, not an arbitrary first file.
