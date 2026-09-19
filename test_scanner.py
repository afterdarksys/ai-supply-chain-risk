import json
import tempfile
import unittest
from pathlib import Path
from scanner import SBOMIntegrityAuditor

class AuditTests(unittest.TestCase):
    def audit(self, document):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bom.json"; path.write_text(json.dumps(document))
            return SBOMIntegrityAuditor(str(path), offline=True).audit()

    def test_valid_component_is_clean_offline(self):
        report = self.audit({"bomFormat":"CycloneDX", "components":[{"name":"requests", "version":"2.31.0", "purl":"pkg:pypi/requests@2.31.0", "hashes":[{"alg":"SHA-256", "content":"a" * 64}]}]})
        self.assertEqual(report["summary"]["findings"], 0)

    def test_detects_missing_and_malformed_hashes(self):
        report = self.audit({"bomFormat":"CycloneDX", "components":[{"name":"x", "version":"1", "hashes":[{"alg":"SHA-256", "content":"not-a-hash"}]}, {"name":"y", "version":"1"}]})
        self.assertEqual(report["summary"]["by_severity"]["high"], 1)
        self.assertEqual(report["summary"]["by_severity"]["medium"], 1)

    def test_duplicate_and_purl_mismatch(self):
        item = {"name":"x", "version":"1", "purl":"pkg:pypi/x@2", "hashes":[{"alg":"SHA-256", "content":"b" * 64}]}
        report = self.audit({"bomFormat":"CycloneDX", "components":[item, item]})
        codes = {finding["code"] for finding in report["findings"]}
        self.assertTrue({"DUPLICATE_COMPONENT", "PURL_VERSION_MISMATCH"}.issubset(codes))

    def test_ai_model_research_signals(self):
        report = self.audit({"bomFormat": "CycloneDX", "components": [{
            "type": "machine-learning-model", "name": "untracked-model", "version": "main",
            "purl": "pkg:huggingface/acme/untracked-model@main"
        }]})
        codes = {finding["code"] for finding in report["findings"]}
        self.assertEqual(report["ai_assets"]["by_type"], {"model": 1})
        self.assertTrue({"AI_ARTIFACT_HASH_MISSING", "AI_LICENSE_MISSING", "AI_MUTABLE_REVISION",
                         "MODEL_CARD_MISSING", "TRAINING_DATA_LINEAGE_MISSING"}.issubset(codes))

    def test_documented_pinned_ai_asset_avoids_research_gaps(self):
        component = {
            "type": "machine-learning-model", "name": "tracked", "version": "abc1234",
            "purl": "pkg:huggingface/acme/tracked@abc1234",
            "hashes": [{"alg": "SHA-256", "content": "c" * 64}],
            "licenses": [{"license": {"id": "Apache-2.0"}}],
            "properties": [{"name": "ai:training-data", "value": "acme/data@2026-01"}],
            "externalReferences": [{"type": "documentation", "url": "https://huggingface.co/acme/tracked"}]
        }
        report = self.audit({"bomFormat": "CycloneDX", "components": [component]})
        self.assertEqual(report["summary"]["findings"], 0)

    def test_os_purl_namespaces_are_retained_and_normalized_for_registries(self):
        self.assertEqual(SBOMIntegrityAuditor.parse_purl("pkg:deb/debian/curl@7.88.1-10%2Bdeb12u14"),
                         ("deb", "debian/curl", "7.88.1-10+deb12u14"))
        self.assertEqual(SBOMIntegrityAuditor.registry_name("fedora/openssl-libs"), "openssl-libs")
        report = self.audit({"bomFormat": "CycloneDX", "components": [{
            "name": "Newtonsoft.Json", "version": "13.0.3", "purl": "pkg:nuget/Newtonsoft.Json@13.0.3"
        }]})
        self.assertEqual(report["summary"]["findings"], 1)  # Offline: only its missing hash is reported.

    def test_vulnerability_enrichment_records_fixes_and_kev_status(self):
        class StubAuditor(SBOMIntegrityAuditor):
            def post_json(self, url, payload):
                if url != "https://api.osv.dev/v1/querybatch":
                    raise AssertionError(url)
                return {"results": [{"vulns": [{"id": "GHSA-test"}]}]}

            def get_json(self, url):
                if "known_exploited" in url:
                    return {"vulnerabilities": [{"cveID": "CVE-2025-0001"}]}
                return {"aliases": ["CVE-2025-0001"], "database_specific": {"severity": "CRITICAL"},
                        "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]}]}

        document = {"bomFormat": "CycloneDX", "components": [{"name": "demo", "version": "1.0.0",
                    "purl": "pkg:pypi/demo@1.0.0", "hashes": [{"alg": "SHA-256", "content": "a" * 64}]}]}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bom.json"; path.write_text(json.dumps(document))
            report = StubAuditor(str(path), vulnerabilities=True).audit()
        finding = next(item for item in report["findings"] if item["code"] == "VULNERABILITY_KEV")
        self.assertEqual(finding["evidence"]["fixed_versions"], ["2.0.0"])
        self.assertTrue(report["vulnerability_enrichment"]["findings"][0]["kev"])

if __name__ == "__main__": unittest.main()
