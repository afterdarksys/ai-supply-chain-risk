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

if __name__ == "__main__": unittest.main()
