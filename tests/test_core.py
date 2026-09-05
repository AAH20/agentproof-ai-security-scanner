import json
import tempfile
import unittest
from pathlib import Path

from agentproof.cli import main
from agentproof.core import build_passport, calculate_unit_economics, scan_manifest


FIXTURE = Path(__file__).parents[1] / "examples" / "secure-agent" / "agentproof.json"


class AgentProofTests(unittest.TestCase):
    def setUp(self):
        self.manifest = json.loads(FIXTURE.read_text())

    def test_secure_manifest_passes_all_checks(self):
        results = scan_manifest(self.manifest)
        self.assertEqual(len(results), 10)
        self.assertTrue(all(result.passed for result in results))

    def test_wildcard_tool_access_fails_critical_check(self):
        self.manifest["authority"]["allowed_tools"] = ["*"]
        failures = [result for result in scan_manifest(self.manifest) if not result.passed]
        self.assertEqual(failures[0].id, "APS-002")
        self.assertEqual(failures[0].severity, "critical")

    def test_passport_contains_hash_kpis_and_classification(self):
        passport = build_passport(self.manifest)
        self.assertEqual(passport["classification"], "synthetic")
        self.assertEqual(len(passport["evidence_sha256"]), 64)
        self.assertEqual(passport["kpis"]["unauthorized_action_prevention_rate"], 1.0)

    def test_unit_economics_are_transparent(self):
        metrics = calculate_unit_economics(self.manifest["economics"])
        self.assertEqual(metrics["total_evaluation_cost_usd"], 325.0)
        self.assertEqual(metrics["cost_per_evaluation_run_usd"], 32.5)
        self.assertEqual(metrics["review_labor_value_saved_usd"], 1300.0)
        self.assertEqual(metrics["risk_reduction_per_program_dollar"], 5.0)

    def test_cli_writes_passport(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "passport.json"
            rc = main(["scan", str(FIXTURE), "--output", str(output)])
            self.assertEqual(rc, 0)
            self.assertTrue(output.exists())


if __name__ == "__main__":
    unittest.main()
