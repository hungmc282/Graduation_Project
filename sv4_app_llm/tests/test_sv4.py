"""Run: python -B -m unittest discover -s tests -v"""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from sv4_app_llm.storage.repository import get_record, list_records, save_record
from sv4_app_llm.reports.export import export_json, export_markdown
from sv4_app_llm.service import run_analysis, validate_assets, explain_report, save_explanation


class SV4Tests(unittest.TestCase):
    def asset(self):
        return dict(asset_id="A1", name="Web", asset_type=None,
                    internet_facing=None, criticality=None, sensitive_data=None)

    def test_unknown_and_invalid_assets(self):
        self.assertIsNone(validate_assets([self.asset()])[0]["criticality"])
        for change in ({"criticality": True}, {"criticality": 6},
                       {"internet_facing": "false"}, {"name": " "}):
            with self.assertRaises(ValueError):
                validate_assets([self.asset() | change])
        with self.assertRaises(ValueError):
            validate_assets([self.asset(), self.asset()])

    def test_durable_snapshots(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/"history.sqlite3"
            data = {"assets": [self.asset()]}
            record_id = save_record("draft", "example", data, path)
            data["assets"].clear()
            self.assertEqual(len(get_record(record_id, path)["payload"]["assets"]), 1)
            self.assertEqual(len(list_records("draft", path)), 1)
            self.assertEqual(list_records("analysis", path), [])

    def test_engine_boundary(self):
        with self.assertRaises(NotImplementedError):
            run_analysis("integrated", draft_id="draft")
        with self.assertRaises(ValueError):
            run_analysis("demo", scenario="before-F01", patched_finding_ids=["F02"])

    def test_reports_and_exports(self):
        envelope = run_analysis("demo", scenario="before-F01")
        self.assertAlmostEqual(envelope["report"]["analysis"]["risk_before"], 41.2825)
        self.assertEqual(json.loads(export_json(envelope))["envelope"], envelope)
        text = export_markdown(envelope).decode()
        self.assertIn("HEURISTIC_INDEX", text)
        self.assertIn(envelope["report"]["analysis"]["analysis_id"], text)
        with self.assertRaises(ValueError):
            export_markdown(envelope, {"analysis_ids": ["wrong"]})

    def test_explanation_cannot_attach_to_other_report(self):
        envelope = run_analysis("demo", scenario="before-F01")
        wrong = {"analysis_ids": ["wrong"]}
        with self.assertRaises(ValueError):
            save_explanation(envelope, wrong)
        with self.assertRaises(ValueError):
            export_json(envelope, wrong)

    def test_ai_provenance_without_network(self):
        envelope = run_analysis("demo", scenario="before-F01")
        with patch("sv4_app_llm.service.explain_demo", return_value=("Example", "test-model")) as mock:
            result = explain_report(envelope, "Why?", compare=True)
        self.assertEqual(len(result["analysis_ids"]), 2)
        self.assertEqual(result["validation_status"], "not_verified")
        self.assertEqual(result["model_id"], "test-model")
        self.assertEqual(len(mock.call_args.args[0]), 2)


if __name__ == "__main__":
    unittest.main()
