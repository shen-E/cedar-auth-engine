import json
import pathlib
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

import integration_baseline as baseline


class IntegrationBaselineTest(unittest.TestCase):
    def test_fixture_path_stays_in_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "snapshot"
            root.mkdir()
            (root / "ok").write_text("ok", encoding="utf-8")
            self.assertEqual(baseline.fixture_path(root, "ok"), (root / "ok").resolve())
            with self.assertRaises(ValueError):
                baseline.fixture_path(root, "../outside")

    def test_schema_reference_and_unsupported_policy_are_counted_separately(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "tests").mkdir()
            for name in ("policy", "entities", "schema"):
                (root / name).write_text("{}", encoding="utf-8")
            request = {"principal": {"type": "User", "id": "a"},
                       "action": {"type": "Action", "id": "read"},
                       "resource": {"type": "File", "id": "a"},
                       "context": {}, "decision": "allow", "reason": ["policy0"], "errors": []}
            case = {"policies": "policy", "entities": "entities", "schema": "schema",
                    "shouldValidate": True, "requests": [request]}
            (root / "tests" / "a.json").write_text(json.dumps(case), encoding="utf-8")
            case["policyFormat"] = "json"
            (root / "tests" / "b.json").write_text(json.dumps(case), encoding="utf-8")
            case["policyFormat"] = "cedar"
            request["validateRequest"] = True
            (root / "tests" / "c.json").write_text(json.dumps(case), encoding="utf-8")
            (root / "tests" / "not-a-case.json").write_text("{}", encoding="utf-8")
            calls = []

            def fake_run(args):
                calls.append(args)
                if args[1] == "validate":
                    return SimpleNamespace(returncode=0, stdout="", stderr="")
                if args[1] == "authorize" and args[0] == "cedar":
                    return SimpleNamespace(returncode=0, stdout="ALLOW\n  policy0\n", stderr="")
                return SimpleNamespace(returncode=0, stdout=json.dumps(
                    {"decision": "Allow", "reasons": ["policy0"], "errors": []}), stderr="")

            with patch.object(baseline, "run", side_effect=fake_run):
                report = baseline.compare(root, "engine", "cedar")
            self.assertEqual(report["cases_total"], 3)
            self.assertEqual(report["counts"]["requests_pass"], 1)
            self.assertEqual(report["counts"]["requests_unsupported_policy_format"], 1)
            self.assertEqual(report["counts"]["requests_unsupported_request_validation"], 1)
            self.assertEqual(report["counts"]["schema_unsupported"], 3)
            reference_calls = [call for call in calls if call[:2] == ["cedar", "authorize"]]
            self.assertEqual(len(reference_calls), 3)
            self.assertTrue(all("--schema" in call and "--schema-format" in call for call in reference_calls))
            self.assertIn("true", reference_calls[2])

    def test_fixture_disagreement_does_not_hide_engine_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "tests").mkdir()
            for name in ("policy", "entities", "schema"):
                (root / name).write_text("{}", encoding="utf-8")
            uid = {"type": "T", "id": "x"}
            case = {"policies": "policy", "entities": "entities", "schema": "schema",
                    "shouldValidate": True, "requests": [{"principal": uid, "action": uid,
                    "resource": uid, "context": {}, "decision": "allow", "reason": [], "errors": []}]}
            (root / "tests" / "case.json").write_text(json.dumps(case), encoding="utf-8")

            def fake_run(args):
                if args[1] == "validate":
                    return SimpleNamespace(returncode=0, stdout="", stderr="")
                if args[0] == "cedar":
                    return SimpleNamespace(returncode=0, stdout="DENY\n", stderr="")
                return SimpleNamespace(returncode=0, stdout='{"decision":"Allow","reasons":[],"errors":[]}', stderr="")

            with patch.object(baseline, "run", side_effect=fake_run):
                report = baseline.compare(root, "engine", "cedar")
            self.assertEqual(report["counts"]["requests_reference_differs_from_fixture"], 1)
            self.assertEqual(report["counts"]["requests_mismatch"], 1)


if __name__ == "__main__":
    unittest.main()
