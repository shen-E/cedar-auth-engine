#!/usr/bin/env python3
"""Exercise the built native CLI against the checked-in examples."""
import json
import pathlib
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
directory = ROOT / "_build" / "native" / "debug" / "build" / "cmd" / "cedar-auth-engine"
binary = next((p for p in (directory / "cedar-auth-engine.exe", directory / "cedar-auth-engine") if p.is_file()), directory / "cedar-auth-engine")


def run(*args):
    return subprocess.run([str(binary), *map(str, args)], capture_output=True, text=True, encoding="utf-8", timeout=30)


def main():
    checks = 0
    for name in ("tenant", "sharing", "admin", "risk", "classified", "invoices", "quota", "network", "tags", "diagnostics", "device", "approvals", "session"):
        base = ROOT / "examples" / name
        policy, entities, cases = (base / "policy.cedar", base / "entities.json", base / "requests.json")
        result = run("check", policy, "--format", "json")
        assert result.returncode == 0 and json.loads(result.stdout)["valid"]
        checks += 1
        result = run("test", policy, entities, cases, "--format", "json")
        report = json.loads(result.stdout)
        assert result.returncode == 0 and report["failures"] == 0
        checks += 1
        for item in json.loads(cases.read_text(encoding="utf-8")):
            with tempfile.TemporaryDirectory() as tmp:
                request = pathlib.Path(tmp) / "request.json"
                request.write_text(json.dumps(item["request"]), encoding="utf-8")
                result = run("authorize", policy, entities, request, "--format", "json")
                assert result.returncode == 0 and json.loads(result.stdout)["decision"] == item["decision"]
                checks += 1
    with tempfile.TemporaryDirectory() as tmp:
        path = pathlib.Path(tmp)
        policy = path / "invalid.cedar"
        policy.write_text("permit(principal, action, resource) when { context.x / 1 > 1 };", encoding="utf-8")
        assert run("check", policy).returncode == 2
        checks += 1
        policy.write_text('@id("read-access") @owner("security") @review permit(principal, action, resource);', encoding="utf-8")
        result = run("check", policy, "--format", "json")
        metadata = json.loads(result.stdout)
        assert result.returncode == 0 and metadata["policies"] == [{"id": "read-access", "effect": "permit", "annotations": {"id": "read-access", "owner": "security", "review": ""}}]
        checks += 1
        policy.write_text("permit(principal, action, resource);", encoding="utf-8")
        entities = path / "duplicate.json"
        entities.write_text('[{"uid":{"type":"User","type":"Other","id":"a"},"attrs":{},"parents":[]}]', encoding="utf-8")
        request = path / "request.json"
        request.write_text('{}', encoding="utf-8")
        result = run("authorize", policy, entities, request, "--format", "json")
        assert result.returncode == 2 and "duplicate JSON key" in result.stderr
        checks += 1
        invalid_tags = path / "invalid-tags.json"
        invalid_tags.write_text('[{"uid":{"type":"File","id":"r"},"attrs":{},"parents":[],"tags":null}]', encoding="utf-8")
        valid_request = path / "valid-request.json"
        valid_request.write_text(json.dumps({"principal":{"type":"User","id":"a"},"action":{"type":"Action","id":"read"},"resource":{"type":"File","id":"r"},"context":{}}), encoding="utf-8")
        assert run("authorize", policy, invalid_tags, valid_request).returncode == 2
        checks += 1
        approval = ROOT / "examples" / "approvals"
        sample = json.loads((approval / "requests.json").read_text(encoding="utf-8"))[0]["request"]
        decimal_request = path / "decimal-request.json"
        for value in ("1", "1.00000", "922337203685477.5808", "-922337203685477.5809"):
            sample["context"]["amount"]["__extn"]["arg"] = value
            decimal_request.write_text(json.dumps(sample), encoding="utf-8")
            result = run("authorize", approval / "policy.cedar", approval / "entities.json", decimal_request, "--format", "json")
            assert result.returncode == 2 and not result.stdout
            checks += 1
        session = ROOT / "examples" / "session"
        sample = json.loads((session / "requests.json").read_text(encoding="utf-8"))[0]["request"]
        duration_request = path / "duration-request.json"
        for value in ("1", "1s1h", "9223372036854775808ms", "-9223372036854775809ms"):
            sample["context"]["session_age"]["__extn"]["arg"] = value
            duration_request.write_text(json.dumps(sample), encoding="utf-8")
            result = run("authorize", session / "policy.cedar", session / "entities.json", duration_request, "--format", "json")
            assert result.returncode == 2 and not result.stdout
            checks += 1
        failed = path / "failed.json"
        request_obj = {"principal":{"type":"User","id":"a"},"action":{"type":"Action","id":"read"},"resource":{"type":"File","id":"r"},"context":{}}
        failed.write_text(json.dumps([{"request": request_obj, "decision": "Deny"}]), encoding="utf-8")
        empty = path / "empty.json"
        empty.write_text('[]', encoding="utf-8")
        assert run("test", policy, empty, failed).returncode == 1
        checks += 1
        cyclic = path / "cycle.json"
        cyclic.write_text('[{"uid":{"type":"Group","id":"x"},"attrs":{},"parents":[{"type":"Group","id":"y"}]},{"uid":{"type":"Group","id":"y"},"attrs":{},"parents":[{"type":"Group","id":"x"}]}]', encoding="utf-8")
        result = run("authorize", policy, cyclic, valid_request, "--format", "json")
        assert result.returncode == 2 and not result.stdout and "cycle" in result.stderr
        checks += 1
        result = run("test", policy, cyclic, failed, "--format", "json")
        assert result.returncode == 2 and not result.stdout and "cycle" in result.stderr
        checks += 1
        empty_cases = path / "empty-cases.json"
        empty_cases.write_text('[]', encoding="utf-8")
        result = run("test", policy, cyclic, empty_cases, "--format", "json")
        assert result.returncode == 2 and not result.stdout and "cycle" in result.stderr
        checks += 1
        result = run("test", policy, empty, empty_cases, "--format", "json")
        assert result.returncode == 0 and json.loads(result.stdout) == {"cases": [], "failures": 0}
        checks += 1
        policy.write_text('permit(principal, action, resource) when { context has a' + '.a' * 128 + ' };', encoding="utf-8")
        assert run("check", policy).returncode == 2
        checks += 1
        policy.write_text('permit(principal, action, resource) when { context' + '.a' * 129 + ' == true };', encoding="utf-8")
        assert run("check", policy).returncode == 2
        checks += 1
        diagnostics = ROOT / "examples" / "diagnostics"
        diagnostic_policy, diagnostic_entities = diagnostics / "policy.cedar", diagnostics / "entities.json"
        cases = json.loads((diagnostics / "requests.json").read_text(encoding="utf-8"))
        samples = []
        for i, case in enumerate(cases):
            sample = path / ("sample-" + str(i) + ".json")
            sample.write_text(json.dumps(case["request"]), encoding="utf-8")
            samples.append(sample)
        for i, case in enumerate(cases):
            normal = run("authorize", diagnostic_policy, diagnostic_entities, samples[i], "--format", "json")
            strict = run("authorize", diagnostic_policy, diagnostic_entities, samples[i], "--strict", "--format", "json")
            assert normal.returncode == 0 and strict.returncode == (1 if case["errors"] else 0)
            assert json.loads(normal.stdout) == json.loads(strict.stdout)
            checks += 1
        batch_input = diagnostics / "batch.json"
        expected = [json.loads(run("authorize", diagnostic_policy, diagnostic_entities, sample, "--format", "json").stdout) for sample in samples]
        batch = run("batch", diagnostic_policy, diagnostic_entities, batch_input, "--format", "json")
        assert batch.returncode == 0 and json.loads(batch.stdout) == expected
        checks += 1
        batch = run("batch", diagnostic_policy, diagnostic_entities, batch_input, "--strict", "--format", "json")
        assert batch.returncode == 1 and json.loads(batch.stdout) == expected
        checks += 1
        batch = run("batch", diagnostic_policy, diagnostic_entities, batch_input, "--format", "json", "--strict")
        assert batch.returncode == 1 and json.loads(batch.stdout) == expected
        checks += 1
        batch = run("batch", diagnostic_policy, diagnostic_entities, batch_input, "--strict")
        assert batch.returncode == 1 and "request 0: Allow" in batch.stdout and "request 3: Deny" in batch.stdout
        assert "suspended" in batch.stdout
        checks += 1
        batch_path = path / "batch.json"
        batch_path.write_text(json.dumps([cases[0]["request"], cases[1]["request"]]), encoding="utf-8")
        batch = run("batch", diagnostic_policy, diagnostic_entities, batch_path, "--strict", "--format", "json")
        assert batch.returncode == 0 and [x["decision"] for x in json.loads(batch.stdout)] == ["Allow", "Deny"]
        checks += 1
        batch_path.write_text('[]', encoding="utf-8")
        batch = run("batch", diagnostic_policy, diagnostic_entities, batch_path, "--strict", "--format", "json")
        assert batch.returncode == 0 and json.loads(batch.stdout) == []
        checks += 1
        batch = run("batch", diagnostic_policy, cyclic, batch_path, "--format", "json")
        assert batch.returncode == 2 and not batch.stdout and "cycle" in batch.stderr
        checks += 1
        for bad in ({}, [cases[0]["request"], {}], [None], "bad"):
            batch_path.write_text(json.dumps(bad), encoding="utf-8")
            batch = run("batch", diagnostic_policy, diagnostic_entities, batch_path, "--format", "json")
            assert batch.returncode == 2 and not batch.stdout
            checks += 1
        batch_path.write_text(json.dumps([cases[0]["request"]] * 4097, separators=(",", ":")), encoding="utf-8")
        batch = run("batch", diagnostic_policy, diagnostic_entities, batch_path, "--format", "json")
        assert batch.returncode == 2 and not batch.stdout and "batch limit" in batch.stderr
        checks += 1
        for flags in (("--strict", "--strict"), ("--format",), ("--format", "text")):
            batch = run("batch", diagnostic_policy, diagnostic_entities, batch_input, *flags)
            assert batch.returncode == 2 and not batch.stdout
            checks += 1
        strict = run("authorize", diagnostic_policy, diagnostic_entities, samples[2], "--format", "json", "--strict")
        assert strict.returncode == 1 and json.loads(strict.stdout)["decision"] == "Allow"
        checks += 1
        strict = run("authorize", diagnostic_policy, diagnostic_entities, samples[2], "--strict")
        assert strict.returncode == 1 and "suspended" in strict.stdout
        checks += 1
        for args in (
            ("check", diagnostic_policy, "--strict"),
            ("test", diagnostic_policy, diagnostic_entities, diagnostics / "requests.json", "--strict"),
            ("authorize", diagnostic_policy, diagnostic_entities, samples[0], "--strict", "--strict"),
            ("authorize", diagnostic_policy, diagnostic_entities, samples[0], "--format"),
            ("authorize", diagnostic_policy, diagnostic_entities, samples[0], "--format", "json", "--format", "json"),
        ):
            assert run(*args).returncode == 2
            checks += 1
        asserted = path / "assertions.json"
        variants = [
            ({**cases[0], "reasons": []}, "reasons"),
            ({**cases[2], "errors": []}, "errors"),
            ({k: v for k, v in cases[2].items() if k != "errors"}, "errors"),
            ({**cases[0], "decision": "Deny"}, "decision"),
        ]
        for case, failed_check in variants:
            asserted.write_text(json.dumps([case]), encoding="utf-8")
            result = run("test", diagnostic_policy, diagnostic_entities, asserted, "--format", "json")
            report = json.loads(result.stdout)
            assert result.returncode == 1 and report["failures"] == 1
            assert report["cases"][0]["checks"][failed_check] is False
            text_result = run("test", diagnostic_policy, diagnostic_entities, asserted)
            assert text_result.returncode == 1 and "FAIL" in text_result.stdout
            if failed_check != "decision":
                assert failed_check + ": expected" in text_result.stdout
            checks += 1
        asserted.write_text(json.dumps([{**cases[3], "errors": list(reversed(cases[3]["errors"]))}]), encoding="utf-8")
        result = run("test", diagnostic_policy, diagnostic_entities, asserted)
        assert result.returncode == 0 and "PASS" in result.stdout
        checks += 1
        unasserted = {k: v for k, v in cases[0].items() if k != "reasons"}
        asserted.write_text(json.dumps([unasserted]), encoding="utf-8")
        report = json.loads(run("test", diagnostic_policy, diagnostic_entities, asserted, "--format", "json").stdout)
        assert report["failures"] == 0 and report["cases"][0]["checks"]["reasons"] is None
        checks += 1
        multi_policy = path / "multiple.cedar"
        multi_policy.write_text('@id("first") permit(principal, action, resource); @id("second") permit(principal, action, resource);', encoding="utf-8")
        asserted.write_text(json.dumps([{**unasserted, "reasons": ["second", "first"]}]), encoding="utf-8")
        assert run("test", multi_policy, diagnostic_entities, asserted).returncode == 0
        checks += 1
        for field, value in (("reasons", None), ("reasons", "department-read"), ("reasons", [1]), ("reasons", ["x", "x"]), ("errors", {}), ("errors", [False]), ("errors", ["x", "x"])):
            asserted.write_text(json.dumps([{**cases[0], field: value}]), encoding="utf-8")
            assert run("test", diagnostic_policy, diagnostic_entities, asserted).returncode == 2
            checks += 1
    print("CLI checks passed:", checks)


if __name__ == "__main__":
    main()
