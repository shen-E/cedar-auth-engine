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
    for name in ("tenant", "sharing", "admin", "risk", "classified", "invoices", "quota", "network", "tags", "diagnostics", "device", "approvals", "session", "access-window"):
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
        sharing = ROOT / "examples" / "template-sharing"
        template = sharing / "template.cedar"
        links = sharing / "links.json"
        policy, entities, cases = sharing / "policy.cedar", sharing / "entities.json", sharing / "requests.json"
        flags = ("--template", template, "--links", links)
        cases_value = json.loads(cases.read_text(encoding="utf-8"))
        result = run("test", policy, entities, cases, *flags, "--format", "json")
        assert result.returncode == 0 and json.loads(result.stdout)["failures"] == 0
        checks += 1
        batch_file = path / "template-batch.json"
        batch_file.write_text(json.dumps([case["request"] for case in cases_value]), encoding="utf-8")
        batch = run("batch", policy, entities, batch_file, "--links", links, "--format", "json", "--template", template)
        responses = json.loads(batch.stdout)
        assert batch.returncode == 0 and len(responses) == len(cases_value)
        for index, case in enumerate(cases_value):
            request = path / "template-request.json"
            request.write_text(json.dumps(case["request"]), encoding="utf-8")
            single = run("authorize", policy, entities, request, *flags, "--format", "json")
            assert single.returncode == 0 and json.loads(single.stdout) == responses[index]
            checks += 1
        for index in (0, 3, 7, 8):
            request = path / "template-enforce-request.json"
            request.write_text(json.dumps(cases_value[index]["request"]), encoding="utf-8")
            original = responses[index]
            allowed = original["decision"] == "Allow" and not original["errors"]
            result = run("enforce", policy, entities, request, *flags, "--format", "json")
            assert result.returncode == (0 if allowed else 1) and json.loads(result.stdout) == {"allowed": allowed, "response": original}
            checks += 1
        enforced = run("enforce-batch", policy, entities, batch_file, *flags, "--format", "json")
        assert enforced.returncode == 1
        assert json.loads(enforced.stdout) == [{"allowed": response["decision"] == "Allow" and not response["errors"], "response": response} for response in responses]
        checks += 1
        strict = run("batch", policy, entities, batch_file, *flags, "--strict", "--format", "json")
        assert strict.returncode == 1 and json.loads(strict.stdout) == responses
        checks += 1
        invalid_links = path / "invalid-links.json"
        valid_links = json.loads(links.read_text(encoding="utf-8"))
        for value in (
            {}, [None], [{"id": "x", "principal": valid_links[0]["principal"]}],
            [{**valid_links[0], "extra": True}], [{**valid_links[0], "principal": None}],
            [{**valid_links[0], "principal": {"type": "User", "id": "a", "extra": 1}}],
            [valid_links[0], valid_links[0]], [{**valid_links[0], "id": "revoked"}],
        ):
            invalid_links.write_text(json.dumps(value), encoding="utf-8")
            result = run("batch", policy, entities, batch_file, "--template", template, "--links", invalid_links, "--format", "json")
            assert result.returncode == 2 and not result.stdout
            checks += 1
        for bad_flags in (("--template", template), ("--links", links), ("--template", template, "--template", template, "--links", links)):
            result = run("batch", policy, entities, batch_file, *bad_flags)
            assert result.returncode == 2 and not result.stdout
            checks += 1
    with tempfile.TemporaryDirectory() as tmp:
        path = pathlib.Path(tmp)
        example = ROOT / "examples" / "multi-template"
        policy, entities, cases = example / "policy.cedar", example / "entities.json", example / "requests.json"
        direct, team = example / "direct.cedar", example / "team.cedar"
        direct_links, team_links = example / "direct-links.json", example / "team-links.json"
        flags = ("--template", direct, "--links", direct_links, "--template", team, "--links", team_links)
        ordered_flags = ("--links", direct_links, "--links", team_links, "--template", direct, "--template", team)
        cases_value = json.loads(cases.read_text(encoding="utf-8"))
        report = run("test", policy, entities, cases, *flags, "--format", "json")
        assert report.returncode == 0 and json.loads(report.stdout)["failures"] == 0
        checks += 1
        batch_file = path / "multi-batch.json"
        batch_file.write_text(json.dumps([case["request"] for case in cases_value]), encoding="utf-8")
        batch = run("batch", policy, entities, batch_file, *ordered_flags, "--format", "json")
        responses = json.loads(batch.stdout)
        assert batch.returncode == 0 and len(responses) == len(cases_value)
        checks += 1
        for index, case in enumerate(cases_value):
            request = path / "multi-request.json"
            request.write_text(json.dumps(case["request"]), encoding="utf-8")
            single = run("authorize", policy, entities, request, *flags, "--format", "json")
            assert single.returncode == 0 and json.loads(single.stdout) == responses[index]
            checks += 1
        enforced = run("enforce-batch", policy, entities, batch_file, *flags, "--format", "json")
        assert enforced.returncode == 1 and json.loads(enforced.stdout) == [
            {"allowed": response["decision"] == "Allow" and not response["errors"], "response": response}
            for response in responses
        ]
        checks += 1
        bad_links = path / "duplicate-cross-template.json"
        duplicate = json.loads(team_links.read_text(encoding="utf-8"))
        duplicate[0]["id"] = "alice-report"
        bad_links.write_text(json.dumps(duplicate), encoding="utf-8")
        for command in ("batch", "enforce-batch"):
            result = run(command, policy, entities, batch_file, "--template", direct, "--links", direct_links, "--template", team, "--links", bad_links, "--format", "json")
            assert result.returncode == 2 and not result.stdout and "duplicate policy id" in result.stderr
            checks += 1
        missing = path / "missing-links.json"
        for flags in (("--template", direct, "--links", direct_links, "--template", team),
                      ("--template", direct, "--links", direct_links, "--links", team_links),
                      ("--template", direct, "--links", direct_links, "--template", team, "--links", missing)):
            result = run("batch", policy, entities, batch_file, *flags, "--format", "json")
            assert result.returncode == 2 and not result.stdout
            checks += 1
        no_links = path / "empty-links.json"
        no_links.write_text("[]", encoding="utf-8")
        result = run("batch", policy, entities, batch_file, "--template", direct, "--links", direct_links, "--template", team, "--links", no_links, "--format", "json")
        assert result.returncode == 0 and json.loads(result.stdout)[1]["reasons"] == ["carol-report"]
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
        window = ROOT / "examples" / "access-window"
        sample = json.loads((window / "requests.json").read_text(encoding="utf-8"))[0]["request"]
        datetime_request = path / "datetime-request.json"
        for value in ("2023-02-29", "2026-11-01T00:00:00", "2026-11-01T24:00:00Z", "2026-11-01T00:00:00+2400"):
            sample["context"]["now"]["__extn"]["arg"] = value
            datetime_request.write_text(json.dumps(sample), encoding="utf-8")
            result = run("authorize", window / "policy.cedar", window / "entities.json", datetime_request, "--format", "json")
            assert result.returncode == 2 and not result.stdout
            checks += 1
        # Invalid entity types must never reach an unconditional permit.
        entity_policy = path / "entity-validation.cedar"
        entity_policy.write_text("permit(principal, action, resource);", encoding="utf-8")
        entity_file = path / "entity-validation-entities.json"
        entity_file.write_text("[]", encoding="utf-8")
        entity_request = path / "entity-validation-request.json"
        valid = {"principal": {"type": "User", "id": "a"}, "action": {"type": "Action", "id": "read"}, "resource": {"type": "File", "id": "r"}, "context": {}}
        for key in ("principal", "action", "resource"):
            bad = {**valid, key: {"type": "invalid type", "id": "x"}}
            entity_request.write_text(json.dumps(bad), encoding="utf-8")
            result = run("authorize", entity_policy, entity_file, entity_request, "--format", "json")
            assert result.returncode == 2 and not result.stdout and "invalid entity type" in result.stderr
            checks += 1
        invalid_nested = {**valid, "context": {"owner": {"__entity": {"type": "App::if", "id": "x"}}}}
        entity_request.write_text(json.dumps(invalid_nested), encoding="utf-8")
        result = run("authorize", entity_policy, entity_file, entity_request, "--format", "json")
        assert result.returncode == 2 and not result.stdout
        checks += 1
        batch_input = path / "invalid-uid-batch.json"
        batch_input.write_text(json.dumps([valid, invalid_nested]), encoding="utf-8")
        result = run("batch", entity_policy, entity_file, batch_input, "--format", "json")
        assert result.returncode == 2 and not result.stdout
        checks += 1
        entity_request.write_text(json.dumps(valid), encoding="utf-8")
        for invalid in (
            {"uid": {"type": "1User", "id": "x"}, "attrs": {}, "parents": []},
            {"uid": {"type": "User", "id": "x"}, "attrs": {}, "parents": [{"type": "Group::", "id": "x"}]},
            {"uid": {"type": "User", "id": "x"}, "attrs": {"owner": {"__entity": {"type": "if", "id": "x"}}}, "parents": []},
            {"uid": {"type": "User", "id": "x"}, "attrs": {}, "parents": [], "tags": {"owner": {"__entity": {"type": "bad name", "id": "x"}}}},
        ):
            entity_file.write_text(json.dumps([invalid]), encoding="utf-8")
            result = run("authorize", entity_policy, entity_file, entity_request, "--format", "json")
            assert result.returncode == 2 and not result.stdout
            checks += 1
        sharing = ROOT / "examples" / "template-sharing"
        bad_links = json.loads((sharing / "links.json").read_text(encoding="utf-8"))
        bad_links[0]["principal"]["type"] = "invalid type"
        link_path = path / "invalid-type-links.json"
        link_path.write_text(json.dumps(bad_links), encoding="utf-8")
        result = run("authorize", sharing / "policy.cedar", sharing / "entities.json", entity_request, "--template", sharing / "template.cedar", "--links", link_path, "--format", "json")
        assert result.returncode == 2 and not result.stdout
        checks += 1
        empty = path / "empty.json"
        empty.write_text('[]', encoding="utf-8")
        # Test batches validate every case before writing text or JSON output.
        batch_cases = path / "batch-cases.json"
        passing_case = {"request": valid, "decision": "Allow"}
        for malformed in (
            None, {}, {"request": valid, "decision": "Maybe"},
            {"request": {**valid, "principal": {"type": "bad type", "id": "x"}}, "decision": "Allow"},
            {"request": valid, "decision": "Allow", "reasons": ["same", "same"]},
        ):
            batch_cases.write_text(json.dumps([passing_case, malformed]), encoding="utf-8")
            for flags in ((), ("--format", "json")):
                result = run("test", entity_policy, empty, batch_cases, *flags)
                assert result.returncode == 2 and not result.stdout
                checks += 1
        # Crossing the internal request batch boundary preserves every result.
        deny_policy = path / "empty-policy.cedar"
        deny_policy.write_text("", encoding="utf-8")
        empty_case = {"request": valid, "decision": "Deny"}
        for size in (4095, 4096, 4097):
            batch_cases.write_text(json.dumps([empty_case] * size, separators=(",", ":")), encoding="utf-8")
            result = run("test", deny_policy, empty, batch_cases, "--format", "json")
            report = json.loads(result.stdout)
            assert result.returncode == 0 and report["failures"] == 0 and len(report["cases"]) == size
            assert report["cases"][0]["index"] == 0 and report["cases"][-1]["index"] == size - 1
            checks += 1
        edge_policy = path / "edge-policy.cedar"
        edge_policy.write_text('permit(principal == User::"alice", action, resource);', encoding="utf-8")
        alice = {**valid, "principal": {"type": "User", "id": "alice"}}
        batch_cases.write_text(json.dumps([empty_case] * 4096 + [{"request": alice, "decision": "Allow"}], separators=(",", ":")), encoding="utf-8")
        result = run("test", edge_policy, empty, batch_cases, "--format", "json")
        report = json.loads(result.stdout)
        assert result.returncode == 0 and report["cases"][4095]["response"]["decision"] == "Deny"
        assert report["cases"][4096]["response"]["decision"] == "Allow" and report["cases"][4096]["response"]["reasons"] == ["policy0"]
        checks += 1
        batch_cases.write_text(json.dumps([empty_case] * 4096 + [{"request": valid}], separators=(",", ":")), encoding="utf-8")
        for flags in ((), ("--format", "json")):
            result = run("test", deny_policy, empty, batch_cases, *flags)
            assert result.returncode == 2 and not result.stdout
            checks += 1
        # Deep sets should complete without exponential duplicate comparisons.
        comparison_policy = path / "comparison.cedar"
        comparison_request = path / "comparison-request.json"
        comparison_policy.write_text('permit(principal, action, resource) when { context.left == context.right };', encoding="utf-8")
        nested = 0
        for _ in range(50):
            nested = [nested]
        comparison_request.write_text(json.dumps({**valid, "context": {"left": nested, "right": nested}}), encoding="utf-8")
        result = run("authorize", comparison_policy, empty, comparison_request, "--strict", "--format", "json")
        assert result.returncode == 0 and json.loads(result.stdout)["decision"] == "Allow"
        checks += 1
        # Exceeding the limit remains a policy error with standard skip semantics.
        comparison_policy.write_text('@id("base") permit(principal, action, resource); @id("guard") forbid(principal, action, resource) when { context.left == context.right };', encoding="utf-8")
        comparison_request.write_text(json.dumps({**valid, "context": {"left": list(range(1500)), "right": list(reversed(range(1500)))}}), encoding="utf-8")
        normal = run("authorize", comparison_policy, empty, comparison_request, "--format", "json")
        strict = run("authorize", comparison_policy, empty, comparison_request, "--strict", "--format", "json")
        value = json.loads(normal.stdout)
        assert normal.returncode == 0 and strict.returncode == 1 and json.loads(strict.stdout) == value
        assert value["decision"] == "Allow" and value["reasons"] == ["base"]
        assert len(value["errors"]) == 1 and value["errors"][0]["policy_id"] == "guard"
        assert "comparison budget" in value["errors"][0]["message"]
        checks += 1
        enforced = run("enforce", comparison_policy, empty, comparison_request, "--format", "json")
        assert enforced.returncode == 1 and json.loads(enforced.stdout) == {"allowed": False, "response": value}
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
        for index, original in enumerate(expected):
            allowed = original["decision"] == "Allow" and not original["errors"]
            enforced = run("enforce", diagnostic_policy, diagnostic_entities, samples[index], "--format", "json")
            assert enforced.returncode == (0 if allowed else 1)
            assert json.loads(enforced.stdout) == {"allowed": allowed, "response": original}
            checks += 1
        text_enforced = run("enforce", diagnostic_policy, diagnostic_entities, samples[2])
        assert text_enforced.returncode == 1 and "Deny (Cedar Allow)" in text_enforced.stdout and "suspended" in text_enforced.stdout
        checks += 1
        text_denied = run("enforce", diagnostic_policy, diagnostic_entities, samples[1])
        assert text_denied.returncode == 1 and "Deny (Cedar Deny)" in text_denied.stdout
        checks += 1
        batch_enforced = run("enforce-batch", diagnostic_policy, diagnostic_entities, batch_input, "--format", "json")
        assert batch_enforced.returncode == 1
        assert json.loads(batch_enforced.stdout) == [{"allowed": response["decision"] == "Allow" and not response["errors"], "response": response} for response in expected]
        checks += 1
        text_batch = run("enforce-batch", diagnostic_policy, diagnostic_entities, batch_input)
        assert text_batch.returncode == 1 and "request 2: Deny (Cedar Allow)" in text_batch.stdout
        checks += 1
        enforcer_batch_path = path / "enforcer-batch.json"
        for indices, status in (([], 0), ([0, 0], 0), ([0, 1], 1), ([2], 1)):
            enforcer_batch_path.write_text(json.dumps([cases[index]["request"] for index in indices]), encoding="utf-8")
            result = run("enforce-batch", diagnostic_policy, diagnostic_entities, enforcer_batch_path, "--format", "json")
            assert result.returncode == status and len(json.loads(result.stdout)) == len(indices)
            checks += 1
        enforcer_batch_path.write_text(json.dumps([cases[0]["request"], {"bad": "request"}]), encoding="utf-8")
        for flags in ((), ("--format", "json")):
            result = run("enforce-batch", diagnostic_policy, diagnostic_entities, enforcer_batch_path, *flags)
            assert result.returncode == 2 and not result.stdout
            checks += 1
        enforcer_batch_path.write_text("[]", encoding="utf-8")
        result = run("enforce-batch", diagnostic_policy, cyclic, enforcer_batch_path, "--format", "json")
        assert result.returncode == 2 and not result.stdout
        checks += 1
        for flags in ((), ("--format", "json")):
            result = run("enforce", diagnostic_policy, cyclic, samples[0], *flags)
            assert result.returncode == 2 and not result.stdout
            result = run("enforce", diagnostic_policy, diagnostic_entities, request, *flags)
            assert result.returncode == 2 and not result.stdout
            checks += 2
        for args in (("enforce", diagnostic_policy, diagnostic_entities, samples[0], "--strict"), ("enforce-batch", diagnostic_policy, diagnostic_entities, batch_input, "--strict")):
            result = run(*args)
            assert result.returncode == 2 and not result.stdout
            checks += 1
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
