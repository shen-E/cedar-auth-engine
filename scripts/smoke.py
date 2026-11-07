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
        flags = ("--template", direct, "--links", direct_links, "--template", team, "--links", team_links)
        # Removal is applied after all templates are linked, independent of flag order.
        remove_flags = ("--remove-policy", "alice-report", *flags, "--remove-policy", "carol-report")
        removed = run("batch", policy, entities, batch_file, *remove_flags, "--format", "json")
        removed_responses = json.loads(removed.stdout)
        assert removed.returncode == 0 and removed_responses[0]["decision"] == "Deny"
        assert removed_responses[1]["reasons"] == ["design-team"]
        assert [error["policy_id"] for error in removed_responses[8]["errors"]] == ["design-team"]
        checks += 1
        for index, case in enumerate(cases_value):
            request = path / "removed-request.json"
            request.write_text(json.dumps(case["request"]), encoding="utf-8")
            single = run("authorize", policy, entities, request, *remove_flags, "--format", "json")
            assert single.returncode == 0 and json.loads(single.stdout) == removed_responses[index]
            enforced = run("enforce", policy, entities, request, *remove_flags, "--format", "json")
            allowed = removed_responses[index]["decision"] == "Allow" and not removed_responses[index]["errors"]
            assert enforced.returncode == (0 if allowed else 1)
            assert json.loads(enforced.stdout) == {"allowed": allowed, "response": removed_responses[index]}
            checks += 2
        enforced = run("enforce-batch", policy, entities, batch_file, *remove_flags, "--format", "json")
        assert enforced.returncode == 1 and json.loads(enforced.stdout) == [
            {"allowed": item["decision"] == "Allow" and not item["errors"], "response": item}
            for item in removed_responses
        ]
        checks += 1
        test_cases = path / "removed-cases.json"
        test_cases.write_text(json.dumps([
            {"request": item["request"], "decision": result["decision"],
             "reasons": result["reasons"], "errors": [error["policy_id"] for error in result["errors"]]}
            for item, result in zip(cases_value, removed_responses)
        ]), encoding="utf-8")
        tested = run("test", policy, entities, test_cases, *remove_flags, "--format", "json")
        assert tested.returncode == 0 and json.loads(tested.stdout)["failures"] == 0
        checks += 1
        # Removing a forbid can reveal a permit.
        without_forbid = run("batch", policy, entities, batch_file, *flags, "--remove-policy", "revoked", "--format", "json")
        assert without_forbid.returncode == 0 and json.loads(without_forbid.stdout)[4]["reasons"] == ["design-team"]
        checks += 1
        for invalid in (("alice-report", "missing"), ("design-team", "design-team")):
            for command in ("batch", "enforce-batch", "test"):
                input_file = test_cases if command == "test" else batch_file
                result = run(command, policy, entities, input_file, *flags, "--remove-policy", invalid[0], "--remove-policy", invalid[1], "--format", "json")
                assert result.returncode == 2 and not result.stdout
                checks += 1
        result = run("check", policy, "--remove-policy", "revoked")
        assert result.returncode == 2 and not result.stdout
        checks += 1
        no_links = path / "empty-links.json"
        no_links.write_text("[]", encoding="utf-8")
        result = run("batch", policy, entities, batch_file, "--template", direct, "--links", direct_links, "--template", team, "--links", no_links, "--format", "json")
        assert result.returncode == 0 and json.loads(result.stdout)[1]["reasons"] == ["carol-report"]
        checks += 1
    with tempfile.TemporaryDirectory() as tmp:
        path = pathlib.Path(tmp)
        multi, update = ROOT / "examples" / "multi-template", ROOT / "examples" / "policy-update"
        policy, entities, cases = multi / "policy.cedar", multi / "entities.json", update / "requests.json"
        # Cross-kind options apply in the documented order, not command-line order.
        flags = ("--replace-policies", update / "replacements.cedar",
                 "--template", multi / "direct.cedar", "--links", multi / "direct-links.json",
                 "--add-policies", update / "additional.cedar",
                 "--template", multi / "team.cedar", "--links", multi / "team-links.json")
        report = run("test", policy, entities, cases, *flags, "--format", "json")
        assert report.returncode == 0 and json.loads(report.stdout)["failures"] == 0
        checks += 1
        cases_value = json.loads(cases.read_text(encoding="utf-8"))
        batch_file = path / "updates-batch.json"
        batch_file.write_text(json.dumps([case["request"] for case in cases_value]), encoding="utf-8")
        batch = run("batch", policy, entities, batch_file, *flags, "--format", "json")
        assert batch.returncode == 0
        responses = json.loads(batch.stdout)
        assert len(responses) == len(cases_value)
        checks += 1
        for index, case in enumerate(cases_value):
            single_file = path / "update-request.json"
            single_file.write_text(json.dumps(case["request"]), encoding="utf-8")
            single = run("authorize", policy, entities, single_file, *flags, "--format", "json")
            assert single.returncode == 0 and json.loads(single.stdout) == responses[index]
            enforced = run("enforce", policy, entities, single_file, *flags, "--format", "json")
            allowed = responses[index]["decision"] == "Allow" and not responses[index]["errors"]
            assert enforced.returncode == (0 if allowed else 1)
            assert json.loads(enforced.stdout) == {"allowed": allowed, "response": responses[index]}
            checks += 2
        enforced = run("enforce-batch", policy, entities, batch_file, *flags, "--format", "json")
        assert enforced.returncode == 1 and json.loads(enforced.stdout) == [
            {"allowed": item["decision"] == "Allow" and not item["errors"], "response": item}
            for item in responses
        ]
        checks += 1
        # Repeated files are applied in their own option order.
        extra = path / "extra.cedar"
        extra.write_text('@id("temporary") permit(principal, action, resource);', encoding="utf-8")
        first = path / "first.cedar"
        first.write_text('@id("temporary") forbid(principal, action, resource);', encoding="utf-8")
        second = path / "second.cedar"
        second.write_text('@id("temporary") permit(principal, action, resource);', encoding="utf-8")
        ordered = run("batch", policy, entities, batch_file, "--add-policies", extra,
                      "--replace-policies", first, "--replace-policies", second, "--format", "json")
        assert ordered.returncode == 0 and json.loads(ordered.stdout)[0]["reasons"] == ["temporary"]
        reversed_order = run("batch", policy, entities, batch_file, "--add-policies", extra,
                             "--replace-policies", second, "--replace-policies", first, "--format", "json")
        assert reversed_order.returncode == 0 and json.loads(reversed_order.stdout)[0]["reasons"] == ["temporary"]
        assert json.loads(ordered.stdout)[0]["decision"] == "Allow"
        assert json.loads(reversed_order.stdout)[0]["decision"] == "Deny"
        checks += 2
        # File updates happen before removals, including removals listed first.
        removed = run("batch", policy, entities, batch_file, "--remove-policy", "emergency", *flags, "--format", "json")
        assert removed.returncode == 0 and json.loads(removed.stdout)[3]["decision"] == "Allow"
        checks += 1
        duplicate = path / "duplicate.cedar"
        duplicate.write_text('@id("revoked") permit(principal, action, resource);', encoding="utf-8")
        missing = path / "missing.cedar"
        missing.write_text('@id("revoked") permit(principal, action, resource); @id("missing") permit(principal, action, resource);', encoding="utf-8")
        invalid = path / "invalid.cedar"
        invalid.write_text('invalid syntax;', encoding="utf-8")
        for option, file in (("--add-policies", duplicate), ("--replace-policies", missing), ("--replace-policies", invalid), ("--add-policies", path / "absent.cedar")):
            for command in ("batch", "enforce-batch", "test"):
                input_file = cases if command == "test" else batch_file
                result = run(command, policy, entities, input_file, *flags, option, file, "--format", "json")
                assert result.returncode == 2 and not result.stdout
                checks += 1
        for option in ("--add-policies", "--replace-policies"):
            result = run("check", policy, option, duplicate)
            assert result.returncode == 2 and not result.stdout
            checks += 1
    with tempfile.TemporaryDirectory() as tmp:
        path = pathlib.Path(tmp)
        multi, example = ROOT / "examples" / "multi-template", ROOT / "examples" / "policy-comparison"
        before, after, entities, requests = multi / "policy.cedar", example / "after.cedar", multi / "entities.json", example / "requests.json"
        flags = ("--before-template", multi / "direct.cedar", "--before-links", multi / "direct-links.json",
                 "--before-template", multi / "team.cedar", "--before-links", multi / "team-links.json",
                 "--after-template", example / "direct.cedar", "--after-links", multi / "direct-links.json",
                 "--after-template", multi / "team.cedar", "--after-links", multi / "team-links.json")
        report = run("compare", before, after, entities, requests, *flags, "--format", "json")
        assert report.returncode == 0
        output = json.loads(report.stdout)
        assert {key: output[key] for key in ("total", "changed", "decisions_changed", "enforcement_changed", "reasons_changed", "errors_changed")} == {
            "total": 8, "changed": 5, "decisions_changed": 3, "enforcement_changed": 4, "reasons_changed": 5, "errors_changed": 2}
        assert output["cases"][1]["before"]["decision"] == output["cases"][1]["after"]["decision"] == "Allow"
        assert output["cases"][1]["enforcement_changed"] and not output["cases"][1]["after_allowed"]
        assert output["cases"][7]["reasons_changed"] and not output["cases"][7]["enforcement_changed"]
        checks += 1
        failed = run("compare", before, after, entities, requests, *flags, "--fail-on-change", "--format", "json")
        assert failed.returncode == 1 and json.loads(failed.stdout) == output
        checks += 1
        textual = run("compare", before, after, entities, requests, *flags, "--fail-on-change")
        assert textual.returncode == 1 and "5/8 changed" in textual.stdout and "missing attribute" in textual.stdout
        checks += 1
        unchanged_flags = ("--before-template", multi / "team.cedar", "--before-links", multi / "team-links.json",
                           "--before-template", multi / "direct.cedar", "--before-links", multi / "direct-links.json",
                           "--after-template", multi / "direct.cedar", "--after-links", multi / "direct-links.json",
                           "--after-template", multi / "team.cedar", "--after-links", multi / "team-links.json")
        unchanged = run("compare", before, before, entities, requests, *unchanged_flags, "--fail-on-change", "--format", "json")
        assert unchanged.returncode == 0 and json.loads(unchanged.stdout)["changed"] == 0
        checks += 1
        # Compare independently composed sides against ordinary batch evaluation.
        update = ROOT / "examples" / "policy-update"
        templates = ("--template", multi / "direct.cedar", "--links", multi / "direct-links.json",
                     "--template", multi / "team.cedar", "--links", multi / "team-links.json")
        old_options = (*templates, "--add-policies", update / "additional.cedar", "--remove-policy", "carol-report")
        new_options = (*templates, "--add-policies", update / "additional.cedar",
                       "--replace-policies", update / "replacements.cedar", "--remove-policy", "design-team")
        def side_options(options, prefix):
            return tuple(("--" + prefix + "-" + value[2:]) if isinstance(value, str) and value.startswith("--") else value for value in options)
        composed = run("compare", before, before, entities, requests,
                       *side_options(old_options, "before"), *side_options(new_options, "after"), "--format", "json")
        old_batch = run("batch", before, entities, requests, *old_options, "--format", "json")
        new_batch = run("batch", before, entities, requests, *new_options, "--format", "json")
        assert composed.returncode == old_batch.returncode == new_batch.returncode == 0
        composed_cases = json.loads(composed.stdout)["cases"]
        assert [case["before"] for case in composed_cases] == json.loads(old_batch.stdout)
        assert [case["after"] for case in composed_cases] == json.loads(new_batch.stdout)
        assert any(case["changed"] for case in composed_cases)
        checks += 1
        # Cross-kind options apply in the documented order even when interleaved.
        scrambled = ("--after-remove-policy", "design-team", "--before-remove-policy", "carol-report",
                     "--after-replace-policies", update / "replacements.cedar",
                     *side_options(templates, "after"), "--before-add-policies", update / "additional.cedar",
                     *side_options(templates, "before"), "--after-add-policies", update / "additional.cedar")
        result = run("compare", before, before, entities, requests, *scrambled, "--format", "json")
        assert result.returncode == 0 and json.loads(result.stdout) == json.loads(composed.stdout)
        checks += 1
        bad_policy = path / "bad-policy.cedar"
        bad_policy.write_text('invalid syntax;', encoding="utf-8")
        duplicate_policy = path / "duplicate-policy.cedar"
        duplicate_policy.write_text('@id("revoked") permit(principal, action, resource);', encoding="utf-8")
        unknown_policy = path / "unknown-policy.cedar"
        unknown_policy.write_text('@id("missing") permit(principal, action, resource);', encoding="utf-8")
        for side in ("before", "after"):
            for bad in (("--" + side + "-add-policies", duplicate_policy),
                        ("--" + side + "-add-policies", bad_policy),
                        ("--" + side + "-add-policies", path / "absent.cedar"),
                        ("--" + side + "-replace-policies", unknown_policy),
                        ("--" + side + "-replace-policies", bad_policy),
                        ("--" + side + "-remove-policy", "missing"),
                        ("--" + side + "-remove-policy", "revoked", "--" + side + "-remove-policy", "revoked")):
                result = run("compare", before, before, entities, requests, *bad, "--format", "json")
                assert result.returncode == 2 and not result.stdout
                checks += 1
            for option in ("add-policies", "replace-policies", "remove-policy"):
                result = run("compare", before, before, entities, requests, *(("--" + side + "-" + option, "x") * 1025))
                assert result.returncode == 2 and not result.stdout and "limit exceeded" in result.stderr
                checks += 1
        # Additions remain independent and policy order does not change the report.
        add_a = path / "add-a.cedar"
        add_b = path / "add-b.cedar"
        add_a.write_text('@id("a") permit(principal, action, resource);', encoding="utf-8")
        add_b.write_text('@id("b") permit(principal, action, resource);', encoding="utf-8")
        reordered = run("compare", before, before, entities, requests,
                        "--before-add-policies", add_a, "--before-add-policies", add_b,
                        "--after-add-policies", add_b, "--after-add-policies", add_a,
                        "--fail-on-change", "--format", "json")
        assert reordered.returncode == 0 and json.loads(reordered.stdout)["changed"] == 0
        checks += 1
        # A removal cannot make an earlier conflicting addition valid.
        duplicate_before_remove = run("compare", before, before, entities, requests,
                                      "--before-add-policies", duplicate_policy,
                                      "--before-remove-policy", "revoked", "--format", "json")
        assert duplicate_before_remove.returncode == 2 and not duplicate_before_remove.stdout
        checks += 1
        # Repeated replacement files apply in order on each side.
        first = path / "first-replacement.cedar"
        second = path / "second-replacement.cedar"
        first.write_text('@id("revoked") forbid(principal, action, resource);', encoding="utf-8")
        second.write_text('@id("revoked") forbid(principal, action, resource) when { false };', encoding="utf-8")
        ordered = run("compare", before, before, entities, requests, "--before-replace-policies", first,
                      "--before-replace-policies", second, "--after-replace-policies", second,
                      "--after-replace-policies", first, "--format", "json")
        assert ordered.returncode == 0
        ordered_cases = json.loads(ordered.stdout)["cases"]
        assert ordered_cases[0]["before"]["reasons"] == [] and ordered_cases[0]["after"]["reasons"] == ["revoked"]
        checks += 1
        empty = path / "empty.json"
        empty.write_text("[]", encoding="utf-8")
        result = run("compare", before, after, entities, empty, "--format", "json")
        assert result.returncode == 0 and json.loads(result.stdout)["total"] == 0
        checks += 1
        invalid_graph = path / "cycle.json"
        invalid_graph.write_text(json.dumps([{"uid":{"type":"User","id":"a"},"attrs":{},"parents":[{"type":"User","id":"a"}]}]), encoding="utf-8")
        result = run("compare", before, after, invalid_graph, empty, "--format", "json")
        assert result.returncode == 2 and not result.stdout
        checks += 1
        invalid_requests = path / "invalid-requests.json"
        sample = json.loads(requests.read_text(encoding="utf-8"))[0]
        invalid_requests.write_text(json.dumps([sample, {}]), encoding="utf-8")
        result = run("compare", before, after, entities, invalid_requests, "--format", "json")
        assert result.returncode == 2 and not result.stdout
        checks += 1
        invalid_requests.write_text(json.dumps([sample] * 4097), encoding="utf-8")
        result = run("compare", before, after, entities, invalid_requests, "--format", "json")
        assert result.returncode == 2 and not result.stdout
        checks += 1
        for bad in (("--before-template", multi / "direct.cedar"),
                    ("--after-links", multi / "direct-links.json"),
                    ("--before-links", multi / "direct-links.json", "--after-template", multi / "direct.cedar"),
                    ("--fail-on-change", "--fail-on-change"), ("--format", "xml")):
            result = run("compare", before, after, entities, requests, *bad)
            assert result.returncode == 2 and not result.stdout
            checks += 1
    with tempfile.TemporaryDirectory() as tmp:
        path = pathlib.Path(tmp)
        multi, example = ROOT / "examples" / "multi-template", ROOT / "examples" / "entity-comparison"
        policy, before, after, requests = multi / "policy.cedar", multi / "entities.json", example / "after-entities.json", example / "requests.json"
        flags = ("--before-template", multi / "team.cedar", "--before-links", multi / "team-links.json",
                 "--after-template", multi / "team.cedar", "--after-links", multi / "team-links.json")
        result = run("compare", policy, policy, before, requests, *flags, "--after-entities", after, "--format", "json")
        assert result.returncode == 0
        report = json.loads(result.stdout)
        assert {key: report[key] for key in ("total", "changed", "decisions_changed", "enforcement_changed", "reasons_changed", "errors_changed")} == {
            "total": 6, "changed": 4, "decisions_changed": 3, "enforcement_changed": 3, "reasons_changed": 3, "errors_changed": 1}
        assert report["cases"][0]["before"]["decision"] == "Deny" and report["cases"][0]["after"]["decision"] == "Allow"
        assert report["cases"][1]["before"]["decision"] == "Allow" and report["cases"][1]["after"]["decision"] == "Deny"
        assert report["cases"][5]["errors_changed"] and not report["cases"][5]["decision_changed"]
        checks += 1
        fail = run("compare", policy, policy, before, requests, *flags, "--after-entities", after, "--fail-on-change", "--format", "json")
        assert fail.returncode == 1 and json.loads(fail.stdout) == report
        checks += 1
        swapped = run("compare", policy, policy, after, requests, *flags, "--after-entities", before, "--format", "json")
        reversed_cases = json.loads(swapped.stdout)["cases"]
        assert swapped.returncode == 0
        assert all(old["before"] == new["after"] and old["after"] == new["before"] for old, new in zip(report["cases"], reversed_cases))
        checks += 1
        same = run("compare", policy, policy, before, requests, *flags, "--format", "json")
        explicit_same = run("compare", policy, policy, before, requests, *flags, "--after-entities", before, "--format", "json")
        assert same.returncode == explicit_same.returncode == 0 and json.loads(same.stdout) == json.loads(explicit_same.stdout)
        checks += 1
        # Repeated hierarchy checks must match separate graph evaluations.
        repeated = path / "repeated-requests.json"
        repeated.write_text(json.dumps(json.loads(requests.read_text(encoding="utf-8")) * 3), encoding="utf-8")
        team_flags = ("--template", multi / "team.cedar", "--links", multi / "team-links.json")
        old_batch = run("batch", policy, before, repeated, *team_flags, "--format", "json")
        new_batch = run("batch", policy, after, repeated, *team_flags, "--format", "json")
        repeated_compare = run("compare", policy, policy, before, repeated, *flags, "--after-entities", after, "--format", "json")
        assert old_batch.returncode == new_batch.returncode == repeated_compare.returncode == 0
        old_values, new_values = json.loads(old_batch.stdout), json.loads(new_batch.stdout)
        pairs = json.loads(repeated_compare.stdout)["cases"]
        assert len(pairs) == len(old_values) == len(new_values) == 18
        for i, pair in enumerate(pairs):
            assert pair["before"] == old_values[i] and pair["after"] == new_values[i]
            assert pair["before"] == report["cases"][i % 6]["before"]
            assert pair["after"] == report["cases"][i % 6]["after"]
            checks += 1
        # Policy composition and entity changes are applied to their own sides.
        removed = run("compare", policy, policy, before, requests, *flags, "--after-entities", after,
                      "--after-remove-policy", "design-team", "--format", "json")
        assert removed.returncode == 0 and json.loads(removed.stdout)["cases"][0]["after"]["decision"] == "Deny"
        checks += 1
        empty = path / "empty.json"
        empty.write_text("[]", encoding="utf-8")
        cycle = path / "cycle.json"
        cycle.write_text(json.dumps([{"uid":{"type":"User","id":"a"},"attrs":{},"parents":[{"type":"User","id":"a"}]}]), encoding="utf-8")
        duplicate = path / "duplicate.json"
        duplicate.write_text(json.dumps([{"uid":{"type":"User","id":"a"},"attrs":{},"parents":[]}] * 2), encoding="utf-8")
        malformed = path / "malformed.json"
        malformed.write_text('{"wrong": true}', encoding="utf-8")
        for invalid in (cycle, duplicate, malformed, path / "missing.json"):
            for input_file in (requests, empty):
                bad = run("compare", policy, policy, before, input_file, "--after-entities", invalid, "--format", "json")
                assert bad.returncode == 2 and not bad.stdout
                checks += 1
        duplicated_option = run("compare", policy, policy, before, requests, "--after-entities", after, "--after-entities", after)
        assert duplicated_option.returncode == 2 and not duplicated_option.stdout
        checks += 1
        invalid_before = run("compare", policy, policy, cycle, empty, "--after-entities", after, "--format", "json")
        assert invalid_before.returncode == 2 and not invalid_before.stdout
        checks += 1
        # A missing tag changes fail-closed enforcement even when Cedar still permits.
        tag_policy = path / "tags.cedar"
        tag_policy.write_text('@id("allow") permit(principal, action, resource); @id("guard") forbid(principal, action, resource) when { resource.getTag("blocked") };', encoding="utf-8")
        tag_before = path / "tags-before.json"
        tag_after = path / "tags-after.json"
        tag_entity = {"uid":{"type":"File","id":"report"},"attrs":{},"parents":[],"tags":{"blocked":False}}
        tag_before.write_text(json.dumps([tag_entity]), encoding="utf-8")
        tag_entity["tags"] = {}
        tag_after.write_text(json.dumps([tag_entity]), encoding="utf-8")
        tag_request = path / "tag-request.json"
        tag_request.write_text(json.dumps([json.loads(requests.read_text(encoding="utf-8"))[0]]), encoding="utf-8")
        tagged = run("compare", tag_policy, tag_policy, tag_before, tag_request, "--after-entities", tag_after, "--format", "json")
        case = json.loads(tagged.stdout)["cases"][0]
        assert tagged.returncode == 0 and case["before"]["decision"] == case["after"]["decision"] == "Allow"
        assert case["before_allowed"] and not case["after_allowed"] and case["errors_changed"] and case["enforcement_changed"]
        checks += 1
    with tempfile.TemporaryDirectory() as tmp:
        path = pathlib.Path(tmp)
        before, after, entities, requests = (path / name for name in ("before.cedar", "after.cedar", "entities.json", "requests.json"))
        entities.write_text("[]", encoding="utf-8")
        request = {"principal":{"type":"User","id":"alice"},"action":{"type":"Action","id":"read"},"resource":{"type":"File","id":"report"},"context":{}}
        requests.write_text(json.dumps([request]), encoding="utf-8")
        permit = '@id("permit") permit(principal, action, resource);'
        guard_error = '@id("guard") forbid(principal, action, resource) when { context.missing };'
        # decision grant, decision revoke, enforcement grant, enforcement revoke, any change
        scenarios = (("", permit, (True, False, True, False, True)),
                     (permit, "", (False, True, False, True, True)),
                     ("", permit + guard_error, (True, False, False, False, True)),
                     (permit + guard_error, permit, (False, False, True, False, True)),
                     (permit, permit + guard_error, (False, False, False, True, True)),
                     (permit + guard_error, "", (False, True, False, False, True)),
                     ("", guard_error, (False, False, False, False, True)),
                     ("", "", (False, False, False, False, False)),
                     (permit + guard_error, permit + guard_error, (False, False, False, False, False)),
                     (permit, '@id("other") permit(principal, action, resource);', (False, False, False, False, True)))
        fields = ("decision_granted", "decision_revoked", "enforcement_granted", "enforcement_revoked", "changed")
        summary = ("decision_grants", "decision_revocations", "enforcement_grants", "enforcement_revocations", "changed")
        switches = ("--fail-on-decision-grant", "--fail-on-decision-revoke", "--fail-on-enforcement-grant", "--fail-on-enforcement-revoke", "--fail-on-change")
        for old_source, new_source, expected in scenarios:
            before.write_text(old_source, encoding="utf-8")
            after.write_text(new_source, encoding="utf-8")
            normal = run("compare", before, after, entities, requests, "--format", "json")
            report = json.loads(normal.stdout)
            assert normal.returncode == 0
            assert tuple(report["cases"][0][field] for field in fields) == expected
            assert tuple(report[field] for field in summary) == tuple(int(value) for value in expected)
            checks += 1
            for flag, should_fail in zip(switches, expected):
                result = run("compare", before, after, entities, requests, flag, "--format", "json")
                assert result.returncode == (1 if should_fail else 0) and json.loads(result.stdout) == report
                checks += 1
            after_error = bool(guard_error and guard_error in new_source)
            assert report["after_error_requests"] == int(after_error)
            error_gate = run("compare", before, after, entities, requests, "--fail-on-after-error", "--format", "json")
            assert error_gate.returncode == (1 if after_error else 0) and json.loads(error_gate.stdout) == report
            checks += 1
            combined = run("compare", before, after, entities, requests, *switches[:4], "--format", "json")
            assert combined.returncode == (1 if any(expected[:4]) else 0) and json.loads(combined.stdout) == report
            checks += 1
        for flag in (*switches[0:4], "--fail-on-after-error"):
            duplicate = run("compare", before, after, entities, requests, flag, flag)
            assert duplicate.returncode == 2 and not duplicate.stdout
            checks += 1
        empty = path / "empty.json"
        empty.write_text("[]", encoding="utf-8")
        empty_result = run("compare", before, after, entities, empty, *switches, "--fail-on-after-error", "--format", "json")
        assert empty_result.returncode == 0 and json.loads(empty_result.stdout)["total"] == 0
        checks += 1
        before.write_text("", encoding="utf-8")
        after.write_text(permit, encoding="utf-8")
        text_report = run("compare", before, after, entities, requests, "--fail-on-enforcement-grant")
        assert text_report.returncode == 1 and "grants=1" in text_report.stdout
        checks += 1
    with tempfile.TemporaryDirectory() as tmp:
        path = pathlib.Path(tmp)
        policy = path / "guard.cedar"
        policy.write_text('@id("grant") permit(principal, action, resource); @id("suspended") forbid(principal, action, resource) when { resource.hasTag("suspended") };', encoding="utf-8")
        entity = {"uid": {"type": "File", "id": "report"}, "attrs": {}, "parents": [], "tags": {"suspended": True}}
        request = {"principal": {"type": "User", "id": "alice"}, "action": {"type": "Action", "id": "read"}, "resource": {"type": "File", "id": "report"}, "context": {}}
        entity_file, request_file, batch_file, cases_file = (path / name for name in ("entities.json", "request.json", "batch.json", "cases.json"))
        entity_file.write_text(json.dumps([entity]), encoding="utf-8")
        request_file.write_text(json.dumps(request), encoding="utf-8")
        batch_file.write_text(json.dumps([request]), encoding="utf-8")
        cases_file.write_text(json.dumps([{"request": request, "decision": "Deny", "reasons": ["suspended"]}]), encoding="utf-8")
        valid = run("authorize", policy, entity_file, request_file, "--format", "json")
        assert valid.returncode == 0 and json.loads(valid.stdout)["reasons"] == ["suspended"]
        checks += 1
        # Misspelled tags previously disappeared silently and could expose an Allow.
        typo = {key: value for key, value in entity.items() if key != "tags"}
        typo["tagz"] = {"suspended": True}
        invalid_entity = path / "invalid-entity.json"
        invalid_entity.write_text(json.dumps([entity, typo]), encoding="utf-8")
        for command, input_file in (("authorize", request_file), ("enforce", request_file),
                                    ("batch", batch_file), ("enforce-batch", batch_file), ("test", cases_file)):
            for formatting in ((), ("--format", "json")):
                result = run(command, policy, invalid_entity, input_file, *formatting)
                assert result.returncode == 2 and not result.stdout and "unknown entity field 'tagz'" in result.stderr
                checks += 1
        for before, after in ((invalid_entity, entity_file), (entity_file, invalid_entity)):
            result = run("compare", policy, policy, before, batch_file, "--after-entities", after, "--format", "json")
            assert result.returncode == 2 and not result.stdout and "unknown entity field 'tagz'" in result.stderr
            checks += 1
        # Validate the complete batch before printing any result.
        invalid_request = {**request, "contextt": {"authenticated": True}}
        invalid_uid = {**request, "principal": {**request["principal"], "tenant": "x"}}
        for bad in (invalid_request, invalid_uid):
            request_file.write_text(json.dumps(bad), encoding="utf-8")
            batch_file.write_text(json.dumps([request, bad]), encoding="utf-8")
            cases_file.write_text(json.dumps([{"request": request, "decision": "Deny"}, {"request": bad, "decision": "Deny"}]), encoding="utf-8")
            for command, input_file in (("authorize", request_file), ("enforce", request_file),
                                        ("batch", batch_file), ("enforce-batch", batch_file), ("test", cases_file)):
                result = run(command, policy, entity_file, input_file, "--format", "json")
                assert result.returncode == 2 and not result.stdout
                checks += 1
            result = run("compare", policy, policy, entity_file, batch_file, "--format", "json")
            assert result.returncode == 2 and not result.stdout
            checks += 1
        # A typo in an optional expectation must not silently turn into a passing test.
        for bad_case in ({"request": request, "decision": "Deny", "reason": ["suspended"]},
                         {"request": request, "decision": "Deny", "error": []},
                         {"request": request, "decision": "Deny", "description": "unrecognized metadata"}):
            cases_file.write_text(json.dumps([{"request": request, "decision": "Deny"}, bad_case]), encoding="utf-8")
            result = run("test", policy, entity_file, cases_file, "--format", "json")
            assert result.returncode == 2 and not result.stdout and "unknown test case field" in result.stderr
            checks += 1
        # Domain records are open-ended and are not treated as structural objects.
        open_request = {**request, "context": {"tagz": True, "record": {"type": "free", "id": 1, "extra": True}}}
        open_entity = {**entity, "attrs": {"tagz": True, "record": {"type": "free", "id": 1, "extra": True}}}
        request_file.write_text(json.dumps(open_request), encoding="utf-8")
        entity_file.write_text(json.dumps([open_entity]), encoding="utf-8")
        result = run("authorize", policy, entity_file, request_file, "--format", "json")
        assert result.returncode == 0 and json.loads(result.stdout)["decision"] == "Deny"
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
    with tempfile.TemporaryDirectory() as tmp:
        path = pathlib.Path(tmp)
        policy, entities, request, batch = (path / name for name in ("policy.cedar", "entities.json", "request.json", "batch.json"))
        policy.write_text("permit(principal, action, resource);", encoding="utf-8")
        entities.write_text("[]", encoding="utf-8")
        input_request = {"principal": {"type": "User", "id": "alice"}, "action": {"type": "Action", "id": "read"},
                         "resource": {"type": "File", "id": "report"}, "context": {"values": [False] * 131071}}
        request.write_text(json.dumps(input_request, separators=(",", ":")), encoding="utf-8")
        result = run("authorize", policy, entities, request, "--format", "json")
        assert result.returncode == 0 and json.loads(result.stdout)["decision"] == "Allow"
        checks += 1
        input_request["context"]["values"].append(False)
        request.write_text(json.dumps(input_request, separators=(",", ":")), encoding="utf-8")
        result = run("authorize", policy, entities, request, "--format", "json")
        assert result.returncode == 2 and not result.stdout and "value limit exceeded" in result.stderr
        checks += 1
        batch.write_text(json.dumps([{**input_request, "context": {}}, input_request], separators=(",", ":")), encoding="utf-8")
        result = run("batch", policy, entities, batch, "--format", "json")
        assert result.returncode == 2 and not result.stdout and "value limit exceeded" in result.stderr
        checks += 1
        entities.write_text(json.dumps([{"uid": {"type": "File", "id": str(i)}, "attrs": {}, "parents": []} for i in range(4097)], separators=(",", ":")), encoding="utf-8")
        request.write_text(json.dumps({**input_request, "context": {}}), encoding="utf-8")
        result = run("authorize", policy, entities, request, "--format", "json")
        assert result.returncode == 2 and not result.stdout and "entity limit exceeded" in result.stderr
        checks += 1
    with tempfile.TemporaryDirectory() as tmp:
        path = pathlib.Path(tmp) / "entities.json"
        team = {"type": "Group", "id": "security"}
        folder = {"type": "Folder", "id": "shared\narchive"}
        alice = {"type": "User", "id": "alice"}
        bob = {"type": "User", "id": "bob"}
        file = {"type": "File", "id": "report"}
        entities = [
            {"uid": alice, "attrs": {}, "parents": [team, team, folder]},
            {"uid": bob, "attrs": {}, "parents": [team]},
            {"uid": file, "attrs": {}, "parents": [folder]},
        ]
        path.write_text(json.dumps(entities), encoding="utf-8")
        expected = {"closed": False, "entity_count": 3, "missing_parents": [
            {"parent": team, "children": [alice, bob]},
            {"parent": folder, "children": [alice, file]},
        ]}
        result = run("check-entities", path, "--format", "json")
        assert result.returncode == 0 and json.loads(result.stdout) == expected
        checks += 1
        result = run("check-entities", path, "--require-closed", "--format", "json")
        assert result.returncode == 1 and json.loads(result.stdout) == expected
        checks += 1
        result = run("check-entities", path, "--require-closed")
        assert result.returncode == 1 and 'shared\\narchive' in result.stdout and "Referenced by:" in result.stdout
        checks += 1
        entities.extend({"uid": uid, "attrs": {}, "parents": []} for uid in (team, folder))
        path.write_text(json.dumps(entities), encoding="utf-8")
        result = run("check-entities", path, "--format", "json", "--require-closed")
        assert result.returncode == 0 and json.loads(result.stdout) == {"closed": True, "entity_count": 5, "missing_parents": []}
        checks += 1
        path.write_text("[]", encoding="utf-8")
        result = run("check-entities", path, "--require-closed", "--format", "json")
        assert result.returncode == 0 and json.loads(result.stdout) == {"closed": True, "entity_count": 0, "missing_parents": []}
        checks += 1
        for bad in ([entities[0], entities[0]], [{"uid": team, "attrs": {}, "parents": [team]}], [{"uid": alice, "attrs": {}, "parents": [], "unknown": True}]):
            path.write_text(json.dumps(bad), encoding="utf-8")
            result = run("check-entities", path, "--format", "json")
            assert result.returncode == 2 and not result.stdout
            checks += 1
        for args in (("check-entities",), ("check-entities", path, "--unknown"), ("check-entities", path, "--require-closed", "--require-closed"), ("check-entities", path, "--format", "text")):
            result = run(*args)
            assert result.returncode == 2 and not result.stdout
            checks += 1
    with tempfile.TemporaryDirectory() as tmp:
        path = pathlib.Path(tmp)
        policy, entities, request = (path / name for name in ("policy.cedar", "entities.json", "request.json"))
        for expression in ('Namespace::if::"id" == Namespace::"id"', '{then: 1}["then"] == 1', 'context.false == true'):
            policy.write_text('permit(principal, action, resource) when { ' + expression + ' };', encoding="utf-8")
            result = run("check", policy, "--format", "json")
            assert result.returncode == 2 and not result.stdout
            checks += 1
        policy.write_text('permit(principal == context::"alice", action, resource) when { {"if": 1}["if"] == 1 && context.principal == "read" };', encoding="utf-8")
        entities.write_text("[]", encoding="utf-8")
        request.write_text(json.dumps({"principal": {"type": "context", "id": "alice"}, "action": {"type": "Action", "id": "read"}, "resource": {"type": "File", "id": "report"}, "context": {"principal": "read"}}), encoding="utf-8")
        result = run("authorize", policy, entities, request, "--format", "json")
        assert result.returncode == 0 and json.loads(result.stdout)["decision"] == "Allow"
        checks += 1
    print("CLI checks passed:", checks)


if __name__ == "__main__":
    main()
