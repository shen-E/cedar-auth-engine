#!/usr/bin/env python3
"""Compare the native engine with Cedar CLI 4.13.0 and pinned integration cases."""
import argparse
import datetime
import json
import ipaddress
import pathlib
import re
import random
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
CORPUS = ROOT / "fixtures" / "cedar"


def run(args):
    return subprocess.run([str(x) for x in args], text=True, encoding="utf-8", capture_output=True, timeout=30)


def uid(value):
    return value["type"] + "::" + json.dumps(value["id"], ensure_ascii=False)


def reference(exe, policy, entities, request, temp, template_links=None):
    transformed = {k: uid(request[k]) for k in ("principal", "action", "resource")}
    transformed["context"] = request["context"]
    path = temp / "cedar-request.json"
    path.write_text(json.dumps(transformed, ensure_ascii=False), encoding="utf-8")
    command = [exe, "authorize", "--policies", policy, "--entities", entities,
               "--request-json", path, "--verbose", "--error-format", "plain"]
    if template_links is not None:
        command.extend(["--template-linked", template_links])
    result = run(command)
    output = result.stdout + "\n" + result.stderr
    decision = re.search(r"(?m)^\s*(ALLOW|DENY)\s*$", output)
    if not decision:
        raise RuntimeError("Cedar failed: " + output)
    reasons = re.findall(r"(?m)^  ([^\r\n]+)$", output)
    errors = re.findall(r"error while evaluating policy `([^`]+)`", output)
    return {"decision": decision.group(1).title(), "reasons": sorted(reasons), "errors": sorted(errors)}


def actual(exe, policy, entities, request, temp, extra_args=()):
    path = temp / "request.json"
    path.write_text(json.dumps(request, ensure_ascii=False), encoding="utf-8")
    result = run([exe, "authorize", policy, entities, path, "--format", "json", *extra_args])
    if result.returncode != 0:
        raise RuntimeError("engine failed: " + result.stderr)
    value = json.loads(result.stdout)
    return {"decision": value["decision"], "reasons": sorted(value["reasons"]),
            "errors": sorted(e["policy_id"] for e in value["errors"])}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cedar", required=True, help="path to cedar-policy-cli 4.13.0")
    parser.add_argument("--engine", required=True, help="path to built cedar-auth-engine executable")
    args = parser.parse_args()
    version = run([args.cedar, "--version"])
    if version.returncode or version.stdout.strip() != "cedar-policy-cli 4.13.0":
        raise RuntimeError("expected cedar-policy-cli 4.13.0, got " + version.stdout.strip())
    count = 0
    mismatches = []
    with tempfile.TemporaryDirectory(prefix="cedar-verify-") as tmp:
        temp = pathlib.Path(tmp)
        for name in ("1a", "2a", "2b", "2c", "3a", "3b", "3c", "4a", "5b"):
            fixture = json.loads((CORPUS / (name + ".json")).read_text(encoding="utf-8"))
            policy = CORPUS / ("policies_" + name + ".cedar")
            entities = CORPUS / ("entities_sandbox_b.json" if name in ("4a", "5b") else "entities.json")
            for item in fixture["requests"]:
                request = {k: item[k] for k in ("principal", "action", "resource", "context")}
                expected = {"decision": item["decision"].title(), "reasons": sorted(item["reason"]), "errors": sorted(item["errors"])}
                ref = reference(args.cedar, policy, entities, request, temp)
                got = actual(args.engine, policy, entities, request, temp)
                count += 1
                if got != expected or ref != expected:
                    mismatches.append({"case": name + ": " + item["description"], "expected": expected, "reference": ref, "actual": got})
        for name in ("tenant", "sharing", "admin", "risk", "classified", "invoices", "quota", "network", "tags", "diagnostics", "device", "approvals", "session", "access-window"):
            base = ROOT / "examples" / name
            cases = json.loads((base / "requests.json").read_text(encoding="utf-8"))
            for i, item in enumerate(cases):
                ref = reference(args.cedar, base / "policy.cedar", base / "entities.json", item["request"], temp)
                got = actual(args.engine, base / "policy.cedar", base / "entities.json", item["request"], temp)
                count += 1
                expected = {"decision": item["decision"], "reasons": sorted(item.get("reasons", got["reasons"])), "errors": sorted(item.get("errors", []))}
                if ref != got or got != expected:
                    mismatches.append({"case": name + ":" + str(i), "expected": expected, "reference": ref, "actual": got})
        # Domain context, attributes and tags remain open-ended data.
        open_policy = temp / "open-data-policy.cedar"
        open_entities = temp / "open-data-entities.json"
        open_entities.write_text(json.dumps([{"uid": {"type": "File", "id": "report"}, "attrs": {"tagz": True}, "parents": [], "tags": {"tagz": True}}]), encoding="utf-8")
        open_request = {"principal": {"type": "User", "id": "alice"}, "action": {"type": "Action", "id": "read"},
                        "resource": {"type": "File", "id": "report"}, "context": {"tagz": True, "detail": {"id": 1, "extra": True}, "owner": {"__entity": {"type": "User", "id": "alice"}}}}
        for policy_id, condition in (("attrs", "resource.tagz && context.tagz"),
                                     ("record", "context.detail.extra && context.detail.id == 1"),
                                     ("tags", 'resource.hasTag("tagz") && resource.getTag("tagz")'),
                                     ("owner", "context.owner == principal")):
            open_policy.write_text('@id("' + policy_id + '") permit(principal, action, resource) when { ' + condition + ' };', encoding="utf-8")
            ref = reference(args.cedar, open_policy, open_entities, open_request, temp)
            got = actual(args.engine, open_policy, open_entities, open_request, temp)
            expected = {"decision": "Allow", "reasons": [policy_id], "errors": []}
            count += 1
            if ref != expected or got != expected:
                mismatches.append({"case": "open-data:" + policy_id, "expected": expected, "reference": ref, "actual": got})
        # Compare actual template links, preserving link IDs in reasons and errors.
        sharing = ROOT / "examples" / "template-sharing"
        linked_policy = temp / "linked-reference.cedar"
        linked_policy.write_text((sharing / "policy.cedar").read_text(encoding="utf-8") + "\n" + (sharing / "template.cedar").read_text(encoding="utf-8"), encoding="utf-8")
        links = json.loads((sharing / "links.json").read_text(encoding="utf-8"))
        ref_links = temp / "cedar-links.json"
        ref_links.write_text(json.dumps([{"template_id": "share", "link_id": link["id"], "args": {"?" + slot: uid(link[slot]) for slot in ("principal", "resource") if slot in link}} for link in links]), encoding="utf-8")
        for index, case in enumerate(json.loads((sharing / "requests.json").read_text(encoding="utf-8"))):
            ref = reference(args.cedar, linked_policy, sharing / "entities.json", case["request"], temp, ref_links)
            got = actual(args.engine, sharing / "policy.cedar", sharing / "entities.json", case["request"], temp, ("--template", sharing / "template.cedar", "--links", sharing / "links.json"))
            expected = {"decision": case["decision"], "reasons": sorted(case["reasons"]), "errors": sorted(case["errors"])}
            count += 1
            if ref != got or got != expected:
                mismatches.append({"case": "template-sharing:" + str(index), "expected": expected, "reference": ref, "actual": got})
            request_path = temp / "template-enforce-request.json"
            request_path.write_text(json.dumps(case["request"]), encoding="utf-8")
            enforced = run([args.engine, "enforce", sharing / "policy.cedar", sharing / "entities.json", request_path, "--template", sharing / "template.cedar", "--links", sharing / "links.json", "--format", "json"])
            result = json.loads(enforced.stdout)
            original = result["response"]
            underlying = {"decision": original["decision"], "reasons": sorted(original["reasons"]), "errors": sorted(error["policy_id"] for error in original["errors"])}
            allowed = ref["decision"] == "Allow" and not ref["errors"]
            count += 1
            if underlying != ref or result["allowed"] != allowed or enforced.returncode != (0 if allowed else 1):
                mismatches.append({"case": "template enforcement:" + str(index), "reference": ref, "actual": result, "status": enforced.returncode})
        # Compare two independently linked templates in one policy set.
        multi = ROOT / "examples" / "multi-template"
        multi_policy = temp / "multi-reference.cedar"
        multi_policy.write_text("\n".join((multi / name).read_text(encoding="utf-8") for name in ("policy.cedar", "direct.cedar", "team.cedar")), encoding="utf-8")
        multi_links = temp / "multi-reference-links.json"
        reference_links = []
        for template_id, file_name in (("direct", "direct-links.json"), ("team", "team-links.json")):
            for link in json.loads((multi / file_name).read_text(encoding="utf-8")):
                reference_links.append({"template_id": template_id, "link_id": link["id"], "args": {"?" + slot: uid(link[slot]) for slot in ("principal", "resource") if slot in link}})
        multi_links.write_text(json.dumps(reference_links), encoding="utf-8")
        multi_flags = ("--template", multi / "direct.cedar", "--links", multi / "direct-links.json", "--template", multi / "team.cedar", "--links", multi / "team-links.json")
        multi_cases = json.loads((multi / "requests.json").read_text(encoding="utf-8"))
        multi_input = temp / "multi-batch.json"
        multi_input.write_text(json.dumps([case["request"] for case in multi_cases]), encoding="utf-8")
        multi_batch = run([args.engine, "batch", multi / "policy.cedar", multi / "entities.json", multi_input, *multi_flags, "--format", "json"])
        multi_enforced = run([args.engine, "enforce-batch", multi / "policy.cedar", multi / "entities.json", multi_input, *multi_flags, "--format", "json"])
        multi_test = run([args.engine, "test", multi / "policy.cedar", multi / "entities.json", multi / "requests.json", *multi_flags, "--format", "json"])
        if multi_batch.returncode != 0 or multi_enforced.returncode != 1 or multi_test.returncode != 0:
            raise RuntimeError("multi-template CLI failed: " + multi_batch.stderr + multi_enforced.stderr + multi_test.stderr)
        batch_results = json.loads(multi_batch.stdout)
        enforced_results = json.loads(multi_enforced.stdout)
        test_results = json.loads(multi_test.stdout)["cases"]
        if any(len(items) != len(multi_cases) for items in (batch_results, enforced_results, test_results)):
            raise RuntimeError("multi-template report length mismatch")
        for index, case in enumerate(multi_cases):
            ref = reference(args.cedar, multi_policy, multi / "entities.json", case["request"], temp, multi_links)
            got = actual(args.engine, multi / "policy.cedar", multi / "entities.json", case["request"], temp, multi_flags)
            expected = {"decision": case["decision"], "reasons": sorted(case["reasons"]), "errors": sorted(case["errors"])}
            single_path = temp / "multi-enforce-request.json"
            single_path.write_text(json.dumps(case["request"]), encoding="utf-8")
            single_enforced = run([args.engine, "enforce", multi / "policy.cedar", multi / "entities.json", single_path, *multi_flags, "--format", "json"])
            single_value = json.loads(single_enforced.stdout)
            raw_batch = batch_results[index]
            normalized = {"decision": raw_batch["decision"], "reasons": sorted(raw_batch["reasons"]), "errors": sorted(error["policy_id"] for error in raw_batch["errors"])}
            allowed = ref["decision"] == "Allow" and not ref["errors"]
            count += 5
            if (ref != expected or got != ref or normalized != ref or not test_results[index]["passed"] or
                test_results[index]["response"] != raw_batch or enforced_results[index] != single_value or
                single_value != {"allowed": allowed, "response": raw_batch} or single_enforced.returncode != (0 if allowed else 1)):
                mismatches.append({"case": "multi-template:" + str(index), "expected": expected, "reference": ref, "actual": got, "batch": raw_batch, "enforced": single_value})
        # Compare policy removal with the corresponding Cedar policy set.
        for removed_ids in (("alice-report",), ("carol-report", "design-team"), ("revoked",)):
            removed_policy = temp / "removed-reference.cedar"
            policy_files = ("direct.cedar", "team.cedar") if "revoked" in removed_ids else ("policy.cedar", "direct.cedar", "team.cedar")
            removed_policy.write_text("\n".join((multi / name).read_text(encoding="utf-8") for name in policy_files), encoding="utf-8")
            removed_links = temp / "removed-reference-links.json"
            removed_links.write_text(json.dumps([link for link in reference_links if link["link_id"] not in removed_ids]), encoding="utf-8")
            remove_flags = tuple(value for ident in removed_ids for value in ("--remove-policy", ident))
            batch = run([args.engine, "batch", multi / "policy.cedar", multi / "entities.json", multi_input, *multi_flags, *remove_flags, "--format", "json"])
            if batch.returncode != 0:
                raise RuntimeError("removed policy batch failed: " + batch.stderr)
            results = json.loads(batch.stdout)
            if len(results) != len(multi_cases):
                raise RuntimeError("removed policy batch length mismatch")
            for index, case in enumerate(multi_cases):
                ref = reference(args.cedar, removed_policy, multi / "entities.json", case["request"], temp, removed_links)
                got = actual(args.engine, multi / "policy.cedar", multi / "entities.json", case["request"], temp, (*multi_flags, *remove_flags))
                raw = results[index]
                batch_got = {"decision": raw["decision"], "reasons": sorted(raw["reasons"]), "errors": sorted(error["policy_id"] for error in raw["errors"])}
                count += 2
                if got != ref or batch_got != ref:
                    mismatches.append({"case": "removal:" + ",".join(removed_ids) + ":" + str(index), "reference": ref, "actual": got, "batch": batch_got})
        # Compare an added forbid and replacements of a static policy and a link.
        update = ROOT / "examples" / "policy-update"
        update_policy = temp / "updates-reference.cedar"
        update_policy.write_text("\n".join(p.read_text(encoding="utf-8") for p in (
            multi / "direct.cedar", multi / "team.cedar",
            update / "additional.cedar", update / "replacements.cedar")), encoding="utf-8")
        update_links = temp / "updates-reference-links.json"
        update_links.write_text(json.dumps([link for link in reference_links if link["link_id"] != "alice-report"]), encoding="utf-8")
        update_cases = json.loads((update / "requests.json").read_text(encoding="utf-8"))
        update_flags = (*multi_flags, "--add-policies", update / "additional.cedar", "--replace-policies", update / "replacements.cedar")
        update_input = temp / "updates-batch.json"
        update_input.write_text(json.dumps([case["request"] for case in update_cases]), encoding="utf-8")
        update_batch = run([args.engine, "batch", multi / "policy.cedar", multi / "entities.json", update_input, *update_flags, "--format", "json"])
        if update_batch.returncode != 0:
            raise RuntimeError("updated policy batch failed: " + update_batch.stderr)
        update_results = json.loads(update_batch.stdout)
        if len(update_results) != len(update_cases):
            raise RuntimeError("updated policy batch length mismatch")
        for index, case in enumerate(update_cases):
            ref = reference(args.cedar, update_policy, multi / "entities.json", case["request"], temp, update_links)
            got = actual(args.engine, multi / "policy.cedar", multi / "entities.json", case["request"], temp, update_flags)
            raw = update_results[index]
            batch_got = {"decision": raw["decision"], "reasons": sorted(raw["reasons"]), "errors": sorted(error["policy_id"] for error in raw["errors"])}
            expected = {"decision": case["decision"], "reasons": sorted(case["reasons"]), "errors": sorted(case["errors"])}
            count += 2
            if got != ref or batch_got != ref or ref != expected:
                mismatches.append({"case": "updates:" + str(index), "expected": expected, "reference": ref, "actual": got, "batch": batch_got})
        # Compare both sides of the impact report against Cedar independently.
        comparison = ROOT / "examples" / "policy-comparison"
        compare_before = multi_policy
        compare_after = temp / "comparison-after.cedar"
        compare_after.write_text("\n".join(p.read_text(encoding="utf-8") for p in (
            comparison / "after.cedar", comparison / "direct.cedar", multi / "team.cedar")), encoding="utf-8")
        compare_flags = ("--before-template", multi / "direct.cedar", "--before-links", multi / "direct-links.json",
                         "--before-template", multi / "team.cedar", "--before-links", multi / "team-links.json",
                         "--after-template", comparison / "direct.cedar", "--after-links", multi / "direct-links.json",
                         "--after-template", multi / "team.cedar", "--after-links", multi / "team-links.json")
        compare_run = run([args.engine, "compare", multi / "policy.cedar", comparison / "after.cedar", multi / "entities.json", comparison / "requests.json", *compare_flags, "--format", "json"])
        if compare_run.returncode:
            raise RuntimeError("policy comparison failed: " + compare_run.stderr)
        compare_cases = json.loads((comparison / "requests.json").read_text(encoding="utf-8"))
        compare_report = json.loads(compare_run.stdout)
        if compare_report["total"] != len(compare_cases) or len(compare_report["cases"]) != len(compare_cases):
            raise RuntimeError("policy comparison length mismatch")
        for index, request in enumerate(compare_cases):
            old = reference(args.cedar, compare_before, multi / "entities.json", request, temp, multi_links)
            new = reference(args.cedar, compare_after, multi / "entities.json", request, temp, multi_links)
            case = compare_report["cases"][index]
            def normalize(response):
                return {"decision": response["decision"], "reasons": sorted(response["reasons"]), "errors": sorted(error["policy_id"] for error in response["errors"])}
            old_allowed = old["decision"] == "Allow" and not old["errors"]
            new_allowed = new["decision"] == "Allow" and not new["errors"]
            expected_flags = {"decision_changed": old["decision"] != new["decision"],
                              "enforcement_changed": old_allowed != new_allowed,
                              "reasons_changed": old["reasons"] != new["reasons"],
                              "errors_changed": old["errors"] != new["errors"]}
            count += 2
            if (normalize(case["before"]) != old or normalize(case["after"]) != new or
                case["before_allowed"] != old_allowed or case["after_allowed"] != new_allowed or
                any(case[key] != value for key, value in expected_flags.items()) or
                case["changed"] != any(expected_flags.values())):
                mismatches.append({"case": "compare:" + str(index), "before": old, "after": new, "actual": case})
        # Compose both comparison sides with additions, replacements and removals.
        composed_before = temp / "composed-before.cedar"
        composed_before.write_text(multi_policy.read_text(encoding="utf-8") + "\n" + (update / "additional.cedar").read_text(encoding="utf-8"), encoding="utf-8")
        composed_before_links = temp / "composed-before-links.json"
        composed_before_links.write_text(json.dumps([link for link in reference_links if link["link_id"] != "carol-report"]), encoding="utf-8")
        composed_after_links = temp / "composed-after-links.json"
        composed_after_links.write_text(json.dumps([link for link in reference_links if link["link_id"] not in ("alice-report", "design-team")]), encoding="utf-8")
        composed_flags = ("--before-template", multi / "direct.cedar", "--before-links", multi / "direct-links.json",
                          "--before-template", multi / "team.cedar", "--before-links", multi / "team-links.json",
                          "--before-add-policies", update / "additional.cedar", "--before-remove-policy", "carol-report",
                          "--after-template", multi / "direct.cedar", "--after-links", multi / "direct-links.json",
                          "--after-template", multi / "team.cedar", "--after-links", multi / "team-links.json",
                          "--after-add-policies", update / "additional.cedar", "--after-replace-policies", update / "replacements.cedar",
                          "--after-remove-policy", "design-team")
        composed_run = run([args.engine, "compare", multi / "policy.cedar", multi / "policy.cedar", multi / "entities.json", comparison / "requests.json", *composed_flags, "--format", "json"])
        if composed_run.returncode:
            raise RuntimeError("composed policy comparison failed: " + composed_run.stderr)
        composed_report = json.loads(composed_run.stdout)
        if composed_report["total"] != len(compare_cases) or len(composed_report["cases"]) != len(compare_cases):
            raise RuntimeError("composed comparison length mismatch")
        for index, request in enumerate(compare_cases):
            old = reference(args.cedar, composed_before, multi / "entities.json", request, temp, composed_before_links)
            new = reference(args.cedar, update_policy, multi / "entities.json", request, temp, composed_after_links)
            case = composed_report["cases"][index]
            old_allowed = old["decision"] == "Allow" and not old["errors"]
            new_allowed = new["decision"] == "Allow" and not new["errors"]
            expected_flags = {"decision_changed": old["decision"] != new["decision"],
                              "enforcement_changed": old_allowed != new_allowed,
                              "reasons_changed": old["reasons"] != new["reasons"],
                              "errors_changed": old["errors"] != new["errors"]}
            count += 2
            if (normalize(case["before"]) != old or normalize(case["after"]) != new or
                case["before_allowed"] != old_allowed or case["after_allowed"] != new_allowed or
                any(case[key] != value for key, value in expected_flags.items()) or
                case["changed"] != any(expected_flags.values())):
                mismatches.append({"case": "composed-compare:" + str(index), "before": old, "after": new, "actual": case})
        # Compare entity snapshots with Cedar using the same linked policy set.
        entities_example = ROOT / "examples" / "entity-comparison"
        entity_policy = temp / "entity-comparison.cedar"
        entity_policy.write_text("\n".join((multi / name).read_text(encoding="utf-8") for name in ("policy.cedar", "team.cedar")), encoding="utf-8")
        entity_links = temp / "entity-comparison-links.json"
        entity_links.write_text(json.dumps([link for link in reference_links if link["link_id"] == "design-team"]), encoding="utf-8")
        entity_flags = ("--before-template", multi / "team.cedar", "--before-links", multi / "team-links.json",
                        "--after-template", multi / "team.cedar", "--after-links", multi / "team-links.json",
                        "--after-entities", entities_example / "after-entities.json")
        entity_run = run([args.engine, "compare", multi / "policy.cedar", multi / "policy.cedar", multi / "entities.json", entities_example / "requests.json", *entity_flags, "--format", "json"])
        if entity_run.returncode:
            raise RuntimeError("entity comparison failed: " + entity_run.stderr)
        entity_requests = json.loads((entities_example / "requests.json").read_text(encoding="utf-8"))
        entity_report = json.loads(entity_run.stdout)
        if entity_report["total"] != len(entity_requests) or len(entity_report["cases"]) != len(entity_requests):
            raise RuntimeError("entity comparison length mismatch")
        for index, request in enumerate(entity_requests):
            old = reference(args.cedar, entity_policy, multi / "entities.json", request, temp, entity_links)
            new = reference(args.cedar, entity_policy, entities_example / "after-entities.json", request, temp, entity_links)
            case = entity_report["cases"][index]
            old_allowed = old["decision"] == "Allow" and not old["errors"]
            new_allowed = new["decision"] == "Allow" and not new["errors"]
            expected_flags = {"decision_changed": old["decision"] != new["decision"],
                              "enforcement_changed": old_allowed != new_allowed,
                              "reasons_changed": old["reasons"] != new["reasons"],
                              "errors_changed": old["errors"] != new["errors"]}
            count += 2
            if (normalize(case["before"]) != old or normalize(case["after"]) != new or
                case["before_allowed"] != old_allowed or case["after_allowed"] != new_allowed or
                any(case[key] != value for key, value in expected_flags.items()) or
                case["changed"] != any(expected_flags.values())):
                mismatches.append({"case": "entity-compare:" + str(index), "before": old, "after": new, "actual": case})
        # Repeated requests share hierarchy lookups but retain independent diagnostics.
        repeated_requests = entity_requests * 2
        repeated_file = temp / "repeated-hierarchy-requests.json"
        repeated_file.write_text(json.dumps(repeated_requests), encoding="utf-8")
        team_flags = ("--template", multi / "team.cedar", "--links", multi / "team-links.json")
        for graph_name, graph_path in (("before", multi / "entities.json"), ("after", entities_example / "after-entities.json")):
            repeated_batch = run([args.engine, "batch", multi / "policy.cedar", graph_path, repeated_file, *team_flags, "--format", "json"])
            if repeated_batch.returncode:
                raise RuntimeError("hierarchy batch failed: " + repeated_batch.stderr)
            repeated_results = json.loads(repeated_batch.stdout)
            if len(repeated_results) != len(repeated_requests):
                raise RuntimeError("hierarchy batch length mismatch")
            for index, request in enumerate(repeated_requests):
                ref = reference(args.cedar, entity_policy, graph_path, request, temp, entity_links)
                got = actual(args.engine, multi / "policy.cedar", graph_path, request, temp, team_flags)
                raw = repeated_results[index]
                batch_got = {"decision": raw["decision"], "reasons": sorted(raw["reasons"]), "errors": sorted(error["policy_id"] for error in raw["errors"])}
                count += 2
                if got != ref or batch_got != ref:
                    mismatches.append({"case": "repeated-hierarchy:" + graph_name + ":" + str(index), "reference": ref, "single": got, "batch": batch_got})
        # Check directional gates against independent Cedar decisions and errors.
        direction_before = temp / "direction-before.cedar"
        direction_after = temp / "direction-after.cedar"
        direction_entities = temp / "direction-entities.json"
        direction_requests = temp / "direction-requests.json"
        direction_entities.write_text("[]", encoding="utf-8")
        direction_request = {"principal":{"type":"User","id":"alice"},"action":{"type":"Action","id":"read"},"resource":{"type":"File","id":"report"},"context":{}}
        direction_requests.write_text(json.dumps([direction_request]), encoding="utf-8")
        permit = '@id("permit") permit(principal, action, resource);'
        guard_error = '@id("guard") forbid(principal, action, resource) when { context.missing };'
        direction_pairs = (("", permit), (permit, ""), ("", permit + guard_error),
                           (permit + guard_error, permit), (permit, permit + guard_error),
                           (permit + guard_error, ""), ("", guard_error), ("", ""),
                           (permit + guard_error, permit + guard_error))
        gate_flags = {"decision_granted": "--fail-on-decision-grant", "decision_revoked": "--fail-on-decision-revoke",
                      "enforcement_granted": "--fail-on-enforcement-grant", "enforcement_revoked": "--fail-on-enforcement-revoke"}
        for index, (old_source, new_source) in enumerate(direction_pairs):
            direction_before.write_text(old_source, encoding="utf-8")
            direction_after.write_text(new_source, encoding="utf-8")
            old = reference(args.cedar, direction_before, direction_entities, direction_request, temp)
            new = reference(args.cedar, direction_after, direction_entities, direction_request, temp)
            old_allowed = old["decision"] == "Allow" and not old["errors"]
            new_allowed = new["decision"] == "Allow" and not new["errors"]
            expected_directions = {"decision_granted": old["decision"] == "Deny" and new["decision"] == "Allow",
                                   "decision_revoked": old["decision"] == "Allow" and new["decision"] == "Deny",
                                   "enforcement_granted": not old_allowed and new_allowed,
                                   "enforcement_revoked": old_allowed and not new_allowed}
            command = [args.engine, "compare", direction_before, direction_after, direction_entities, direction_requests, "--format", "json"]
            result = run(command)
            if result.returncode:
                raise RuntimeError("direction comparison failed: " + result.stderr)
            report = json.loads(result.stdout)
            if len(report["cases"]) != 1:
                raise RuntimeError("direction comparison length mismatch")
            case = report["cases"][0]
            if (normalize(case["before"]) != old or normalize(case["after"]) != new or
                any(case[key] != value for key, value in expected_directions.items())):
                mismatches.append({"case": "directions:" + str(index), "before": old, "after": new, "actual": case})
            for key, flag in gate_flags.items():
                gated = run([*command, flag])
                if gated.returncode != (1 if expected_directions[key] else 0) or json.loads(gated.stdout) != report:
                    mismatches.append({"case": "direction-gate:" + str(index) + ":" + key, "actual_status": gated.returncode})
            after_error_gate = run([*command, "--fail-on-after-error"])
            if (report["after_error_requests"] != int(bool(new["errors"])) or
                after_error_gate.returncode != (1 if new["errors"] else 0) or json.loads(after_error_gate.stdout) != report):
                mismatches.append({"case": "after-error-gate:" + str(index), "actual_status": after_error_gate.returncode})
            count += 2
        # Exercise single-slot, hierarchy, typed scopes and forbid links too.
        engine_policy = temp / "template-static.cedar"
        template_path = temp / "template.cedar"
        engine_links = temp / "template-links.json"
        template_entities = temp / "template-entities.json"
        def entity(kind, ident):
            return {"type": kind, "id": ident}
        template_entities.write_text(json.dumps([
            {"uid": entity("User", "alice"), "attrs": {}, "parents": [entity("Group", "team")]},
            {"uid": entity("File", "report"), "attrs": {}, "parents": [entity("Folder", "shared")]},
        ]), encoding="utf-8")
        request = {"principal": entity("User", "alice"), "action": entity("Action", "read"), "resource": entity("File", "report"), "context": {}}
        for source, slot_values, base in [
            ('permit(principal in ?principal, action, resource in ?resource);', {"principal": entity("Group", "team"), "resource": entity("Folder", "shared")}, ''),
            ('permit(principal is User in ?principal, action, resource is File in ?resource);', {"principal": entity("Group", "team"), "resource": entity("Folder", "shared")}, ''),
            ('permit(principal is Group in ?principal, action, resource is File in ?resource);', {"principal": entity("Group", "team"), "resource": entity("Folder", "shared")}, ''),
            ('permit(principal == ?principal, action, resource);', {"principal": entity("User", "alice")}, ''),
            ('permit(principal, action, resource == ?resource);', {"resource": entity("File", "report")}, ''),
            ('forbid(principal, action, resource == ?resource);', {"resource": entity("File", "report")}, '@id("base") permit(principal, action, resource);'),
        ]:
            engine_policy.write_text(base, encoding="utf-8")
            template_path.write_text('@id("template") ' + source, encoding="utf-8")
            linked_policy.write_text(base + '\n@id("template") ' + source, encoding="utf-8")
            engine_links.write_text(json.dumps([{"id": "linked", **slot_values}]), encoding="utf-8")
            ref_links.write_text(json.dumps([{"template_id": "template", "link_id": "linked", "args": {"?" + key: uid(value) for key, value in slot_values.items()}}]), encoding="utf-8")
            ref = reference(args.cedar, linked_policy, template_entities, request, temp, ref_links)
            got = actual(args.engine, engine_policy, template_entities, request, temp, ("--template", template_path, "--links", engine_links))
            count += 1
            if ref != got:
                mismatches.append({"case": "template scope: " + source, "reference": ref, "actual": got})
        # Compare ordered batch responses with independent Cedar authorizations.
        for name in ("diagnostics", "tags", "device"):
            base = ROOT / "examples" / name
            cases = json.loads((base / "requests.json").read_text(encoding="utf-8"))
            batch_input = temp / "batch-requests.json"
            batch_input.write_text(json.dumps([item["request"] for item in cases], ensure_ascii=False), encoding="utf-8")
            command = [args.engine, "batch", base / "policy.cedar", base / "entities.json", batch_input]
            batch = run(command + ["--format", "json"])
            strict = run(command + ["--strict", "--format", "json"])
            if batch.returncode != 0:
                mismatches.append({"case": name + ":batch", "status": batch.returncode, "stderr": batch.stderr})
                continue
            try:
                responses = json.loads(batch.stdout)
                strict_responses = json.loads(strict.stdout)
            except json.JSONDecodeError:
                mismatches.append({"case": name + ":batch output", "stdout": batch.stdout, "strict_stdout": strict.stdout})
                continue
            if not isinstance(responses, list) or len(responses) != len(cases):
                mismatches.append({"case": name + ":batch length", "responses": responses})
                continue
            strict_status = 1 if any(response["errors"] for response in responses) else 0
            if strict.returncode != strict_status or strict_responses != responses:
                mismatches.append({"case": name + ":strict batch", "status": strict.returncode, "expected_status": strict_status})
            for i, (item, response) in enumerate(zip(cases, responses)):
                ref = reference(args.cedar, base / "policy.cedar", base / "entities.json", item["request"], temp)
                got = {"decision": response["decision"], "reasons": sorted(response["reasons"]), "errors": sorted(error["policy_id"] for error in response["errors"])}
                count += 1
                if ref != got:
                    mismatches.append({"case": name + ":batch:" + str(i), "reference": ref, "actual": got})
        # Verify fail-closed single and batch decisions against Cedar responses.
        for name in ("diagnostics", "tags", "device"):
            base = ROOT / "examples" / name
            cases = json.loads((base / "requests.json").read_text(encoding="utf-8"))
            input_path = temp / "enforcement-batch.json"
            input_path.write_text(json.dumps([case["request"] for case in cases], ensure_ascii=False), encoding="utf-8")
            batch = run([args.engine, "enforce-batch", base / "policy.cedar", base / "entities.json", input_path, "--format", "json"])
            if batch.returncode not in (0, 1):
                mismatches.append({"case": name + ":enforce-batch status", "status": batch.returncode, "stderr": batch.stderr})
                continue
            results = json.loads(batch.stdout)
            if not isinstance(results, list) or len(results) != len(cases):
                mismatches.append({"case": name + ":enforce-batch length", "responses": results})
                continue
            any_denied = False
            for index, (case, batch_result) in enumerate(zip(cases, results)):
                ref = reference(args.cedar, base / "policy.cedar", base / "entities.json", case["request"], temp)
                allowed = ref["decision"] == "Allow" and not ref["errors"]
                any_denied |= not allowed
                request_path = temp / "enforcement-request.json"
                request_path.write_text(json.dumps(case["request"], ensure_ascii=False), encoding="utf-8")
                single = run([args.engine, "enforce", base / "policy.cedar", base / "entities.json", request_path, "--format", "json"])
                result = json.loads(single.stdout)
                original = result["response"]
                underlying = {"decision": original["decision"], "reasons": sorted(original["reasons"]), "errors": sorted(error["policy_id"] for error in original["errors"])}
                count += 2
                if underlying != ref or result["allowed"] != allowed or single.returncode != (0 if allowed else 1) or batch_result != result:
                    mismatches.append({"case": name + ":enforcement:" + str(index), "reference": ref, "actual": result, "batch": batch_result, "status": single.returncode})
            if batch.returncode != (1 if any_denied else 0):
                mismatches.append({"case": name + ":enforce-batch exit", "status": batch.returncode})
        # Check the case-test command against independent Cedar decisions.
        for name in ("diagnostics", "tags", "device"):
            base = ROOT / "examples" / name
            cases = json.loads((base / "requests.json").read_text(encoding="utf-8"))
            report = run([args.engine, "test", base / "policy.cedar", base / "entities.json", base / "requests.json", "--format", "json"])
            if report.returncode != 0:
                mismatches.append({"case": name + ":test command", "status": report.returncode, "stderr": report.stderr})
                continue
            data = json.loads(report.stdout)
            if data["failures"] != 0 or len(data["cases"]) != len(cases):
                mismatches.append({"case": name + ":test report", "report": data})
                continue
            for index, (case, result) in enumerate(zip(cases, data["cases"])):
                ref = reference(args.cedar, base / "policy.cedar", base / "entities.json", case["request"], temp)
                response = result["response"]
                got = {"decision": response["decision"], "reasons": sorted(response["reasons"]), "errors": sorted(error["policy_id"] for error in response["errors"])}
                count += 1
                if ref != got or result["index"] != index or not result["passed"]:
                    mismatches.append({"case": name + ":test:" + str(index), "reference": ref, "actual": got, "report": result})
        policy = temp / "errors.cedar"
        entities = temp / "entities.json"
        policy.write_text('permit(principal, action, resource); forbid(principal, action, resource) when { resource.missing };', encoding="utf-8")
        entities.write_text('[]', encoding="utf-8")
        request = {"principal": {"type": "User", "id": "alice"}, "action": {"type": "Action", "id": "read"},
                   "resource": {"type": "File", "id": "r"}, "context": {}}
        ref = reference(args.cedar, policy, entities, request, temp)
        got = actual(args.engine, policy, entities, request, temp)
        count += 1
        if ref != got:
            mismatches.append({"case": "skip-on-error", "reference": ref, "actual": got})
        # Compare set equality and membership, including duplicate values.
        set_rng = random.Random(20261104)
        set_cases = [([], []), ([1, 1, 2], [2, 1]), ([1], [1, 2]), ([0, 1, 2], [2, 1, 0])]
        set_cases.extend(([set_rng.randrange(4) for _ in range(set_rng.randrange(7))], [set_rng.randrange(4) for _ in range(set_rng.randrange(7))]) for _ in range(12))
        set_expressions = (
            ("context.left == context.right", lambda a, b: set(a) == set(b)),
            ("context.left.containsAll(context.right)", lambda a, b: set(b) <= set(a)),
            ("context.left.containsAny(context.right)", lambda a, b: bool(set(a) & set(b))),
            ("context.left.contains(context.needle)", lambda a, b: 2 in a),
        )
        for left, right in set_cases:
            for expression, oracle in set_expressions:
                policy.write_text('permit(principal, action, resource) when { ' + expression + ' };', encoding="utf-8")
                candidate = {**request, "context": {"left": left, "right": right, "needle": 2}}
                ref = reference(args.cedar, policy, entities, candidate, temp)
                got = actual(args.engine, policy, entities, candidate, temp)
                expected = "Allow" if oracle(left, right) else "Deny"
                count += 1
                if ref != got or ref["decision"] != expected or ref["errors"]:
                    mismatches.append({"case": "set comparison: " + expression, "left": left, "right": right, "reference": ref, "actual": got, "expected": expected})
        for levels, same in ((1, True), (10, True), (26, True), (50, False)):
            left, right = 1, (1 if same else 2)
            for _ in range(levels):
                left, right = [left], [right]
            policy.write_text('permit(principal, action, resource) when { context.left == context.right };', encoding="utf-8")
            candidate = {**request, "context": {"left": left, "right": right}}
            ref = reference(args.cedar, policy, entities, candidate, temp)
            got = actual(args.engine, policy, entities, candidate, temp)
            count += 1
            if ref != got or got["decision"] != ("Allow" if same else "Deny"):
                mismatches.append({"case": "nested set comparison", "depth": levels, "reference": ref, "actual": got})
        # Compare datetime parsing and operations with Cedar 4.13.0.
        datetime_values = [
            "1970-01-01", "0000-01-01", "9999-12-31", "2000-02-29", "1900-02-28",
            "1900-02-29", "2023-02-29", "2024-04-31", "2024-13-01", "2024-01-00",
            "2024-01-01T00:00:00Z", "2024-01-01T00:00:00.123Z", "2024-01-01T00:00:00+2359",
            "2024-01-01T00:00:00.123-0500", "2024-01-01T00:00:00-0000", "2024-01-01Z",
            "2024-01-01 ", "2024-01-01T00:00:00", "2024-01-01t00:00:00z", "2024-01-01T24:00:00Z",
            "2024-01-01T00:60:00Z", "2016-12-31T23:59:60Z", "2024-01-01T00:00:00.1Z",
            "2024-01-01T00:00:00.01Z", "2024-01-01T00:00:00.0000Z", "2024-01-01T00:00:00+00:00",
            "2024-01-01T00:00:00+2400", "2024-01-01T00:00:00+0060", "2024-01-01T00:00:00ZZ", "00011-12-13", "",
        ]
        datetime_expressions = [
            'datetime("1970-01-01") == datetime("1969-12-31T19:00:00-0500")',
            'datetime("1970-01-01") < datetime("1970-01-02")',
            'datetime("1970-01-01") <= datetime("1970-01-01")',
            'datetime("1970-01-02") > datetime("1970-01-01")',
            'datetime("1970-01-01") >= datetime("1970-01-01")',
            'datetime("1970-01-01") == 0', 'datetime("1970-01-01") < 0',
            'datetime("2024-10-15").offset(duration("1h")) == datetime("2024-10-15T01:00:00Z")',
            'datetime("2024-10-15T01:00:00Z").durationSince(datetime("2024-10-15")) == duration("1h")',
            'datetime("1969-12-31T23:59:59.999Z").toDate() == datetime("1969-12-31")',
            'datetime("1969-12-31T23:59:59.999Z").toTime() == duration("23h59m59s999ms")',
            'datetime("2025-02-20T22:00:00-0500").toDate() == datetime("2025-02-21")',
            'datetime("2025-02-20T22:00:00-0500").toTime() == duration("3h")',
            'datetime("1970-01-01").offset(duration("9223372036854775807ms")).offset(duration("1ms")) == datetime("1970-01-01")',
            'datetime("1970-01-01").offset(duration("-9223372036854775808ms")).toDate() == datetime("1970-01-01")',
            'datetime("1970-01-01").offset(duration("-9223372036854775808ms")).toTime() >= duration("0ms")',
            'datetime("1970-01-01").durationSince(datetime("1970-01-01").offset(duration("-9223372036854775808ms"))) == duration("0ms")',
            'datetime(1) == datetime("1970-01-01")',
            'datetime("1970-01-01").offset(1) == datetime("1970-01-01")',
            'duration("1h").toDate() == datetime("1970-01-01")',
            'true || datetime("bad") == datetime("1970-01-01")',
        ]
        datetime_cases = [(expression, {}, None) for expression in datetime_expressions]
        datetime_cases += [('datetime(context.input) == datetime("1970-01-01")', {"input": value}, None) for value in datetime_values]
        # Python's calendar arithmetic is an independent oracle for generated UTC offsets.
        time_rng = random.Random(4096)
        epoch = datetime.datetime(1970, 1, 1)
        for _ in range(20):
            year = time_rng.randint(1900, 2100)
            month = time_rng.randint(1, 12)
            day = time_rng.randint(1, 28)
            hour, minute, second, milli = time_rng.randrange(24), time_rng.randrange(60), time_rng.randrange(60), time_rng.randrange(1000)
            offset_minutes = time_rng.randint(-1439, 1439)
            sign = "+" if offset_minutes >= 0 else "-"
            zone_hour, zone_minute = divmod(abs(offset_minutes), 60)
            stamp = f"{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{milli:03}{sign}{zone_hour:02}{zone_minute:02}"
            local_time = datetime.datetime(year, month, day, hour, minute, second, milli * 1000)
            delta = local_time - datetime.timedelta(minutes=offset_minutes) - epoch
            expected_millis = delta.days * 86400000 + delta.seconds * 1000 + delta.microseconds // 1000
            datetime_cases.append(('datetime(context.input).durationSince(datetime("1970-01-01")).toMilliseconds() == context.expected', {"input": stamp, "expected": expected_millis}, "Allow"))
        for expression, context, expected in datetime_cases:
            policy.write_text('permit(principal, action, resource) when { ' + expression + ' };', encoding="utf-8")
            candidate = {**request, "context": context}
            ref = reference(args.cedar, policy, entities, candidate, temp)
            got = actual(args.engine, policy, entities, candidate, temp)
            count += 1
            if ref != got or (expected is not None and (ref["decision"] != expected or got["decision"] != expected)):
                mismatches.append({"case": "datetime: " + expression, "context": context, "reference": ref, "actual": got})
        # Check ordered duration units, bounds, comparison and conversions.
        duration_values = [
            "", "-", "0", "0ms", "-0ms", "1ms", "-1ms", "1s", "1m", "1h", "1d",
            "1d2h3m4s5ms", "-1d2h3m4s5ms", "00h001m", "1h60m", "1m1ms",
            "00000000000000000000001ms", "9223372036854775807ms", "-9223372036854775808ms",
            "9223372036854775808ms", "-9223372036854775809ms", "1d9223372036854775807ms",
            "106751991168d", "+1h", "--1h", "1h-1m", "1m1h", "1s1s", "1ms1s",
            "1h ", " 1h", "1.5h", "1H", "１h", "1d2", "ms",
        ]
        duration_expressions = [
            'duration("1h30m") == duration("90m")',
            'duration("-1ms") < duration("0ms")',
            'duration("1h") <= duration("60m")',
            'duration("2h") > duration("1h")',
            'duration("1h") >= duration("60m")',
            'duration("1h") < duration("60m")',
            'duration("1h") == 3600000',
            'duration("1h") < 3600000',
            'duration("4s100ms").toMilliseconds() == 4100',
            'duration("-1500ms").toSeconds() == -1',
            'duration("-1ms").toSeconds() == 0',
            'duration("4m70s").toMinutes() == 5',
            'duration("4h70m").toHours() == 5',
            'duration("4d30h").toDays() == 5',
            'duration("-9223372036854775808ms").toMilliseconds() == -9223372036854775808',
            'duration(1) == duration("1s")',
            'duration("1s1h") == duration("1h1s")',
            '1.toSeconds() == 1',
            'true || duration("bad") == duration("0ms")',
            'duration(if true then "2h" else "bad") >= duration("119m")',
        ]
        for expression, context in (
            [(expression, {}) for expression in duration_expressions] +
            [('duration(context.input) == duration("0ms")', {"input": value}) for value in duration_values]
        ):
            policy.write_text('permit(principal, action, resource) when { ' + expression + ' };', encoding="utf-8")
            candidate = {**request, "context": context}
            ref = reference(args.cedar, policy, entities, candidate, temp)
            got = actual(args.engine, policy, entities, candidate, temp)
            count += 1
            if ref != got:
                mismatches.append({"case": "duration: " + expression, "context": context, "reference": ref, "actual": got})
        # Exercise the decimal constructor and comparison methods against Cedar.
        decimal_values = [
            "0.0", "-0.0", "00.000", "0000000000000000000001.0", "1.0", "-1.0001",
            "0.0001", "-0.0001", "922337203685477.5807", "-922337203685477.5808",
            "922337203685477.5808", "-922337203685477.5809", "1000000000000000.0",
            "", ".1", "1.", "1", "1.00000", "+1.0", "--1.0", "1.2.3", " 1.0",
            "1.0 ", "1e1.0", "１２.０",
        ]
        decimal_expressions = [
            'decimal("1.00") == decimal("01.0000")',
            'decimal("-0.0000") == decimal("0.0")',
            'decimal("0.0001").greaterThan(decimal("0.0"))',
            'decimal("-0.0001").lessThan(decimal("0.0"))',
            'decimal("-922337203685477.5808").lessThan(decimal("922337203685477.5807"))',
            'decimal("1.0").lessThan(decimal("1.0"))',
            'decimal("1.0").lessThanOrEqual(decimal("1.00"))',
            'decimal("1.0").greaterThan(decimal("1.0"))',
            'decimal("1.0").greaterThanOrEqual(decimal("1.00"))',
            'decimal("1.0") == 1',
            '[decimal("1.00")].contains(decimal("1.0"))',
            'decimal(1) == decimal("1.0")',
            'decimal("1.0").lessThan(1)',
            '1.greaterThan(decimal("1.0"))',
            'false && decimal("bad") == decimal("1.0")',
            'true || decimal("bad") == decimal("1.0")',
            'decimal(if true then "1.5" else "bad").lessThan(decimal("2.0"))',
        ]
        for expression, context in (
            [(expression, {}) for expression in decimal_expressions] +
            [('decimal(context.input) == decimal("1.0")', {"input": value}) for value in decimal_values]
        ):
            policy.write_text('permit(principal, action, resource) when { ' + expression + ' };', encoding="utf-8")
            candidate = {**request, "context": context}
            ref = reference(args.cedar, policy, entities, candidate, temp)
            got = actual(args.engine, policy, entities, candidate, temp)
            count += 1
            if ref != got:
                mismatches.append({"case": "decimal: " + expression, "context": context, "reference": ref, "actual": got})
        for expression in (
            '[1, 2, 1] == [2, 1]',
            '9223372036854775807 == 9223372036854775807',
            'context has missing',
            'true || resource.missing',
            'false && resource.missing',
            '{name: "ok"}.name == "ok"',
            'principal in User::"alice"',
            '[1, 2].contains(2)',
            '[1, 2].contains(3)',
            '[1, "two"].contains("two")',
            '[1, 2].containsAll([2, 1, 1])',
            '[1].containsAll([])',
            '[1].containsAll([2])',
            '[1, 2].containsAny([2, 3])',
            '[1].containsAny([])',
            '[1].containsAny([2])',
            '[].isEmpty()',
            '[1].isEmpty()',
            '[[1, 2], {name: 1}].contains([2, 1])',
            '"a".contains("a")',
            '[1].containsAll(1)',
            '[1].containsAny(1)',
            '1.isEmpty()',
            '-9223372036854775808 < 9223372036854775807',
            '9223372036854775807 >= 9223372036854775807',
            '-5 <= -5',
            '0 > -1',
            '1 < 1',
            '2 <= 1',
            '1 > 1',
            '1 >= 2',
            '1 < "2"',
            'true || ("x" < 1)',
            'principal is User',
            'principal is Group',
            'principal is Example::User',
            '1 is User',
            'principal is Group in resource.missing',
            'principal is User in User::"alice"',
            'if true then true else resource.missing',
            'if false then resource.missing else true',
            '(if true then 3 else 1) == 3',
            'if true then (if false then false else true) else false',
            'if 1 then true else false',
            'if false then true else 1',
            'context has "missing field"',
            'context["missing field"] == 1',
            '{"team-id": "alpha"}["team-id"] == "alpha"',
            '{"settings": {"retention.days": 30}}.settings["retention.days"] == 30',
            '"ham and eggs" like "ham*"',
            '"ham and eggs" like "*ham"',
            '"Gotham" like "*ham"',
            '"ham" like "*h*a*m*"',
            '"" like "**"',
            '"abc" like "a**c"',
            r'"string*with*stars" like "string\*with\*stars"',
            r'"a*b" like "a\u{2a}b"',
            r'"axb" like "a\u{2a}b"',
            r'"a*b" like "a\x2ab"',
            r'"axb" like "a\x2ab"',
            r'"\u{1f600}" == "😀"',
            r'"\u{0_41}" == "A"',
            r'"\u{41_}" == "A"',
            r'"\x41" == "A"',
            r'"\0" == "\x00"',
            r'"a\nb" like "a*b"',
            '1 like "*"',
            'true || (1 like "*")',
            '1+2*3 == 7',
            '(1+2)*3 == 9',
            '10-3-2 == 5',
            '1--2 == 3',
            '1*-2 == -2',
            '--1 == 1',
            '- -1 == 1',
            '- 1 == -1',
            '-9223372036854775808 + 1 == -9223372036854775807',
            '9223372036854775807 - 1 == 9223372036854775806',
            '(-3037000499 * -3037000499) == 9223372030926249001',
            '-9223372036854775808 * 0 == 0',
            '0 - -9223372036854775807 == 9223372036854775807',
            '9223372036854775807 + 1 > 0',
            '-9223372036854775808 + -1 < 0',
            '-9223372036854775808 - 1 < 0',
            '9223372036854775807 - -1 > 0',
            '-(-9223372036854775808) > 0',
            '- -9223372036854775808 > 0',
            '9223372036854775807 * 2 > 0',
            '-9223372036854775808 * -1 > 0',
            '-1 * -9223372036854775808 > 0',
            '-9223372036854775808 * 2 > 0',
            '2 * -9223372036854775808 > 0',
            '3037000500 * 3037000500 > 0',
            '(-3037000500 * -3037000500) > 0',
            '(-3037000500 * 3037000500) < 0',
            'true + 1 == 2',
            '1 * false == 0',
            '-true == 1',
            'false && (9223372036854775807 + 1 > 0)',
            'true || (9223372036854775807 + 1 > 0)',
            'if true then true else (9223372036854775807 + 1 > 0)',
            '(if false then 10 else 3) * 4 == 12',
            'context.missing + 1 > 0',
            '1 + context.missing > 0',
            '1 + 2 < 4',
            '1 * 2 == 3',
            '0 - -9223372036854775808 == 0',
            'ip("192.168.1.42").isInRange(ip("192.168.1.99/24"))',
            'ip("192.168.1.42/25").isInRange(ip("192.168.1.0/24"))',
            'ip("192.168.1.0/24").isInRange(ip("192.168.1.0/25"))',
            'ip("192.168.1.128").isInRange(ip("192.168.1.0/25"))',
            'ip("203.0.113.2").isInRange(ip("0.0.0.0/0"))',
            'ip("2001:db8:abcd::1").isInRange(ip("2001:db8:abcd::/48"))',
            'ip("2001:db8:abcd::/48").isInRange(ip("2001:db8::/32"))',
            'ip("::1") == ip("0:0:0:0:0:0:0:1/128")',
            'ip("127.0.0.1") == ip("127.0.0.1/32")',
            'ip("127.0.0.1").isIpv4() && ip("::1").isIpv6()',
            'ip(if true then "10.0.0.1" else "bad").isIpv4()',
            '[ip("::1")].contains(ip("0:0:0:0:0:0:0:1"))',
            'ip("192.168.1.5/24") == ip("192.168.1.0/24")',
            'ip("::1").isInRange(ip("0.0.0.0/0"))',
            'ip(1).isIpv4()',
            '1.isIpv4()',
            'ip("::1").isInRange(1)',
            'true || ip("bad").isIpv4()',
            'ip("").isIpv4()',
            'ip("1.2.3").isIpv4()',
            'ip("1.2.3.256").isIpv4()',
            'ip("01.2.3.4").isIpv4()',
            'ip("1.2.3.4/033").isIpv4()',
            'ip("1.2.3.4/33").isIpv4()',
            'ip("1.2.3.4/").isIpv4()',
            'ip("1.2.3.4/8/16").isIpv4()',
            'ip(":::").isIpv4()',
            'ip("1::2::3").isIpv4()',
            'ip("::1/129").isIpv4()',
            'ip("::ffff:192.0.2.1").isIpv4()',
            'ip("1:2:3:4:5:6:7:8:9").isIpv4()',
            'ip("1:2:3:4:5:6:7").isIpv4()',
            'ip("12345::").isIpv4()',
            'ip("fe80::1%eth0").isIpv4()',
            'ip("127.1.2.3").isLoopback()',
            'ip("127.1.2.3/8").isLoopback()',
            'ip("127.1.2.3/7").isLoopback()',
            'ip("126.255.255.255").isLoopback()',
            'ip("128.0.0.0").isLoopback()',
            'ip("::1").isLoopback()',
            'ip("::1/128").isLoopback()',
            'ip("::1/127").isLoopback()',
            'ip("::2").isLoopback()',
            'ip("224.1.2.3/4").isMulticast()',
            'ip("224.1.2.3/3").isMulticast()',
            'ip("239.255.255.255").isMulticast()',
            'ip("223.255.255.255").isMulticast()',
            'ip("240.0.0.0").isMulticast()',
            'ip("ff00::1/8").isMulticast()',
            'ip("ff00::1/7").isMulticast()',
            'ip("feff::1").isMulticast()',
            'ip("ffff::1").isMulticast()',
            'ip("127.0.0.1").isMulticast()',
            '1.isLoopback()',
            '"224.0.0.1".isMulticast()',
            'ip("bad").isLoopback()',
            'true || ip("bad").isMulticast()',
        ):
            policy.write_text('permit(principal, action, resource) when { ' + expression + ' };', encoding="utf-8")
            ref = reference(args.cedar, policy, entities, request, temp)
            got = actual(args.engine, policy, entities, request, temp)
            count += 1
            if ref != got:
                mismatches.append({"case": expression, "reference": ref, "actual": got})
        # Compare range inclusion with both Cedar and Python's independent IP implementation.
        ip_pairs = (
            ("10.0.0.1", "0.0.0.0/0"), ("127.0.0.1", "0.0.0.0/1"),
            ("128.0.0.1", "0.0.0.0/1"), ("10.127.1.1", "10.0.0.0/9"),
            ("10.128.1.1", "10.0.0.0/9"), ("192.168.1.127", "192.168.1.0/25"),
            ("192.168.1.128", "192.168.1.0/25"), ("192.168.1.0/24", "192.168.1.0/25"),
            ("192.168.1.128/25", "192.168.1.42/24"), ("255.255.255.254", "255.255.255.255/31"),
            ("255.255.255.255", "255.255.255.254/32"), ("::1", "::/0"),
            ("8000::", "::/1"), ("2001:db8::1", "2001:db8::/32"),
            ("2001:db9::1", "2001:db8::/32"), ("2001:db8:0:0:7fff::", "2001:db8::/65"),
            ("2001:db8:0:0:8000::", "2001:db8::/65"),
            ("2001:db8::/64", "2001:db8::/65"), ("::1", "::/127"),
            ("::2", "::/127"), ("::1", "::1/128"),
            ("10.0.0.1", "::/0"), ("::1", "0.0.0.0/0"),
        )
        rng = random.Random(20261102)
        for family, width in ((4, 32), (6, 128)):
            address_type = ipaddress.IPv4Address if family == 4 else ipaddress.IPv6Address
            for _ in range(16):
                prefix = rng.randrange(1, width + 1)
                value = rng.getrandbits(width)
                network = ipaddress.ip_network(f"{address_type(value)}/{prefix}", strict=False)
                inside = address_type(value)
                outside = address_type(value ^ (1 << (width - prefix)))
                child_prefix = rng.randrange(prefix, width + 1)
                ip_pairs += (
                    (str(inside), str(network)), (str(outside), str(network)),
                    (f"{inside}/{child_prefix}", str(network)),
                    (f"{outside}/{child_prefix}", str(network)),
                )
        for left, right in ip_pairs:
            a, b = ipaddress.ip_network(left, strict=False), ipaddress.ip_network(right, strict=False)
            expected = a.version == b.version and a.subnet_of(b)
            expression = f'ip("{left}").isInRange(ip("{right}"))'
            policy.write_text('permit(principal, action, resource) when { ' + expression + ' };', encoding="utf-8")
            ref = reference(args.cedar, policy, entities, request, temp)
            got = actual(args.engine, policy, entities, request, temp)
            count += 1
            if ref != got or (got["decision"] == "Allow") != expected or got["errors"]:
                mismatches.append({"case": expression, "expected": expected, "reference": ref, "actual": got})
        # Boundary pairs cover both operand orders and sign combinations.
        for left, right in (
            (-9223372036854775808, -1), (-1, -9223372036854775808),
            (9223372036854775807, 1), (1, 9223372036854775807),
            (-9223372036854775808, 2), (2, -9223372036854775808),
            (-3037000500, -3037000500), (-3037000500, 3037000500),
            (3037000500, -3037000500), (3037000500, 3037000500),
        ):
            for op in ("+", "-", "*"):
                expression = f"({left} {op} {right}) == 0"
                policy.write_text('permit(principal, action, resource) when { ' + expression + ' };', encoding="utf-8")
                ref = reference(args.cedar, policy, entities, request, temp)
                got = actual(args.engine, policy, entities, request, temp)
                count += 1
                if ref != got:
                    mismatches.append({"case": expression, "reference": ref, "actual": got})
        policy.write_text('permit(principal, action, resource); forbid(principal, action, resource) when { 9223372036854775807 + 1 > 0 };', encoding="utf-8")
        ref = reference(args.cedar, policy, entities, request, temp)
        got = actual(args.engine, policy, entities, request, temp)
        count += 1
        if ref != got:
            mismatches.append({"case": "overflow in forbid", "reference": ref, "actual": got})
        for source in (
            '@owner("security") @shadow_mode permit(principal, action, resource);',
            '@id("grant") @owner("security") permit(principal, action, resource);',
            '@id("grant") permit(principal, action, resource); @id("guard") forbid(principal, action, resource) when { resource.missing };',
            '@id("grant") permit(principal, action, resource); @id("guard") forbid(principal, action, resource);',
            '@if @true @__cedar permit(principal, action, resource);',
            '@id("one") permit(principal, action, resource); permit(principal, action, resource);',
        ):
            policy.write_text(source, encoding="utf-8")
            ref = reference(args.cedar, policy, entities, request, temp)
            got = actual(args.engine, policy, entities, request, temp)
            count += 1
            if ref != got:
                mismatches.append({"case": source, "reference": ref, "actual": got})
        for scope in (
            'principal is User in User::"alice", action, resource is File',
            'principal is Group in User::"alice", action, resource',
            'principal is User in Group::"staff", action, resource',
            'principal is Example::User, action, resource',
            'principal, action, resource is File',
            'principal, action, resource is Document',
        ):
            policy.write_text('permit(' + scope + ');', encoding="utf-8")
            ref = reference(args.cedar, policy, entities, request, temp)
            got = actual(args.engine, policy, entities, request, temp)
            count += 1
            if ref != got:
                mismatches.append({"case": scope, "reference": ref, "actual": got})
        # Nested attribute checks cover records, entity references and absent entities.
        nested_entities = [
            {"uid": {"type": "User", "id": "manager"}, "attrs": {"access": {"level": 3}}, "parents": []},
            {"uid": {"type": "File", "id": "r"}, "attrs": {"owner": {"__entity": {"type": "User", "id": "manager"}}}, "parents": []},
        ]
        nested_request = {**request, "context": {
            "profile": {"team": {"name": "security", "active": False}, "flag": 1},
            "profile.team": "literal",
            "link": {"__entity": {"type": "User", "id": "manager"}},
            "missingLink": {"__entity": {"type": "User", "id": "unknown"}},
        }}
        entities.write_text(json.dumps(nested_entities), encoding="utf-8")
        for expression in (
            'context has profile.team.name', 'context has profile.team.active',
            'context has "profile.team"', 'context has link.access.level',
            'resource has owner.access.level', 'context.profile has team.name',
            'context has profile.team && context.profile.team.name == "security"',
            '(context has profile.team.name) == true', '!(context has profile.missing.name)',
            '!(context has missing.team.name)', '!(context has missingLink.name)',
            'context has missing.team', 'context has profile.missing.name',
            'context has profile.team.missing', 'context has missingLink.name',
            'resource has owner.access.missing', 'resource has absent.more',
            'context has profile.flag.name', 'context has profile.team.name.more',
            '1 has name', 'context.missing has team.name', 'resource.absent has team.name',
            'true || (context has profile.flag.name)',
            'context has missing.flag.name && context.missing.flag.name == 1',
            'context has profile.team && context.profile.team.active == false',
            'resource has owner.access.level && resource.owner.access.level == 3',
        ):
            policy.write_text('permit(principal, action, resource) when { ' + expression + ' };', encoding="utf-8")
            ref = reference(args.cedar, policy, entities, nested_request, temp)
            got = actual(args.engine, policy, entities, nested_request, temp)
            count += 1
            if ref != got:
                mismatches.append({"case": "nested has: " + expression, "reference": ref, "actual": got})
        # Entity tags use dynamic keys and remain separate from attributes and parents.
        tag_entity = {
            "uid": {"type": "File", "id": "r"},
            "attrs": {"classification": "attribute"},
            "parents": [{"type": "Folder", "id": "group"}],
            "tags": {
                "classification": "secret", "approved": False,
                "label": {"level": 3}, "ranges": [1, 2], "": "empty key",
                "ip": {"__extn": {"fn": "ip", "arg": "10.0.0.1"}},
            },
        }
        tag_parent = {"uid": {"type": "Folder", "id": "group"}, "attrs": {}, "parents": [], "tags": {"inherited": True}}
        tag_request = {**request, "context": {"key": "classification"}}
        for entity_set in ([], [tag_entity, tag_parent]):
            entities.write_text(json.dumps(entity_set), encoding="utf-8")
            for expression in (
                'resource.hasTag("classification")',
                'resource.getTag("classification") == "secret"',
                'resource.hasTag(context.key)', 'resource.getTag(context.key) == "secret"',
                'resource.hasTag("missing")', 'resource.getTag("missing") == "x"',
                'resource.hasTag(1)', 'resource.getTag(1) == 1',
                '{}.hasTag("x")', '{}.getTag("x") == 1',
                'resource.hasTag("classification") || resource.getTag("missing") == "x"',
                'resource.getTag("approved") == false',
                'resource.getTag("label").level == 3',
                'resource.getTag("ranges").contains(2)',
                'resource.getTag("") == "empty key"',
                'resource.getTag("ip").isInRange(ip("10.0.0.0/8"))',
                'resource.hasTag("inherited")',
                'resource.classification == "attribute" && resource.getTag("classification") == "secret"',
                'resource.hasTag("missing") && resource.getTag("missing") == true',
                'true || resource.getTag("missing") == true',
            ):
                policy.write_text('permit(principal, action, resource) when { ' + expression + ' };', encoding="utf-8")
                ref = reference(args.cedar, policy, entities, tag_request, temp)
                got = actual(args.engine, policy, entities, tag_request, temp)
                count += 1
                if ref != got:
                    mismatches.append({"case": "tags: " + expression, "reference": ref, "actual": got})
        policy.write_text('permit(principal, action, resource); forbid(principal, action, resource) when { resource.getTag("missing") == true };', encoding="utf-8")
        ref = reference(args.cedar, policy, entities, tag_request, temp)
        got = actual(args.engine, policy, entities, tag_request, temp)
        count += 1
        if ref != got:
            mismatches.append({"case": "tags: forbid error", "reference": ref, "actual": got})
        # Compare role hierarchies with both Cedar and a separate reachability walk.
        def entity(kind, name, parents):
            return {"uid": {"type": kind, "id": name}, "attrs": {}, "parents": [{"type": "Group", "id": parent} for parent in parents]}

        rng = random.Random(20261103)
        graph_sets = [
            ([entity("User", "alice", ["absent"])], "absent"),
            ([entity("User", "alice", ["a", "b", "a"]), entity("Group", "a", ["root"]), entity("Group", "b", ["root"]), entity("Group", "root", [])], "root"),
            ([entity("User", "alice", ["a"]), entity("Group", "a", [])], "other"),
            ([entity("User", "alice", ["a", "a"]), entity("Group", "a", ["absent"])], "absent"),
        ]
        for _ in range(24):
            nodes = [f"g{i}" for i in range(8)]
            initial = [name for name in nodes if rng.random() < 0.35]
            graph = [entity("User", "alice", initial)]
            for i, name in enumerate(nodes):
                parents = [other for other in nodes[i + 1:] if rng.random() < 0.35]
                if rng.random() < 0.25:
                    parents.append("external")
                graph.append(entity("Group", name, parents))
            graph_sets.append((graph, rng.choice(nodes + ["external", "other"])))
        for graph, target in graph_sets:
            links = {(item["uid"]["type"], item["uid"]["id"]): [(parent["type"], parent["id"]) for parent in item["parents"]] for item in graph}
            pending, visited = [("User", "alice")], set()
            while pending:
                node = pending.pop()
                if node in visited:
                    continue
                visited.add(node)
                pending.extend(links.get(node, ()))
            expected = ("Group", target) in visited
            policy.write_text('permit(principal in Group::"' + target + '", action, resource);', encoding="utf-8")
            entities.write_text(json.dumps(graph), encoding="utf-8")
            ref = reference(args.cedar, policy, entities, request, temp)
            got = actual(args.engine, policy, entities, request, temp)
            count += 1
            if ref != got or (got["decision"] == "Allow") != expected or got["errors"]:
                mismatches.append({"case": "hierarchy: " + target, "expected": expected, "reference": ref, "actual": got})
        invalid_graphs = (
            [entity("Group", "a", ["a"])],
            [entity("Group", "a", ["b"]), entity("Group", "b", ["a"])],
            [entity("Group", "a", ["b"]), entity("Group", "b", ["c"]), entity("Group", "c", ["a"])],
            [entity("User", "alice", []), entity("Group", "a", ["b"]), entity("Group", "b", ["a"])],
            [{**entity("Group", "a", []), "attrs": {"x": 1}}, {**entity("Group", "a", []), "attrs": {"x": 2}}],
        )
        graph_checks = 0
        policy.write_text('permit(principal, action, resource);', encoding="utf-8")
        ref_request = {k: uid(request[k]) for k in ("principal", "action", "resource")}
        ref_request["context"] = request["context"]
        ref_path, engine_path = temp / "graph-cedar-request.json", temp / "graph-request.json"
        ref_path.write_text(json.dumps(ref_request), encoding="utf-8")
        engine_path.write_text(json.dumps(request), encoding="utf-8")
        empty_cases = temp / "graph-empty-cases.json"
        empty_cases.write_text('[]', encoding="utf-8")
        for graph in invalid_graphs:
            entities.write_text(json.dumps(graph), encoding="utf-8")
            ref = run([args.cedar, "authorize", "--policies", policy, "--entities", entities, "--request-json", ref_path])
            got = run([args.engine, "authorize", policy, entities, engine_path, "--format", "json"])
            empty_batch = run([args.engine, "test", policy, entities, empty_cases, "--format", "json"])
            empty_authorize_batch = run([args.engine, "batch", policy, entities, empty_cases, "--format", "json"])
            graph_checks += 1
            if ref.returncode == 0 or got.returncode != 2 or got.stdout.strip() or empty_batch.returncode != 2 or empty_batch.stdout.strip() or empty_authorize_batch.returncode != 2 or empty_authorize_batch.stdout.strip():
                mismatches.append({"case": "invalid entity graph", "graph": graph, "reference_status": ref.returncode, "actual_status": got.returncode, "empty_batch_status": empty_batch.returncode, "empty_authorize_batch_status": empty_authorize_batch.returncode})
        # Compare accepted entity type names and invalid IDs at the JSON boundary.
        entity_type_checks = 0
        name_cases = [
            ("User", True), ("App::User", True), ("_", True), ("_App::_2", True),
            ("principal", True), ("when", True), ("__cedarX", True), ("App::when", True),
            ("", False), (" User", False), ("User ", False), ("1User", False),
            ("User-Name", False), ("User.Name", False), ("équipe", False),
            ("::User", False), ("User::", False), ("User::::Group", False), ("User::1Group", False),
            ("User:: if", False), ("User::Group\n", False), ("if", False), ("then", False),
            ("else", False), ("in", False), ("is", False), ("has", False), ("like", False),
            ("true", False), ("false", False), ("__cedar", False), ("App::if", False), ("App::__cedar", False),
        ]
        for kind, valid in name_cases:
            entities.write_text(json.dumps([{"uid": {"type": kind, "id": ""}, "attrs": {}, "parents": []}], ensure_ascii=False), encoding="utf-8")
            ref = run([args.cedar, "authorize", "--policies", policy, "--entities", entities, "--request-json", ref_path])
            got = run([args.engine, "authorize", policy, entities, engine_path, "--format", "json"])
            entity_type_checks += 1
            if (ref.returncode == 0) != valid or (got.returncode == 0) != valid or (not valid and (got.returncode != 2 or got.stdout.strip())):
                mismatches.append({"case": "entity type", "type": kind, "reference_status": ref.returncode, "actual_status": got.returncode})
        bad_uid = {"type": "invalid type", "id": "x"}
        good_uid = {"type": "User", "id": "a"}
        for graph in [
            [{"uid": bad_uid, "attrs": {}, "parents": []}],
            [{"uid": good_uid, "attrs": {}, "parents": [bad_uid]}],
            [{"uid": good_uid, "attrs": {"owner": {"__entity": bad_uid}}, "parents": []}],
            [{"uid": good_uid, "attrs": {}, "parents": [], "tags": {"owner": {"__entity": bad_uid}}}],
        ]:
            entities.write_text(json.dumps(graph), encoding="utf-8")
            ref = run([args.cedar, "authorize", "--policies", policy, "--entities", entities, "--request-json", ref_path])
            got = run([args.engine, "authorize", policy, entities, engine_path, "--format", "json"])
            entity_type_checks += 1
            if ref.returncode == 0 or got.returncode != 2 or got.stdout.strip():
                mismatches.append({"case": "invalid nested entity type", "graph": graph, "reference_status": ref.returncode, "actual_status": got.returncode})
        entities.write_text("[]", encoding="utf-8")
        for field in ("principal", "action", "resource"):
            bad_request = {**request, field: bad_uid}
            bad_ref_request = {k: uid(bad_request[k]) for k in ("principal", "action", "resource")}
            bad_ref_request["context"] = bad_request["context"]
            ref_path.write_text(json.dumps(bad_ref_request), encoding="utf-8")
            engine_path.write_text(json.dumps(bad_request), encoding="utf-8")
            ref = run([args.cedar, "authorize", "--policies", policy, "--entities", entities, "--request-json", ref_path])
            got = run([args.engine, "authorize", policy, entities, engine_path, "--format", "json"])
            entity_type_checks += 1
            if ref.returncode == 0 or got.returncode != 2 or got.stdout.strip():
                mismatches.append({"case": "invalid request entity type: " + field, "reference_status": ref.returncode, "actual_status": got.returncode})
        # Template bindings are entity IDs and follow the same naming rule.
        sharing = ROOT / "examples" / "template-sharing"
        bad_links = json.loads((sharing / "links.json").read_text(encoding="utf-8"))
        bad_links[0]["principal"]["type"] = "invalid type"
        bad_links_path = temp / "invalid-entity-link.json"
        bad_links_path.write_text(json.dumps(bad_links), encoding="utf-8")
        ref_links_path = temp / "invalid-entity-link-reference.json"
        ref_links_path.write_text(json.dumps([{"template_id": "share", "link_id": link["id"], "args": {"?" + slot: uid(link[slot]) for slot in ("principal", "resource")}} for link in bad_links]), encoding="utf-8")
        ref_policy_path = temp / "invalid-entity-link-policy.cedar"
        ref_policy_path.write_text((sharing / "policy.cedar").read_text(encoding="utf-8") + "\n" + (sharing / "template.cedar").read_text(encoding="utf-8"), encoding="utf-8")
        ref_path.write_text(json.dumps(ref_request), encoding="utf-8")
        engine_path.write_text(json.dumps(request), encoding="utf-8")
        ref = run([args.cedar, "authorize", "--policies", ref_policy_path, "--entities", sharing / "entities.json", "--request-json", ref_path, "--template-linked", ref_links_path])
        got = run([args.engine, "authorize", sharing / "policy.cedar", sharing / "entities.json", engine_path, "--template", sharing / "template.cedar", "--links", bad_links_path, "--format", "json"])
        entity_type_checks += 1
        if ref.returncode == 0 or got.returncode != 2 or got.stdout.strip():
            mismatches.append({"case": "invalid template slot entity type", "reference_status": ref.returncode, "actual_status": got.returncode})
        # Trailing commas in supported literals, calls, and policy scopes.
        entities.write_text("[]", encoding="utf-8")
        for expression in (
            '[1, 2,] == [2, 1]',
            '{name: "alice", nested: {active: true,},}.nested.active',
            'ip("127.0.0.1",).isIpv4()',
            'ip("10.0.0.1",).isInRange(ip("10.0.0.0/8",),)',
            'decimal("1.0",).lessThan(decimal("2.0",),)',
            'duration("1s",).toSeconds() == 1',
            'datetime("2026-11-01",).offset(duration("1s",),) > datetime("2026-11-01",)',
            '[1, 2,].containsAll([2,],)',
        ):
            policy.write_text('permit(principal, action in [Action::"read",], resource,) when { ' + expression + ' };', encoding="utf-8")
            ref = reference(args.cedar, policy, entities, request, temp)
            got = actual(args.engine, policy, entities, request, temp)
            count += 1
            expected = {"decision": "Allow", "reasons": ["policy0"], "errors": []}
            if ref != expected or got != expected:
                mismatches.append({"case": "trailing comma: " + expression, "reference": ref, "actual": got})
        # Reserved words are not bare attributes or entity type path segments.
        syntax_checks = 0
        reserved = ("if", "then", "else", "in", "is", "has", "like", "true", "false", "__cedar")
        for name in reserved:
            expressions = (
                f'{name}::"id" == Namespace::"id"',
                f'Namespace::{name}::"id" == Namespace::"id"',
                f'{{{name}: 1}}["value"] == 1',
                f'context.{name} == 1',
                f'context has {name}',
            )
            for expression in expressions:
                policy.write_text('permit(principal, action, resource) when { ' + expression + ' };', encoding="utf-8")
                ref = run([args.cedar, "check-parse", "--policies", policy])
                got = run([args.engine, "check", policy])
                syntax_checks += 1
                if ref.returncode == 0 or got.returncode != 2:
                    mismatches.append({"case": "reserved identifier: " + expression, "reference_status": ref.returncode, "actual_status": got.returncode})
        # Quoting allows reserved record names; contextual names are legal types.
        entities.write_text("[]", encoding="utf-8")
        for name in reserved:
            expression = f'{{"{name}": 1}}["{name}"] == 1'
            policy.write_text('permit(principal, action, resource) when { ' + expression + ' };', encoding="utf-8")
            ref = reference(args.cedar, policy, entities, request, temp)
            got = actual(args.engine, policy, entities, request, temp)
            count += 1
            expected = {"decision": "Allow", "reasons": ["policy0"], "errors": []}
            if ref != expected or got != expected:
                mismatches.append({"case": "quoted identifier: " + name, "reference": ref, "actual": got})
        for name in ("principal", "action", "resource", "context", "permit", "forbid", "when", "unless", "ip"):
            expression = f'{{{name}: 1}}.{name} == 1 && {name}::User::"id" == {name}::User::"id"'
            policy.write_text('permit(principal, action, resource) when { ' + expression + ' };', encoding="utf-8")
            ref = reference(args.cedar, policy, entities, request, temp)
            got = actual(args.engine, policy, entities, request, temp)
            count += 1
            expected = {"decision": "Allow", "reasons": ["policy0"], "errors": []}
            if ref != expected or got != expected:
                mismatches.append({"case": "contextual identifier: " + name, "reference": ref, "actual": got})
        for name in ("principal", "action", "resource", "context"):
            contextual = {**request, "principal": {"type": name, "id": "alice"}, "context": {"principal": "read"}}
            policy.write_text(f'permit(principal == {name}::"alice", action, resource) when {{ principal == {name}::"alice" && context.principal == "read" }};', encoding="utf-8")
            ref = reference(args.cedar, policy, entities, contextual, temp)
            got = actual(args.engine, policy, entities, contextual, temp)
            count += 1
            expected = {"decision": "Allow", "reasons": ["policy0"], "errors": []}
            if ref != expected or got != expected:
                mismatches.append({"case": "contextual scope: " + name, "reference": ref, "actual": got})
        for expression in (
            r'"\u0041" == "A"', r'"\b" == "x"', r'"\/" == "/"',
            r'"\x80" == "x"', r'"\*" == "*"', r'"\u{_41}" == "A"',
            r'"\u{d800}" == "x"', r'"\u{110000}" == "x"',
            r'"x" like "\q"', 'context.name like context.pattern',
            '1 / 2 == 0', '0 - 9223372036854775808 == 0',
            '-(9223372036854775808) == 0', '-----1 == 0', '!-1 == 0', '-!true == 0',
            'context has "profile".team', 'context has profile."team"',
            'context has profile["team"]', 'context has profile.team()',
            'context has profile.true', 'context has profile.if', 'context has true',
            'context has __cedar', 'context has profile.', 'context has profile..name',
            'context has profile.1', 'context has profile.team == true',
            '[,] == []', '{,} == {}', '[1,,] == [1]', '{a: 1,,}.a == 1',
            'ip(,).isIpv4()', '[1].contains(1, 2,)', '[].isEmpty(,)',
            'context["x",] == 1', '(1,) == 1',
        ):
            policy.write_text('permit(principal, action, resource) when { ' + expression + ' };', encoding="utf-8")
            ref = run([args.cedar, "check-parse", "--policies", policy])
            got = run([args.engine, "check", policy])
            syntax_checks += 1
            if ref.returncode == 0 or got.returncode != 2:
                mismatches.append({"case": expression, "reference_status": ref.returncode, "actual_status": got.returncode})
        for source in (
            '@owner("a") @owner("b") permit(principal, action, resource);',
            '@id("same") permit(principal, action, resource); @id("same") forbid(principal, action, resource);',
            '@id("policy1") permit(principal, action, resource); permit(principal, action, resource);',
            '@name() permit(principal, action, resource);',
            '@name(1) permit(principal, action, resource);',
            '@name("value", "other") permit(principal, action, resource);',
            '@name("value")', '@123 permit(principal, action, resource);',
            '@owner("team",) permit(principal, action, resource);',
            'permit(principal, action, resource,,);',
        ):
            policy.write_text(source, encoding="utf-8")
            ref = run([args.cedar, "check-parse", "--policies", policy])
            got = run([args.engine, "check", policy])
            syntax_checks += 1
            if ref.returncode == 0 or got.returncode != 2:
                mismatches.append({"case": source, "reference_status": ref.returncode, "actual_status": got.returncode})
        # Compare batch graph queries with Cedar's policy-level entity membership.
        entities = ROOT / "examples" / "sharing" / "entities.json"
        query_file = temp / "membership.json"
        alice = {"type": "User", "id": "alice"}
        bob = {"type": "User", "id": "bob"}
        editors = {"type": "Group", "id": "editors"}
        roadmap = {"type": "Document", "id": "roadmap"}
        projects = {"type": "Folder", "id": "projects"}
        team = {"type": "Folder", "id": "team"}
        pairs = [(alice, editors), (bob, editors), (roadmap, projects),
                 (roadmap, team), (team, team), (team, roadmap), (alice, editors)]
        query_file.write_text(json.dumps([{"child": child, "ancestor": ancestor}
                                         for child, ancestor in pairs]), encoding="utf-8")
        batch = run([args.engine, "check-membership", entities, query_file, "--format", "json"])
        if batch.returncode != 0:
            raise RuntimeError("membership batch failed: " + batch.stderr)
        results = json.loads(batch.stdout)
        if len(results) != len(pairs):
            raise RuntimeError("membership batch returned an unexpected number of results")
        for index, (child, ancestor) in enumerate(pairs):
            policy.write_text('permit(principal in ' + uid(ancestor) + ', action, resource);', encoding="utf-8")
            member_request = {"principal": child, "action": {"type": "Action", "id": "read"},
                              "resource": {"type": "Document", "id": "roadmap"}, "context": {}}
            ref = reference(args.cedar, policy, entities, member_request, temp)
            count += 1
            if ref["errors"] or results[index] != (ref["decision"] == "Allow"):
                mismatches.append({"case": "membership batch: " + str(index), "reference": ref, "actual": results[index]})
        policy.write_text(
            '@id("report") permit(principal, action == Action::"read", resource == Document::"roadmap");'
            '@id("guard") forbid(principal, action, resource == Document::"roadmap") when { context.missing };'
            '@id("team") permit(principal in Group::"editors", action, resource == Document::"other");'
            '@id("other") forbid(principal, action == Action::"write", resource == Document::"other");',
            encoding="utf-8")
        for subject in (alice, bob):
            for action in ("read", "write"):
                for resource in ("roadmap", "other", "absent"):
                    case = {"principal": subject, "action": {"type": "Action", "id": action},
                            "resource": {"type": "Document", "id": resource}, "context": {}}
                    ref = reference(args.cedar, policy, entities, case, temp)
                    got = actual(args.engine, policy, entities, case, temp)
                    count += 1
                    if ref != got:
                        mismatches.append({"case": "resource index", "request": case, "reference": ref, "actual": got})
        # Compare each trace outcome with an independently evaluated Cedar policy.
        trace_parts = (
            ("active", '@id("active") permit(principal, action == Action::"read", resource) when { context.active };'),
            ("blocked", '@id("blocked") forbid(principal == User::"alice", action, resource) when { context.blocked };'),
            ("team", '@id("team") permit(principal in Group::"editors", action, resource == Document::"roadmap");'),
            ("missing", '@id("missing") permit(principal == User::"bob", action, resource) when { context.missing };'),
        )
        trace_policy, single_policy, trace_request = (temp / name for name in ("trace.cedar", "single.cedar", "trace-request.json"))
        trace_policy.write_text('\n'.join(source for _, source in trace_parts), encoding="utf-8")
        for subject, context in ((alice, {"active": True, "blocked": True}),
                                 (alice, {}), (bob, {"active": True, "blocked": False}),
                                 ({"type": "User", "id": "other"}, {"active": False})):
            case = {"principal": subject, "action": {"type": "Action", "id": "read"},
                    "resource": {"type": "Document", "id": "roadmap"}, "context": context}
            trace_request.write_text(json.dumps(case), encoding="utf-8")
            output = run([args.engine, "explain", trace_policy, entities, trace_request, "--format", "json"])
            if output.returncode != 0:
                raise RuntimeError("trace failed: " + output.stderr)
            trace = json.loads(output.stdout)
            reference_response = reference(args.cedar, trace_policy, entities, case, temp)
            actual_response = {"decision": trace["response"]["decision"],
                               "reasons": sorted(trace["response"]["reasons"]),
                               "errors": sorted(item["policy_id"] for item in trace["response"]["errors"])}
            count += 1
            if reference_response != actual_response or len(trace["policies"]) != len(trace_parts):
                mismatches.append({"case": "trace response", "reference": reference_response, "actual": actual_response})
            for item, (policy_id, source) in zip(trace["policies"], trace_parts):
                single_policy.write_text(source, encoding="utf-8")
                single = reference(args.cedar, single_policy, entities, case, temp)
                expected_outcome = "error" if single["errors"] else "matched" if policy_id in single["reasons"] else "not_matched"
                count += 1
                if item["policy_id"] != policy_id or item["outcome"] != expected_outcome:
                    mismatches.append({"case": "trace policy " + policy_id, "expected": expected_outcome, "actual": item})
    print(json.dumps({"cedar": version.stdout.strip(), "official_fixture_commit": "f64ff16c8a5c2473e0db9391997d10ceae9bb2f2", "comparisons": count, "invalid_syntax_checks": syntax_checks, "invalid_graph_checks": graph_checks, "entity_type_checks": entity_type_checks, "mismatches": mismatches}, indent=2))
    return 1 if mismatches else 0


if __name__ == "__main__":
    raise SystemExit(main())
