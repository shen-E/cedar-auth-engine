#!/usr/bin/env python3
"""Compare the native engine with Cedar CLI 4.13.0 and pinned integration cases."""
import argparse
import json
import pathlib
import re
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
CORPUS = ROOT / "fixtures" / "cedar"


def run(args):
    return subprocess.run([str(x) for x in args], text=True, encoding="utf-8", capture_output=True, timeout=30)


def uid(value):
    return value["type"] + "::" + json.dumps(value["id"], ensure_ascii=False)


def reference(exe, policy, entities, request, temp):
    transformed = {k: uid(request[k]) for k in ("principal", "action", "resource")}
    transformed["context"] = request["context"]
    path = temp / "cedar-request.json"
    path.write_text(json.dumps(transformed, ensure_ascii=False), encoding="utf-8")
    result = run([exe, "authorize", "--policies", policy, "--entities", entities,
                  "--request-json", path, "--verbose", "--error-format", "plain"])
    output = result.stdout + "\n" + result.stderr
    decision = re.search(r"(?m)^\s*(ALLOW|DENY)\s*$", output)
    if not decision:
        raise RuntimeError("Cedar failed: " + output)
    reasons = re.findall(r"(?m)^\s+(policy\d+)\s*$", output)
    errors = re.findall(r"error while evaluating policy `([^`]+)`", output)
    return {"decision": decision.group(1).title(), "reasons": sorted(reasons), "errors": sorted(errors)}


def actual(exe, policy, entities, request, temp):
    path = temp / "request.json"
    path.write_text(json.dumps(request, ensure_ascii=False), encoding="utf-8")
    result = run([exe, "authorize", policy, entities, path, "--format", "json"])
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
        for name in ("tenant", "sharing", "admin", "risk", "classified", "invoices"):
            base = ROOT / "examples" / name
            cases = json.loads((base / "requests.json").read_text(encoding="utf-8"))
            for i, item in enumerate(cases):
                ref = reference(args.cedar, base / "policy.cedar", base / "entities.json", item["request"], temp)
                got = actual(args.engine, base / "policy.cedar", base / "entities.json", item["request"], temp)
                count += 1
                if ref != got or got["decision"] != item["decision"]:
                    mismatches.append({"case": name + ":" + str(i), "reference": ref, "actual": got})
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
        ):
            policy.write_text('permit(principal, action, resource) when { ' + expression + ' };', encoding="utf-8")
            ref = reference(args.cedar, policy, entities, request, temp)
            got = actual(args.engine, policy, entities, request, temp)
            count += 1
            if ref != got:
                mismatches.append({"case": expression, "reference": ref, "actual": got})
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
        syntax_checks = 0
        for expression in (
            r'"\u0041" == "A"', r'"\b" == "x"', r'"\/" == "/"',
            r'"\x80" == "x"', r'"\*" == "*"', r'"\u{_41}" == "A"',
            r'"\u{d800}" == "x"', r'"\u{110000}" == "x"',
            r'"x" like "\q"', 'context.name like context.pattern',
        ):
            policy.write_text('permit(principal, action, resource) when { ' + expression + ' };', encoding="utf-8")
            ref = run([args.cedar, "check-parse", "--policies", policy])
            got = run([args.engine, "check", policy])
            syntax_checks += 1
            if ref.returncode == 0 or got.returncode != 2:
                mismatches.append({"case": expression, "reference_status": ref.returncode, "actual_status": got.returncode})
    print(json.dumps({"cedar": version.stdout.strip(), "official_fixture_commit": "f64ff16c8a5c2473e0db9391997d10ceae9bb2f2", "comparisons": count, "invalid_syntax_checks": syntax_checks, "mismatches": mismatches}, indent=2))
    return 1 if mismatches else 0


if __name__ == "__main__":
    raise SystemExit(main())
