#!/usr/bin/env python3
"""Compare the native engine with Cedar CLI 4.13.0 and pinned integration cases."""
import argparse
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
    reasons = re.findall(r"(?m)^  ([^\r\n]+)$", output)
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
        for name in ("tenant", "sharing", "admin", "risk", "classified", "invoices", "quota", "network", "tags", "diagnostics", "device", "approvals"):
            base = ROOT / "examples" / name
            cases = json.loads((base / "requests.json").read_text(encoding="utf-8"))
            for i, item in enumerate(cases):
                ref = reference(args.cedar, base / "policy.cedar", base / "entities.json", item["request"], temp)
                got = actual(args.engine, base / "policy.cedar", base / "entities.json", item["request"], temp)
                count += 1
                expected = {"decision": item["decision"], "reasons": sorted(item.get("reasons", got["reasons"])), "errors": sorted(item.get("errors", []))}
                if ref != got or got != expected:
                    mismatches.append({"case": name + ":" + str(i), "expected": expected, "reference": ref, "actual": got})
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
        syntax_checks = 0
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
        ):
            policy.write_text(source, encoding="utf-8")
            ref = run([args.cedar, "check-parse", "--policies", policy])
            got = run([args.engine, "check", policy])
            syntax_checks += 1
            if ref.returncode == 0 or got.returncode != 2:
                mismatches.append({"case": source, "reference_status": ref.returncode, "actual_status": got.returncode})
    print(json.dumps({"cedar": version.stdout.strip(), "official_fixture_commit": "f64ff16c8a5c2473e0db9391997d10ceae9bb2f2", "comparisons": count, "invalid_syntax_checks": syntax_checks, "invalid_graph_checks": graph_checks, "mismatches": mismatches}, indent=2))
    return 1 if mismatches else 0


if __name__ == "__main__":
    raise SystemExit(main())
