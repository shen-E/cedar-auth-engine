#!/usr/bin/env python3
"""Compare every handwritten test in a pinned Cedar integration snapshot."""
import argparse
import collections
import json
import pathlib
import re
import subprocess
import tempfile

from verify import uid

FIXTURE_REVISION = "f64ff16c8a5c2473e0db9391997d10ceae9bb2f2"
REFERENCE_VERSION = "cedar-policy-cli 4.13.0"


def run(args):
    return subprocess.run([str(arg) for arg in args], capture_output=True,
                          text=True, encoding="utf-8", errors="replace", timeout=30)


def fixtures(root):
    for path in sorted((root / "tests").rglob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and "requests" in data and "policies" in data:
            yield path.relative_to(root).as_posix(), data


def fixture_path(root, value):
    path = (root / value).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError:
        raise ValueError("invalid fixture input path") from None
    if not path.is_file():
        raise ValueError("invalid fixture input path")
    return path


def decision(result):
    output = result.stdout + "\n" + result.stderr
    match = re.search(r"(?m)^\s*(ALLOW|DENY)\s*$", output)
    if not match:
        return None
    return {"decision": match.group(1).title(),
            "reasons": sorted(re.findall(r"(?m)^  ([^\r\n]+)$", output)),
            "errors": sorted(re.findall(r"error while evaluating policy `([^`]+)`", output))}


def compare(root, engine, cedar):
    cases = []
    counts = collections.Counter()
    with tempfile.TemporaryDirectory(prefix="cedar-integration-") as temp:
        request_path = pathlib.Path(temp) / "request.json"
        for name, data in fixtures(root):
            policy = fixture_path(root, data["policies"])
            entities = fixture_path(root, data["entities"])
            schema = fixture_path(root, data["schema"])
            policy_format = data.get("policyFormat", "cedar")
            schema_format = data.get("schemaFormat", "cedar")
            validated = run([cedar, "validate", "--policies", policy,
                             "--policy-format", policy_format, "--schema", schema,
                             "--schema-format", schema_format, "--error-format", "plain"])
            schema_reference = ("valid" if validated.returncode == 0 else
                                "invalid" if validated.returncode == 1 else "error")
            schema_fixture = "valid" if data["shouldValidate"] else "invalid"
            counts["schema_total"] += 1
            counts["schema_unsupported"] += 1
            if schema_reference != schema_fixture:
                counts["schema_reference_disagreements"] += 1
            case = {"fixture": name, "policy_format": policy_format,
                    "schema_format": schema_format,
                    "schema": {"fixture": schema_fixture, "reference": schema_reference,
                               "engine": "unsupported"}, "requests": []}
            for index, item in enumerate(data["requests"]):
                counts["requests_total"] += 1
                actual = None
                expected = {"decision": item["decision"].title(),
                            "reasons": sorted(item.get("reason", [])),
                            "errors": sorted(item.get("errors", []))}
                request = {key: item[key] for key in ("principal", "action", "resource", "context")}
                ref_request = {key: uid(request[key]) for key in ("principal", "action", "resource")}
                ref_request["context"] = request["context"]
                request_path.write_text(json.dumps(ref_request, ensure_ascii=False), encoding="utf-8")
                reference = decision(run([cedar, "authorize", "--policies", policy,
                                          "--policy-format", policy_format, "--entities", entities,
                                          "--schema", schema, "--schema-format", schema_format,
                                          "--request-validation", str(item.get("validateRequest", False)).lower(),
                                          "--request-json", request_path, "--verbose", "--error-format", "plain"]))
                fixture_match = reference == expected if reference is not None else None
                if fixture_match is False:
                    counts["requests_reference_differs_from_fixture"] += 1
                if reference is None:
                    status = "reference_error"
                elif policy_format != "cedar":
                    status = "unsupported_policy_format"
                elif item.get("validateRequest", False):
                    status = "unsupported_request_validation"
                else:
                    request_path.write_text(json.dumps(request, ensure_ascii=False), encoding="utf-8")
                    result = run([engine, "authorize", policy, entities, request_path, "--format", "json"])
                    if result.returncode != 0:
                        status = "engine_input_error"
                    else:
                        output = json.loads(result.stdout)
                        actual = {"decision": output["decision"],
                                  "reasons": sorted(output["reasons"]),
                                  "errors": sorted(error["policy_id"] for error in output["errors"])}
                        status = "pass" if actual == reference else "mismatch"
                counts["requests_" + status] += 1
                detail = {"index": index, "status": status,
                          "reference_matches_fixture": fixture_match}
                if status == "mismatch" or fixture_match is False:
                    detail.update({"fixture": expected, "reference": reference,
                                   "engine": actual})
                case["requests"].append(detail)
            cases.append(case)
    return {"reference": REFERENCE_VERSION, "fixture_revision": FIXTURE_REVISION,
            "fixture_version_note": "Historical fixture snapshot; evaluated again with Cedar 4.13.0.",
            "cases_total": len(cases), "counts": dict(sorted(counts.items())), "cases": cases}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", required=True, type=pathlib.Path)
    parser.add_argument("--cedar", required=True, type=pathlib.Path)
    parser.add_argument("--engine", required=True, type=pathlib.Path)
    parser.add_argument("--require-complete", action="store_true")
    args = parser.parse_args()
    revision = run(["git", "-C", args.fixtures, "rev-parse", "HEAD"])
    if revision.returncode != 0 or revision.stdout.strip() != FIXTURE_REVISION:
        parser.error("fixtures must be checked out at the pinned revision")
    version = run([args.cedar, "--version"])
    if version.returncode != 0 or version.stdout.strip() != REFERENCE_VERSION:
        parser.error("expected cedar-policy-cli 4.13.0")
    report = compare(args.fixtures, args.engine, args.cedar)
    print(json.dumps(report, indent=2, ensure_ascii=False))
    counts = report["counts"]
    if report["cases_total"] == 0 or counts.get("requests_total", 0) == 0:
        return 1
    complete = (report["cases_total"] > 0 and counts.get("requests_total", 0) > 0 and
                counts.get("requests_pass", 0) == counts.get("requests_total", 0) and
                counts.get("schema_unsupported", 0) == 0 and
                counts.get("schema_reference_disagreements", 0) == 0 and
                counts.get("requests_reference_differs_from_fixture", 0) == 0)
    return 1 if args.require_complete and not complete else 0


if __name__ == "__main__":
    raise SystemExit(main())
