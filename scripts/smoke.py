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
    for name in ("tenant", "sharing", "admin", "risk", "classified", "invoices"):
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
        policy.write_text("permit(principal, action, resource) when { context.x + 1 > 1 };", encoding="utf-8")
        assert run("check", policy).returncode == 2
        checks += 1
        policy.write_text("permit(principal, action, resource);", encoding="utf-8")
        entities = path / "duplicate.json"
        entities.write_text('[{"uid":{"type":"User","type":"Other","id":"a"},"attrs":{},"parents":[]}]', encoding="utf-8")
        request = path / "request.json"
        request.write_text('{}', encoding="utf-8")
        result = run("authorize", policy, entities, request, "--format", "json")
        assert result.returncode == 2 and "duplicate JSON key" in result.stderr
        checks += 1
        failed = path / "failed.json"
        request_obj = {"principal":{"type":"User","id":"a"},"action":{"type":"Action","id":"read"},"resource":{"type":"File","id":"r"},"context":{}}
        failed.write_text(json.dumps([{"request": request_obj, "decision": "Deny"}]), encoding="utf-8")
        empty = path / "empty.json"
        empty.write_text('[]', encoding="utf-8")
        assert run("test", policy, empty, failed).returncode == 1
        checks += 1
    print("CLI checks passed:", checks)


if __name__ == "__main__":
    main()
