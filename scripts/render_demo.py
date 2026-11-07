#!/usr/bin/env python3
"""Render the Chinese demo from verified CLI results and a local Windows voice."""
import argparse
import json
import os
import pathlib
import re
import subprocess
import tempfile
import wave

from PIL import Image, ImageDraw, ImageFont

ROOT = pathlib.Path(__file__).resolve().parents[1]
WIDTH, HEIGHT = 1920, 1080
FONT_DIR = pathlib.Path(os.environ.get("WINDIR", r"C:\Windows")) / "Fonts"
NAVY, INK, MUTED = "#102b37", "#163943", "#637f85"
TEAL, ORANGE, GREEN, RED = "#007d70", "#d06c36", "#26a782", "#e47959"


def command(args):
    result = subprocess.run([str(item) for item in args], cwd=ROOT, capture_output=True,
                            text=True, encoding="utf-8", timeout=180)
    if result.returncode:
        raise RuntimeError(f"command failed: {args}\n{result.stderr}\n{result.stdout}")
    return result.stdout


def font(name, size):
    return ImageFont.truetype(str(FONT_DIR / name), size)


def wrap(draw, text, face, width):
    result, line = [], ""
    for char in text:
        if line and draw.textlength(line + char, font=face) > width:
            result.append(line)
            line = char
        else:
            line += char
    if line:
        result.append(line)
    return result


def render(path, index, count, scene, subtitle):
    img = Image.new("RGB", (WIDTH, HEIGHT), "#f4f7f6")
    d = ImageDraw.Draw(img)
    bold, regular, mono = "msyhbd.ttc", "msyh.ttc", "consola.ttf"
    eyebrow, title, body = font(bold, 24), font(bold, 52), font(regular, 30)
    code, caption = font(mono, 31), font(regular, 38)
    d.rectangle((0, 0, WIDTH, 16), fill=TEAL)
    d.text((94, 53), "CEDAR AUTH ENGINE", font=eyebrow, fill=TEAL)
    d.text((94, 101), scene["title"], font=title, fill=INK)
    d.text((1740, 65), f"{index:02d} / {count:02d}", font=eyebrow, fill=MUTED)
    d.line((94, 194, 1826, 194), fill="#d6e3e0", width=2)
    kind = scene["kind"]
    if kind == "intro":
        d.rounded_rectangle((94, 240, 1826, 812), radius=22, fill=NAVY)
        d.rectangle((94, 240, 108, 812), fill=TEAL)
        d.text((155, 311), "同一份文档，谁可以访问？", font=font(bold, 62), fill="white")
        d.text((157, 411), "用策略描述规则，用授权结果解释决定。", font=font(regular, 35), fill="#b7d2d1")
        for x, label, color in [(155, "同租户", GREEN), (510, "跨租户", ORANGE), (865, "停用账户", RED)]:
            d.rounded_rectangle((x, 570, x + 305, 658), radius=12, fill="#1c4550")
            d.ellipse((x + 26, 603, x + 45, 622), fill=color)
            d.text((x + 67, 588), label, font=font(bold, 31), fill="white")
    elif kind == "policy":
        d.rounded_rectangle((94, 240, 1826, 812), radius=20, fill=NAVY)
        d.text((139, 271), "examples/tenant/policy.cedar", font=font(mono, 26), fill="#91bbb8")
        d.line((139, 322, 1780, 322), fill="#39535a", width=2)
        for i, line in enumerate(scene["lines"]):
            color = "#6ed6b6" if line.startswith("permit") else "#f6a877" if line.startswith("forbid") else "#e6f3f0"
            d.text((140, 364 + i * 65), line, font=font(mono, 35), fill=color)
        d.text((140, 710), "同租户且已认证：允许    ·    用户已停用：禁止", font=font(regular, 30), fill="#b7d2d1")
    elif kind == "case":
        d.rounded_rectangle((94, 240, 644, 812), radius=20, fill="white", outline="#d4e4df", width=2)
        d.text((135, 278), scene["person"], font=font(bold, 48), fill=INK)
        d.text((135, 350), "请求读取 report 文档", font=body, fill=MUTED)
        y = 434
        for label, value in scene["facts"]:
            d.text((135, y), label, font=body, fill=MUTED)
            d.text((135, y + 42), value, font=font(bold, 32), fill=INK)
            y += 105
        d.rounded_rectangle((675, 240, 1826, 812), radius=20, fill=NAVY)
        d.text((720, 276), "实际授权结果  /  JSON", font=font(bold, 27), fill="#a1c8c4")
        d.line((720, 329, 1780, 329), fill="#39535a", width=2)
        for i, line in enumerate(scene["lines"]):
            color = "#71ddb8" if '"Allow"' in line else "#ff9e7f" if '"Deny"' in line else "#e6f3f0"
            d.text((725, 361 + i * 51), line, font=code, fill=color)
    elif kind == "terminal":
        d.rounded_rectangle((94, 240, 1826, 812), radius=20, fill=NAVY)
        d.text((140, 277), scene["label"], font=font(bold, 27), fill="#a1c8c4")
        d.line((140, 329, 1780, 329), fill="#39535a", width=2)
        for i, line in enumerate(scene["lines"]):
            d.text((140, 365 + i * 51), line, font=code, fill="#6ed6b6" if line.startswith("$") else "#e6f3f0")
    elif kind == "end":
        d.rounded_rectangle((94, 240, 1826, 812), radius=20, fill="#e1f1eb")
        d.text((150, 314), "把授权判断接入自己的应用", font=font(bold, 55), fill=INK)
        for x, title_text, text in [(150, "MoonBit 库", "在应用中调用"), (705, "原生命令行", "检查、授权与测试"), (1260, "授权结果", "决定、策略与错误")]:
            d.rounded_rectangle((x, 460, x + 495, 655), radius=16, fill="white")
            d.rectangle((x, 460, x + 495, 468), fill=TEAL)
            d.text((x + 28, 504), title_text, font=font(bold, 36), fill=INK)
            d.text((x + 28, 565), text, font=body, fill=MUTED)
    d.rectangle((0, 851, WIDTH, HEIGHT), fill="#122d37")
    lines = wrap(d, subtitle, caption, 1600)
    if len(lines) > 2:
        raise RuntimeError("subtitle exceeds two lines")
    y = 893 if len(lines) == 2 else 923
    for line in lines:
        length = d.textlength(line, font=caption)
        d.text(((WIDTH - length) / 2, y), line, font=caption, fill="white")
        y += 57
    img.save(path)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--engine", required=True, type=pathlib.Path)
    parser.add_argument("--ffmpeg", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--preview-dir", type=pathlib.Path)
    args = parser.parse_args()
    engine, ffmpeg, output = (p.resolve() for p in (args.engine, args.ffmpeg, args.output))
    fixture = ROOT / "examples" / "tenant"
    policy, entities = fixture / "policy.cedar", fixture / "entities.json"
    cases = json.loads((fixture / "requests.json").read_text(encoding="utf-8"))
    entity_data = json.loads(entities.read_text(encoding="utf-8"))
    by_id = {(e["uid"]["type"], e["uid"]["id"]): e for e in entity_data}
    if [case["request"]["principal"] for case in cases] != [{"type": "User", "id": name} for name in ("alice", "bob", "eve")]:
        raise RuntimeError("tenant example principals changed; update the narration")
    tenant = by_id[("Document", "report")]["attrs"]["tenant"]
    if tenant != "acme" or by_id[("User", "alice")]["attrs"] != {"tenant": "acme", "suspended": False} or by_id[("User", "bob")]["attrs"]["tenant"] != "other" or by_id[("User", "eve")]["attrs"] != {"tenant": "acme", "suspended": True}:
        raise RuntimeError("tenant entities changed; update the narration")
    if any(c["request"]["resource"] != {"type": "Document", "id": "report"} or c["request"]["action"] != {"type": "Action", "id": "read"} or c["request"]["context"].get("authenticated") is not True for c in cases):
        raise RuntimeError("tenant requests changed; update the narration")
    with tempfile.TemporaryDirectory(prefix="cedar-demo-") as directory:
        tmp = pathlib.Path(directory)
        results = []
        for i, case in enumerate(cases):
            request = tmp / f"request-{i}.json"
            request.write_text(json.dumps(case["request"], ensure_ascii=False), encoding="utf-8")
            response = json.loads(command([engine, "authorize", policy, entities, request, "--format", "json"]))
            if response["decision"] != case["decision"] or response["errors"]:
                raise RuntimeError(f"unexpected tenant response: {response}")
            results.append(response)
        if [r["reasons"] for r in results] != [["policy0"], [], ["policy1"]]:
            raise RuntimeError("tenant policy reasons changed; update the narration")
        check = json.loads(command([engine, "check-entities", entities, "--require-closed", "--format", "json"]))
        test = json.loads(command([engine, "test", policy, entities, fixture / "requests.json", "--format", "json"]))
        if check != {"closed": True, "entity_count": 4, "missing_parents": []} or test["failures"] or len(test["cases"]) != 3:
            raise RuntimeError("entity check or example tests failed")
        policy_lines = policy.read_text(encoding="utf-8").splitlines()[1:]
        if policy_lines != [
            'permit(principal, action == Action::"read", resource)',
            'when { principal.tenant == resource.tenant && context.authenticated };',
            'forbid(principal, action, resource)',
            'when { principal.suspended == true };',
        ]:
            raise RuntimeError("tenant policy changed; update the narration")
        show = lambda value: json.dumps(value, ensure_ascii=False, indent=2).splitlines()
        scenes = [
            dict(kind="intro", title="一个多租户访问控制案例", narration="同一份文档，谁可以访问？我们用一个多租户场景，看看策略如何给出授权决定。"),
            dict(kind="policy", title="先写清楚访问规则", lines=policy_lines, narration="策略写了两条规则：用户与文档属于同一租户，且请求已经认证时，可以读取。"),
            dict(kind="policy", title="停用账户始终禁止", lines=policy_lines, narration="如果用户已经停用，禁止规则会生效。发生冲突时，禁止优先于允许。"),
            dict(kind="terminal", title="授权请求包含什么", label="REQUEST  /  示例请求摘要", lines=[
                json.dumps({"principal": cases[0]["request"]["principal"]}, ensure_ascii=False),
                json.dumps({"action": cases[0]["request"]["action"]}, ensure_ascii=False),
                json.dumps({"resource": cases[0]["request"]["resource"]}, ensure_ascii=False),
                json.dumps({"context": cases[0]["request"]["context"]}, ensure_ascii=False),
            ], narration="一次请求包含主体、操作、资源和上下文。这里的主体是爱丽丝，操作是读取，资源是 report 文档。"),
            dict(kind="case", title="同租户：允许访问", person="Alice", facts=[("用户租户", "acme"), ("文档租户", "acme"), ("请求状态", "已认证")], lines=show(results[0]), narration="爱丽丝与文档都属于 acme，请求也已经认证。引擎返回允许，并指出命中的允许策略。"),
            dict(kind="case", title="跨租户：默认拒绝", person="Bob", facts=[("用户租户", "other"), ("文档租户", "acme"), ("请求状态", "已认证")], lines=show(results[1]), narration="鲍勃属于另一个租户，没有允许策略命中，因此结果是默认拒绝。"),
            dict(kind="case", title="停用账户：禁止优先", person="Eve", facts=[("用户租户", "acme"), ("文档租户", "acme"), ("账户状态", "已停用")], lines=show(results[2]), narration="伊芙虽然属于同一租户，但账户已停用。禁止规则覆盖允许，结果中返回禁止策略编号。"),
            dict(kind="terminal", title="读懂授权结果", label="RESPONSE  /  结果字段", lines=[
                'decision     Allow / Deny',
                'reasons      determining policy IDs',
                'errors       per-policy evaluation errors',
            ], narration="授权结果不只有允许或拒绝。命中策略说明决定的来源，求值错误帮助应用定位数据或策略问题。"),
            dict(kind="terminal", title="检查实体数据", label="CHECK-ENTITIES  /  实际 CLI 输出", lines=["$ cd examples/tenant", "$ cedar-auth-engine check-entities entities.json --require-closed --format json", ""] + show(check), narration="授权前还可以检查实体关系。这个例子有四个实体，父级引用完整。"),
            dict(kind="terminal", title="批量验证三个请求", label="TEST  /  实际 CLI 输出摘要", lines=["$ cd examples/tenant", "$ cedar-auth-engine test policy.cedar entities.json requests.json --format json", ""] + [json.dumps({k: c[k] for k in ("index", "expected", "passed")}, ensure_ascii=False) for c in test["cases"]] + ["", '"failures": ' + str(test["failures"])], narration="批量测试把三条请求的结果与预期逐一比较。三个用例全部通过。"),
            dict(kind="end", title="将策略接入应用", narration="项目提供 MoonBit 库和原生命令行。应用提供策略、请求和实体数据，获得决定、命中策略和求值错误。"),
        ]
        ps = pathlib.Path(os.environ["SystemRoot"]) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        parts, durations, params = [], [], None
        if args.preview_dir:
            args.preview_dir.mkdir(parents=True, exist_ok=True)
        image_paths, scene_boundaries = [], []
        for i, scene in enumerate(scenes):
            if i:
                scene_boundaries.append(sum(durations))
            phrases = [part for part in re.findall(r"[^，。！？；]+[，。！？；]?", scene["narration"]) if part.strip()]
            for j, phrase in enumerate(phrases):
                image_path = tmp / f"scene-{i:02}-{j:02}.png"
                render(image_path, i + 1, len(scenes), scene, phrase)
                image_paths.append(image_path)
                if args.preview_dir and j == 0:
                    import shutil
                    shutil.copyfile(image_path, args.preview_dir / f"scene-{i:02}.png")
                text, audio = tmp / f"voice-{i:02}-{j:02}.txt", tmp / f"voice-{i:02}-{j:02}.wav"
                text.write_text(phrase, encoding="utf-8")
                command([ps, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", ROOT / "scripts" / "demo_voice.ps1", "-TextFile", text, "-OutputFile", audio])
                with wave.open(str(audio), "rb") as voice:
                    current = (voice.getnchannels(), voice.getsampwidth(), voice.getframerate())
                    if params is not None and current != params:
                        raise RuntimeError("voice segment audio formats differ")
                    params = current
                    frames = voice.readframes(voice.getnframes())
                    pause = 0.55 if j == len(phrases) - 1 else 0.1
                    silence = b"\0" * (int(pause * current[2]) * current[0] * current[1])
                    parts.append(frames + silence)
                    durations.append((len(frames) + len(silence)) / (current[0] * current[1] * current[2]))
        narration = tmp / "narration.wav"
        with wave.open(str(narration), "wb") as voice:
            voice.setnchannels(params[0]); voice.setsampwidth(params[1]); voice.setframerate(params[2])
            for part in parts:
                voice.writeframes(part)
        sequence = tmp / "scenes.ffconcat"
        entries = ["ffconcat version 1.0"]
        for image_path, duration in zip(image_paths, durations):
            entries.extend([f"file '{image_path.as_posix()}'", f"duration {duration:.6f}"])
        entries.append(f"file '{image_paths[-1].as_posix()}'")
        sequence.write_text("\n".join(entries) + "\n", encoding="utf-8")
        output.parent.mkdir(parents=True, exist_ok=True)
        # Brief fades mark scene changes; subtitle changes within a scene stay sharp.
        filters = ["fps=24", "tpad=stop_mode=clone:stop_duration=2"]
        for boundary in scene_boundaries:
            filters.extend([f"fade=t=out:st={boundary - 0.18:.3f}:d=0.18:enable='between(t,{boundary - 0.18:.3f},{boundary:.3f})'",
                            f"fade=t=in:st={boundary:.3f}:d=0.18:enable='between(t,{boundary:.3f},{boundary + 0.18:.3f})'"])
        command([ffmpeg, "-hide_banner", "-loglevel", "error", "-y", "-f", "concat", "-safe", "0", "-i", sequence, "-i", narration,
                 "-vf", ",".join(filters), "-c:v", "libx264", "-preset", "veryfast", "-crf", "20", "-pix_fmt", "yuv420p", "-c:a", "aac", "-b:a", "160k", "-t", f"{sum(durations):.6f}", "-movflags", "+faststart", output])
        print(f"Video: {output} ({sum(durations):.1f} seconds, {len(scenes)} scenes)")


if __name__ == "__main__":
    main()
