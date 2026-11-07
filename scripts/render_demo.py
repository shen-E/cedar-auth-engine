#!/usr/bin/env python3
"""Render the Chinese demo from live CLI output and a local Windows voice."""
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
BG, PANEL, INK, MUTED, ACCENT = "#f5f7f5", "#ffffff", "#182d2a", "#536c66", "#32675b"
FONT_DIR = pathlib.Path(os.environ.get("WINDIR", r"C:\Windows")) / "Fonts"


def command(args):
    result = subprocess.run([str(item) for item in args], cwd=ROOT, capture_output=True, text=True, encoding="utf-8", timeout=180)
    if result.returncode:
        raise RuntimeError(f"command failed: {args}\n{result.stderr}\n{result.stdout}")
    return result.stdout


def wrap(draw, text, font, max_width):
    lines, current = [], ""
    for char in text:
        if char == "\n":
            lines.append(current)
            current = ""
        elif current and draw.textlength(current + char, font=font) > max_width:
            if char in "，。；：！？、":
                lines.append(current + char)
                current = ""
            else:
                split = max(current.rfind(mark) for mark in "，。；：！？")
                if split >= len(current) // 2:
                    lines.append(current[:split + 1])
                    current = current[split + 1:] + char
                else:
                    lines.append(current)
                    current = char
        else:
            current += char
    if current:
        lines.append(current)
    return lines


def render_slide(path, index, title, label, lines, narration, total):
    image = Image.new("RGB", (WIDTH, HEIGHT), BG)
    draw = ImageDraw.Draw(image)
    regular = str(FONT_DIR / "msyh.ttc")
    bold = str(FONT_DIR / "msyhbd.ttc")
    mono = str(FONT_DIR / "consola.ttf")
    fonts = {"eyebrow": ImageFont.truetype(regular, 25), "title": ImageFont.truetype(bold, 55),
             "label": ImageFont.truetype(regular, 27), "body": ImageFont.truetype(mono, 32),
             "subtitle": ImageFont.truetype(regular, 40)}
    draw.text((96, 65), "CEDAR AUTH ENGINE  /  DEMO", font=fonts["eyebrow"], fill=MUTED)
    draw.text((96, 122), title, font=fonts["title"], fill=INK)
    draw.text((1690, 80), f"{index:02d} / {total:02d}", font=fonts["eyebrow"], fill=MUTED)
    draw.rounded_rectangle((96, 220, 1824, 785), radius=20, fill=PANEL, outline="#d7e1dc", width=2)
    draw.text((140, 253), label, font=fonts["label"], fill=ACCENT)
    draw.line((140, 307, 1780, 307), fill="#e0e8e3", width=2)
    y = 335
    for line in lines:
        for piece in wrap(draw, line, fonts["body"], 1640):
            draw.text((140, y), piece, font=fonts["body"], fill=INK)
            y += 45
    if y > 760:
        raise RuntimeError("demo slide content exceeds panel")
    draw.line((96, 844, 1824, 844), fill="#d7e1dc", width=2)
    subtitle = wrap(draw, narration, fonts["subtitle"], 1700)
    if len(subtitle) > 3:
        raise RuntimeError("demo subtitle exceeds three lines")
    y = 875
    for line in subtitle:
        draw.text((110, y), line, font=fonts["subtitle"], fill=INK)
        y += 57
    image.save(path)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--engine", required=True, type=pathlib.Path)
    parser.add_argument("--moon", required=True, type=pathlib.Path)
    parser.add_argument("--ffmpeg", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()
    engine, moon, ffmpeg, output = (p.resolve() for p in (args.engine, args.moon, args.ffmpeg, args.output))
    fixture = ROOT / "examples" / "tenant"
    policy = fixture / "policy.cedar"
    entities = fixture / "entities.json"
    cases = json.loads((fixture / "requests.json").read_text(encoding="utf-8"))
    entity_data = json.loads(entities.read_text(encoding="utf-8"))
    by_id = {(e["uid"]["type"], e["uid"]["id"]): e for e in entity_data}
    if [case["request"]["principal"] for case in cases] != [{"type": "User", "id": name} for name in ("alice", "bob", "eve")]:
        raise RuntimeError("tenant example principals changed; update the narration")
    if any(case["request"]["resource"] != {"type": "Document", "id": "report"} or
           case["request"]["context"].get("authenticated") is not True for case in cases):
        raise RuntimeError("tenant request data changed; update the narration")
    tenant = by_id[("Document", "report")]["attrs"]["tenant"]
    if by_id[("User", "alice")]["attrs"]["tenant"] != tenant or by_id[("User", "bob")]["attrs"]["tenant"] == tenant or by_id[("User", "eve")]["attrs"]["tenant"] != tenant or by_id[("User", "eve")]["attrs"]["suspended"] is not True:
        raise RuntimeError("tenant entities changed; update the narration")
    with tempfile.TemporaryDirectory(prefix="cedar-demo-") as directory:
        tmp = pathlib.Path(directory)
        results = []
        for i, case in enumerate(cases):
            request_file = tmp / f"request-{i}.json"
            request_file.write_text(json.dumps(case["request"], ensure_ascii=False), encoding="utf-8")
            result = json.loads(command([engine, "authorize", policy, entities, request_file, "--format", "json"]))
            if result["decision"] != case["decision"] or result["errors"]:
                raise RuntimeError(f"unexpected tenant response: {result}")
            results.append(result)
        if results[0]["reasons"] != ["policy0"] or results[1]["reasons"] or results[2]["reasons"] != ["policy1"]:
            raise RuntimeError("tenant policy reasons changed; update the narration")
        check = json.loads(command([engine, "check-entities", entities, "--require-closed", "--format", "json"]))
        test = json.loads(command([engine, "test", policy, entities, fixture / "requests.json", "--format", "json"]))
        if check != {"closed": True, "entity_count": 4, "missing_parents": []} or test["failures"] or len(test["cases"]) != len(cases):
            raise RuntimeError("entity check or example tests failed")
        moon_test = command([moon, "test", "--target", "all"])
        totals = re.findall(r"Total tests: [^\r\n]+", moon_test)
        if len(totals) != 4 or any("failed: 0" not in line for line in totals):
            raise RuntimeError("unable to verify all MoonBit target test results")
        policy_lines = policy.read_text(encoding="utf-8").splitlines()
        show = lambda value: json.dumps(value, ensure_ascii=False, indent=2).splitlines()
        slides = [
            ("可嵌入的授权引擎", "MOONBIT  /  CEDAR SUBSET", ["Principal  +  Action  +  Resource  +  Context", "", "Decision  /  Reasons  /  Evaluation errors"],
             "这是一个可以嵌入应用的授权引擎。应用提供主体、操作、资源和上下文，引擎返回允许或拒绝，并保留决定原因和求值错误。"),
            ("从策略开始", "examples/tenant/policy.cedar", policy_lines,
             "演示使用多租户文档策略。允许规则要求用户和文档属于同一租户，且请求已经认证。另一条禁止规则会阻止已停用的用户。"),
            ("同租户请求", "REQUEST  /  ALICE", ["principal: User::\"alice\"", "principal.tenant: " + by_id[("User", "alice")]["attrs"]["tenant"], "resource: Document::\"report\"", "resource.tenant: " + by_id[("Document", "report")]["attrs"]["tenant"], "context.authenticated: true"],
             "先看爱丽丝的请求。她和文档属于同一租户，请求也已经认证。应用把这些数据交给引擎，由策略决定访问结果。"),
            ("允许，并给出原因", "AUTHORIZE  /  ACTUAL CLI OUTPUT", show(results[0]),
             "实际运行得到允许。返回的 policy 零是命中的允许策略，错误列表为空。应用可以同时使用决定和诊断结果。"),
            ("跨租户默认拒绝", "AUTHORIZE  /  BOB  /  ACTUAL CLI OUTPUT", ["principal.tenant: " + by_id[("User", "bob")]["attrs"]["tenant"], "resource.tenant: " + by_id[("Document", "report")]["attrs"]["tenant"], ""] + show(results[1]),
             "鲍勃来自另一个租户，即使请求已认证，也不满足允许条件。没有允许策略命中，因此引擎按默认规则拒绝访问。"),
            ("禁止规则优先", "AUTHORIZE  /  EVE  /  ACTUAL CLI OUTPUT", ["principal.suspended: true", ""] + show(results[2]),
             "伊芙与文档属于同一租户，但账户已经停用。禁止规则优先，所以最终结果仍然是拒绝，并返回禁止策略的编号。"),
            ("检查实体层级", "CHECK-ENTITIES  /  ACTUAL CLI OUTPUT", show(check),
             "项目还可以检查实体层级。这个示例中四个实体的父级关系完整；如果父级缺失，命令会列出相关引用，便于更新前检查。"),
            ("运行示例用例", "TEST  /  ACTUAL CLI OUTPUT", [f"cases: {len(test['cases'])}", f"failures: {test['failures']}", "", "alice  -> " + results[0]["decision"], "bob    -> " + results[1]["decision"], "eve    -> " + results[2]["decision"]],
             "测试命令将三条实际请求与预期结果逐一比较。这里全部通过：同租户允许，跨租户拒绝，停用用户由禁止规则拦截。"),
            ("用于应用集成", "LIBRARY  /  CLI", ["MoonBit library: typed requests and entity snapshots", "Native CLI: check, authorize, test and compare", "", "The host supplies identity, policies and entity data."],
             "引擎同时提供 MoonBit 库和原生命令行。应用负责身份认证，以及策略和实体数据的保存；授权核心本身不访问网络、文件系统或时钟。"),
            ("验证与复现", "MOON TEST --TARGET ALL  /  ACTUAL OUTPUT", totals,
             "最后展示当前版本的实际测试结果。四个 MoonBit 目标分别运行测试；仓库还提供固定版本的 Cedar 参考对照，方便继续验证兼容性。"),
        ]
        ps = pathlib.Path(os.environ["SystemRoot"]) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        wave_parts, durations, params = [], [], None
        for i, (title, label, lines, narration) in enumerate(slides):
            render_slide(tmp / f"slide-{i:02}.png", i + 1, title, label, lines, narration, len(slides))
            text = tmp / f"voice-{i:02}.txt"
            audio = tmp / f"voice-{i:02}.wav"
            text.write_text(narration, encoding="utf-8")
            command([ps, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", ROOT / "scripts" / "demo_voice.ps1", "-TextFile", text, "-OutputFile", audio])
            with wave.open(str(audio), "rb") as voice:
                current = (voice.getnchannels(), voice.getsampwidth(), voice.getframerate())
                if params is not None and current != params:
                    raise RuntimeError("voice segment audio formats differ")
                params = current
                frames = voice.readframes(voice.getnframes())
                silence = b"\0" * (int(0.8 * current[2]) * current[0] * current[1])
                wave_parts.append(frames + silence)
                durations.append((len(frames) + len(silence)) / (current[0] * current[1] * current[2]))
        narration_path = tmp / "narration.wav"
        with wave.open(str(narration_path), "wb") as audio:
            audio.setnchannels(params[0]); audio.setsampwidth(params[1]); audio.setframerate(params[2])
            for part in wave_parts:
                audio.writeframes(part)
        sequence = tmp / "slides.ffconcat"
        entries = ["ffconcat version 1.0"]
        for i, duration in enumerate(durations):
            entries.extend([f"file '{(tmp / f'slide-{i:02}.png').as_posix()}'", f"duration {duration:.6f}"])
        entries.append(f"file '{(tmp / f'slide-{len(slides)-1:02}.png').as_posix()}'")
        sequence.write_text("\n".join(entries) + "\n", encoding="utf-8")
        output.parent.mkdir(parents=True, exist_ok=True)
        command([ffmpeg, "-hide_banner", "-loglevel", "error", "-y", "-f", "concat", "-safe", "0", "-i", sequence, "-i", narration_path,
                 "-vf", "fps=24,tpad=stop_mode=clone:stop_duration=2", "-c:v", "libx264", "-preset", "veryfast", "-crf", "23", "-pix_fmt", "yuv420p", "-c:a", "aac", "-b:a", "128k", "-t", f"{sum(durations):.6f}", "-movflags", "+faststart", output])
        print(f"Video: {output} ({sum(durations):.1f} seconds, {len(slides)} scenes)")


if __name__ == "__main__":
    main()
