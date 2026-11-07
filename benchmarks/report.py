"""Minimal, explicit metadata for benchmark reports."""
import os
import pathlib
import re
import sys


def revision(value):
    if not re.fullmatch(r'[0-9a-fA-F]{7,40}', value):
        raise ValueError('revision must be a hexadecimal commit ID')
    return value.lower()


def toolchain(value):
    if not re.fullmatch(r'(?:moonc|MoonBit) v?\d+\.\d+\.\d+(?:\+[0-9a-fA-F]+)?(?: native debug)?', value):
        raise ValueError('toolchain must be a MoonBit version label')
    return value


def metadata():
    hosted = os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
    python = '.'.join(map(str, sys.version_info[:3] if hosted else sys.version_info[:2]))
    runner = {'source': 'local'}
    if hosted:
        runner = {'source': 'github-hosted'}
        for key, name, allowed in (
            ('os', 'RUNNER_OS', {'Linux', 'Windows', 'macOS'}),
            ('arch', 'RUNNER_ARCH', {'X86', 'X64', 'ARM', 'ARM64'}),
        ):
            value = os.environ.get(name, '')
            if value in allowed:
                runner[key] = value
        image = os.environ.get('ImageOS', '')
        if re.fullmatch(r'[A-Za-z0-9_-]{1,40}', image):
            runner['image'] = image
        runner['logical_cpus'] = os.cpu_count()
        if runner.get('os') == 'Linux':
            cpuinfo = pathlib.Path('/proc/cpuinfo').read_text(encoding='utf-8', errors='replace')
            model = next((line.split(':', 1)[1].strip() for line in cpuinfo.splitlines() if line.startswith('model name') and ':' in line), '')
            if re.fullmatch(r'[A-Za-z0-9 ._@()+-]{1,120}', model):
                runner['cpu_model'] = model
            meminfo = pathlib.Path('/proc/meminfo').read_text(encoding='utf-8', errors='replace')
            mem = re.search(r'^MemTotal:\s+(\d+)\s+kB$', meminfo, re.MULTILINE)
            if mem:
                runner['memory_kib'] = int(mem.group(1))
        repository, run_id = os.environ.get('GITHUB_REPOSITORY', ''), os.environ.get('GITHUB_RUN_ID', '')
        if re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository) and run_id.isdigit():
            runner['run_url'] = 'https://github.com/' + repository + '/actions/runs/' + run_id
    return {'python': python, 'runner': runner}
