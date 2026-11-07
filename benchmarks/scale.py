#!/usr/bin/env python3
"""Repeatable CLI workload measurements, including input preparation costs."""
import argparse
import ctypes
import hashlib
import shlex
import json
import os
import pathlib
import platform
import statistics
import subprocess
import sys
import tempfile
import time


def peak_memory(process):
    """Return bytes of peak working set on Windows, or VmHWM on Linux."""
    if os.name == 'nt':
        class Counters(ctypes.Structure):
            _fields_ = [('cb', ctypes.c_ulong), ('faults', ctypes.c_ulong)] + [
                (name, ctypes.c_size_t) for name in ('peak_working_set', 'working_set',
                'peak_paged', 'paged', 'peak_nonpaged', 'nonpaged', 'pagefile', 'peak_pagefile')]
        info = Counters()
        info.cb = ctypes.sizeof(info)
        psapi = ctypes.WinDLL('psapi', use_last_error=True)
        psapi.GetProcessMemoryInfo.argtypes = [ctypes.c_void_p, ctypes.POINTER(Counters), ctypes.c_ulong]
        if psapi.GetProcessMemoryInfo(int(process._handle), ctypes.byref(info), info.cb):
            return info.peak_working_set
    elif sys.platform.startswith('linux'):
        try:
            for line in pathlib.Path('/proc/%d/status' % process.pid).read_text().splitlines():
                if line.startswith('VmHWM:'):
                    return int(line.split()[1]) * 1024
        except (OSError, ValueError):
            pass
    return None


def timed_run(command, temp):
    stdout, stderr = temp / 'out.json', temp / 'err.txt'
    with stdout.open('wb') as out, stderr.open('wb') as err:
        start = time.perf_counter()
        process = subprocess.Popen([str(item) for item in command], stdout=out, stderr=err)
        peak = None
        while process.poll() is None:
            value = peak_memory(process)
            if value is not None:
                peak = max(peak or 0, value)
            if time.perf_counter() - start > 300:
                process.kill()
                process.wait()
                raise RuntimeError('benchmark command timed out')
            time.sleep(0.002)
        elapsed = time.perf_counter() - start
        if process.returncode:
            raise RuntimeError('command failed: ' + stderr.read_text(encoding='utf-8', errors='replace'))
    return elapsed, peak, json.loads(stdout.read_text(encoding='utf-8'))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--engine', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--profile', choices=('baseline', 'scale'), default='baseline')
    parser.add_argument('--repeat', type=int, default=3)
    parser.add_argument('--revision', required=True, help='source revision or working-tree identifier')
    parser.add_argument('--toolchain', required=True, help='toolchain used to build the engine')
    args = parser.parse_args()
    if args.repeat < 1:
        parser.error('--repeat must be positive')
    engine = str(pathlib.Path(args.engine).resolve())
    sizes = {'baseline': (60, 512, 512), 'scale': (2048, 10000, 16384)}
    policies, entities, batch = sizes[args.profile]
    measurements = []
    with tempfile.TemporaryDirectory(prefix='cedar-scale-') as tmpdir:
        tmp = pathlib.Path(tmpdir)
        for workload in ('sparse', 'dense'):
            policy_file, entity_file = tmp / 'policy.cedar', tmp / 'entities.json'
            request_file, batch_file = tmp / 'request.json', tmp / 'requests.json'
            # Dense has many policies in scope; sparse has only one.
            root = entities - 1 if workload == 'sparse' else ((entities - 1) // 16) * 16
            policy_lines = ['@id("p0") permit(principal in Group::"%s", action, resource);' % root]
            policy_lines.extend(
                '@id("p%d") permit(principal, action == Action::"%s", resource);' %
                (i, 'shared' if workload == 'dense' and (args.profile == 'baseline' or i < 32) else 'action%d' % i)
                for i in range(1, policies))
            policy_file.write_text('\n'.join(policy_lines), encoding='utf-8')
            values = []
            for i in range(entities):
                parents = [{'type': 'Group', 'id': str(i - 1)}] if workload == 'dense' and i % 16 else []
                values.append({'uid': {'type': 'Group', 'id': str(i)}, 'attrs': {}, 'parents': parents})
            entity_file.write_text(json.dumps(values, separators=(',', ':')), encoding='utf-8')
            req = {'principal': {'type': 'Group', 'id': str(entities - 1)},
                   'action': {'type': 'Action', 'id': 'shared' if workload == 'dense' else 'action1'},
                   'resource': {'type': 'Document', 'id': 'report'}, 'context': {}}
            request_file.write_text(json.dumps(req, separators=(',', ':')), encoding='utf-8')
            batch_file.write_text(json.dumps([req] * batch, separators=(',', ':')), encoding='utf-8')
            commands = {
                'parse': [engine, 'check', policy_file, '--format', 'json'],
                'entity_snapshot': [engine, 'check-entities', entity_file, '--format', 'json'],
                'authorize': [engine, 'authorize', policy_file, entity_file, request_file, '--format', 'json'],
                'batch': [engine, 'batch', policy_file, entity_file, batch_file, '--format', 'json'],
            }
            for name, command in commands.items():
                samples, peaks = [], []
                for _ in range(args.repeat):
                    elapsed, peak, result_data = timed_run(command, tmp)
                    if name == 'authorize' and result_data['decision'] != 'Allow':
                        raise RuntimeError('unexpected decision')
                    if name == 'batch' and (len(result_data) != batch or any(r['decision'] != 'Allow' for r in result_data)):
                        raise RuntimeError('unexpected batch decision')
                    samples.append(elapsed)
                    peaks.append(peak)
                median = statistics.median(samples)
                measurements.append({'workload': workload, 'operation': name,
                                     'seconds': samples, 'median_seconds': median, 'peak_memory_bytes': peaks,
                                     'requests_per_second': batch / median if name == 'batch' else None})
    result = {'command': 'python ' + shlex.join(sys.argv), 'source_revision': args.revision,
              'engine_sha256': hashlib.sha256(pathlib.Path(engine).read_bytes()).hexdigest(),
              'moonbit_toolchain': args.toolchain, 'profile': args.profile, 'repetitions': args.repeat,
              'seed': None, 'policies': policies, 'entities': entities, 'requests': batch,
              'hierarchy': {'sparse': 'no parent links', 'dense': 'chains of at most 16 entities'}, 'dense_matching_policies': policies if args.profile == 'baseline' else 32, 'environment': {'os': platform.platform(),
              'machine': platform.machine(), 'python': platform.python_version(), 'cpu': platform.processor()},
              'memory_note': 'sampled child peak working set on Windows or VmHWM on Linux; null if unavailable',
              'measurement_note': 'wall time includes process startup and input parsing; not an isolated library microbenchmark',
              'measurements': measurements}
    pathlib.Path(args.output).write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
