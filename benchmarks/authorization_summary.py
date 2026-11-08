#!/usr/bin/env python3
"""Measure full and summarized batch authorization on the same workload."""
import argparse
import hashlib
import json
import pathlib
import statistics
import tempfile

from report import metadata, revision, toolchain
from scale import timed_run


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--engine', required=True, type=pathlib.Path)
    parser.add_argument('--requests', type=int, default=32768)
    parser.add_argument('--repeat', type=int, default=3)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--toolchain', required=True)
    parser.add_argument('--output', required=True, type=pathlib.Path)
    args = parser.parse_args()
    args.revision = revision(args.revision)
    args.toolchain = toolchain(args.toolchain)
    if not 1 <= args.requests <= 32768 or args.repeat < 1:
        parser.error('--requests must be 1..32768 and --repeat must be positive')
    engine = args.engine.resolve()
    entity_count, policy_count = 10000, 2050
    modes = {name: {'seconds': [], 'peak_memory_bytes': [], 'output_sha256': None,
                    'output_bytes': None} for name in ('full', 'summary')}
    allowed_without_error = (args.requests + 2) // 3
    denied_without_error = (args.requests + 1) // 3
    allowed_with_error = args.requests // 3
    expected = {'total': args.requests, 'cedar_allowed': allowed_without_error + allowed_with_error,
                'cedar_denied': denied_without_error, 'error_requests': allowed_with_error,
                'enforcement_allowed': allowed_without_error,
                'enforcement_denied': denied_without_error + allowed_with_error}
    with tempfile.TemporaryDirectory(prefix='cedar-auth-summary-') as directory:
        temp = pathlib.Path(directory)
        policy, entities, requests = [temp / name for name in ('policy.cedar', 'entities.json', 'requests.json')]
        policies = ['@id("read") permit(principal in Group::"root", action == Action::"read", resource);',
                    '@id("blocked") forbid(principal, action, resource) when { context.blocked };',
                    '@id("guard") forbid(principal, action, resource) when { context.guard };']
        policies.extend('@id("p%d") permit(principal, action == Action::"unused%d", resource);' % (i, i)
                        for i in range(1, 2048))
        assert len(policies) == policy_count
        policy.write_text('\n'.join(policies), encoding='utf-8')
        graph = [{'uid': {'type': 'Group', 'id': 'root'}, 'attrs': {}, 'parents': []}]
        graph.extend({'uid': {'type': 'Group', 'id': 'g%d' % i}, 'attrs': {},
                      'parents': [{'type': 'Group', 'id': 'root'}]} for i in range(1, entity_count))
        entities.write_text(json.dumps(graph, separators=(',', ':')), encoding='utf-8')
        request = {'principal': {'type': 'Group', 'id': 'g9999'},
                   'action': {'type': 'Action', 'id': 'read'},
                   'resource': {'type': 'File', 'id': 'report'}}
        contexts = ({'blocked': False, 'guard': False}, {'blocked': True, 'guard': False}, {'blocked': False})
        requests.write_text(json.dumps([{**request, 'context': contexts[i % 3]} for i in range(args.requests)],
                                       separators=(',', ':')), encoding='utf-8')
        for repeat in range(args.repeat):
            for mode in (('full', 'summary') if repeat % 2 == 0 else ('summary', 'full')):
                command = [engine, 'batch', policy, entities, requests, '--format', 'json']
                if mode == 'summary':
                    command.append('--summary')
                elapsed, peak, response = timed_run(command, temp)
                if mode == 'full':
                    if len(response) != args.requests:
                        raise RuntimeError('unexpected response count')
                    for i, item in enumerate(response):
                        decision = 'Deny' if i % 3 == 1 else 'Allow'
                        reasons = ['blocked'] if i % 3 == 1 else ['read']
                        errors = [error['policy_id'] for error in item['errors']]
                        if item['decision'] != decision or item['reasons'] != reasons or errors != (['guard'] if i % 3 == 2 else []):
                            raise RuntimeError('unexpected authorization response')
                elif response != expected:
                    raise RuntimeError('unexpected authorization summary')
                output = (temp / 'out.json').read_bytes()
                digest = hashlib.sha256(output).hexdigest()
                entry = modes[mode]
                if entry['output_sha256'] is not None and entry['output_sha256'] != digest:
                    raise RuntimeError('output differs between samples')
                entry['output_sha256'] = digest
                entry['output_bytes'] = len(output)
                entry['seconds'].append(elapsed)
                entry['peak_memory_bytes'].append(peak)
    for entry in modes.values():
        entry['median_seconds'] = statistics.median(entry['seconds'])
    result = {
        'command': 'python benchmarks/authorization_summary.py --engine <ENGINE> --requests <REQUESTS> --repeat <REPEAT> --revision <REVISION> --toolchain <TOOLCHAIN> --output <OUTPUT>',
        'source_revision': args.revision,
        'engine_sha256': hashlib.sha256(engine.read_bytes()).hexdigest(),
        'moonbit_toolchain': args.toolchain,
        'environment': metadata(),
        'requests': args.requests,
        'repetitions': args.repeat,
        'seed': None,
        'entities': entity_count,
        'policies': policy_count,
        'workload': 'alternating allow, explicit deny and allow with an evaluation error',
        'expected_summary': expected,
        'measurement_note': 'CLI wall time includes startup, input parsing, authorization and JSON output; mode order alternates',
        'memory_note': 'sampled child peak working set on Windows or VmHWM on Linux; null if unavailable',
        'modes': modes,
    }
    args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
