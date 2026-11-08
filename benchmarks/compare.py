#!/usr/bin/env python3
"""Measure policy comparisons over two entity snapshots."""
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
    parser.add_argument('--requests', required=True, type=int)
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
    entity_count, policy_count = 10000, 2048
    samples, peaks = [], []
    digest = None
    with tempfile.TemporaryDirectory(prefix='cedar-compare-') as directory:
        temp = pathlib.Path(directory)
        before, after, entities, requests = [temp / name for name in
                                              ('before.cedar', 'after.cedar', 'entities.json', 'requests.json')]
        policies = ['@id("read") permit(principal in Group::"root", action == Action::"read", resource);']
        policies.extend('@id("p%d") permit(principal, action == Action::"unused%d", resource);' % (i, i)
                        for i in range(1, policy_count))
        before.write_text('\n'.join(policies), encoding='utf-8')
        policies.append('@id("blocked") forbid(principal, action == Action::"read", resource) when { context.blocked };')
        after.write_text('\n'.join(policies), encoding='utf-8')
        graph = [{'uid': {'type': 'Group', 'id': 'root'}, 'attrs': {}, 'parents': []}]
        graph.extend({'uid': {'type': 'Group', 'id': 'g%d' % i}, 'attrs': {},
                      'parents': [{'type': 'Group', 'id': 'root'}]} for i in range(1, entity_count))
        entities.write_text(json.dumps(graph, separators=(',', ':')), encoding='utf-8')
        request = {'principal': {'type': 'Group', 'id': 'g9999'},
                   'action': {'type': 'Action', 'id': 'read'},
                   'resource': {'type': 'File', 'id': 'report'}}
        cases = [{**request, 'context': {'blocked': i % 2 == 1}} for i in range(args.requests)]
        requests.write_text(json.dumps(cases, separators=(',', ':')), encoding='utf-8')
        command = [engine, 'compare', before, after, entities, requests,
                   '--after-entities', entities, '--format', 'json']
        for _ in range(args.repeat):
            elapsed, peak, report = timed_run(command, temp)
            expected = args.requests // 2
            if (report['total'] != args.requests or report['changed'] != expected or
                report['decision_revocations'] != expected or report['enforcement_revocations'] != expected or
                report['after_error_requests'] != 0 or len(report['cases']) != args.requests or
                any(item['index'] != i or item['decision_revoked'] != (i % 2 == 1)
                    for i, item in enumerate(report['cases']))):
                raise RuntimeError('unexpected comparison result')
            current = hashlib.sha256((temp / 'out.json').read_bytes()).hexdigest()
            if digest is not None and digest != current:
                raise RuntimeError('comparison output differs between samples')
            digest = current
            samples.append(elapsed)
            peaks.append(peak)
    result = {
        'command': 'python benchmarks/compare.py --engine <ENGINE> --requests <REQUESTS> --repeat <REPEAT> --revision <REVISION> --toolchain <TOOLCHAIN> --output <OUTPUT>',
        'source_revision': args.revision,
        'engine_sha256': hashlib.sha256(engine.read_bytes()).hexdigest(),
        'moonbit_toolchain': args.toolchain,
        'environment': metadata(),
        'requests': args.requests,
        'repetitions': args.repeat,
        'seed': None,
        'entities_per_snapshot': entity_count,
        'snapshots': 2,
        'before_policies': policy_count,
        'after_policies': policy_count + 1,
        'changed_requests': args.requests // 2,
        'workload': 'alternating blocked context; both snapshots contain the same hierarchy',
        'measurement_note': 'CLI wall time includes startup, input parsing, comparison and JSON output',
        'memory_note': 'sampled child peak working set on Windows or VmHWM on Linux; null if unavailable',
        'seconds': samples,
        'median_seconds': statistics.median(samples),
        'peak_memory_bytes': peaks,
        'output_sha256': digest,
    }
    args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
