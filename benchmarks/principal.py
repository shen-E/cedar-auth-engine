#!/usr/bin/env python3
"""Compare exact-principal or exact-resource authorization on two CLI builds."""
import argparse
import hashlib
import json
import pathlib
import statistics
import subprocess
import tempfile
import time

from report import metadata, revision, toolchain


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--before', required=True, type=pathlib.Path)
    parser.add_argument('--after', required=True, type=pathlib.Path)
    parser.add_argument('--output', required=True, type=pathlib.Path)
    parser.add_argument('--repeat', type=int, default=5)
    parser.add_argument('--scope', choices=('principal', 'resource'), default='principal')
    parser.add_argument('--policies', type=int, default=2048)
    parser.add_argument('--requests', type=int, default=4096)
    parser.add_argument('--before-revision', required=True)
    parser.add_argument('--after-revision', required=True)
    parser.add_argument('--toolchain', required=True)
    args = parser.parse_args()
    args.before_revision = revision(args.before_revision)
    args.after_revision = revision(args.after_revision)
    args.toolchain = toolchain(args.toolchain)
    if args.repeat < 1:
        parser.error('--repeat must be positive')
    if not 1 <= args.policies <= 4096 or not 1 <= args.requests <= 16384:
        parser.error('--policies must be 1..4096 and --requests must be 1..16384')
    engines = {'before': args.before.resolve(), 'after': args.after.resolve()}
    policy_count, request_count = args.policies, args.requests
    target = policy_count // 2
    timings = {name: [] for name in engines}
    with tempfile.TemporaryDirectory(prefix='cedar-principal-') as directory:
        tmp = pathlib.Path(directory)
        policy, entities, requests = [tmp / name for name in ('policy.cedar', 'entities.json', 'requests.json')]
        if args.scope == 'principal':
            policies = ('@id("share-%d") permit(principal == User::"user-%d", action == Action::"read", resource);' % (i, i)
                        for i in range(policy_count))
        else:
            policies = ('@id("share-%d") permit(principal, action == Action::"read", resource == Document::"doc-%d");' % (i, i)
                        for i in range(policy_count))
        policy.write_text('\n'.join(policies), encoding='utf-8')
        entities.write_text('[]', encoding='utf-8')
        request = {'principal': {'type': 'User', 'id': 'user-%d' % target},
                   'action': {'type': 'Action', 'id': 'read'},
                   'resource': {'type': 'Document', 'id': 'doc-%d' % target if args.scope == 'resource' else 'report'}, 'context': {}}
        requests.write_text(json.dumps([request] * request_count, separators=(',', ':')), encoding='utf-8')
        reference = None
        for repeat in range(args.repeat):
            # Alternate order to reduce the effect of changing machine load.
            for name in (('before', 'after') if repeat % 2 == 0 else ('after', 'before')):
                start = time.perf_counter()
                run = subprocess.run([str(engines[name]), 'batch', str(policy), str(entities), str(requests), '--format', 'json'],
                                     capture_output=True, timeout=180)
                elapsed = time.perf_counter() - start
                if run.returncode:
                    raise RuntimeError(run.stderr.decode('utf-8', errors='replace'))
                responses = json.loads(run.stdout)
                if len(responses) != request_count or any(
                    response != {'decision': 'Allow', 'reasons': ['share-%d' % target], 'errors': []}
                    for response in responses
                ):
                    raise RuntimeError('unexpected authorization response')
                digest = hashlib.sha256(run.stdout).hexdigest()
                if reference is not None and reference != digest:
                    raise RuntimeError('outputs differ between benchmark runs')
                reference = digest
                timings[name].append(elapsed)
    result = {
        'command': 'python benchmarks/principal.py --scope <SCOPE> --policies <POLICIES> --requests <REQUESTS> --before <BEFORE> --after <AFTER> --before-revision <BEFORE_REVISION> --after-revision <AFTER_REVISION> --toolchain <TOOLCHAIN> --output <OUTPUT> --repeat <REPEAT>',
        'before_revision': args.before_revision, 'after_revision': args.after_revision,
        'engine_sha256': {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in engines.items()},
        'toolchain': args.toolchain,
        'environment': metadata(),
        'scope': args.scope, 'policies': policy_count, 'requests': request_count, 'entities': 0,
        'matching_policies': 1, 'repeat': args.repeat, 'seed': None,
        'measurement': 'CLI wall time including startup, parsing, evaluation and JSON output; alternated run order',
        'output_sha256': reference,
        'results': {name: {'seconds': values, 'median_seconds': statistics.median(values),
                           'requests_per_second': request_count / statistics.median(values)}
                    for name, values in timings.items()},
    }
    args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
