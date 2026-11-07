import json
import os
import unittest
from unittest.mock import patch

import report


class ReportMetadataTest(unittest.TestCase):
    def test_local_and_self_hosted_do_not_export_machine_data(self):
        with patch.dict(os.environ, {
            'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'self-hosted',
            'RUNNER_OS': 'Windows', 'RUNNER_ARCH': 'X64',
            'USERNAME': 'private-user', 'HOME': '/private/home',
        }, clear=True):
            value = report.metadata()
        self.assertEqual(value['runner'], {'source': 'local'})
        self.assertNotIn('private', json.dumps(value))
        self.assertEqual(len(value['python'].split('.')), 2)

    def test_hosted_metadata_uses_only_known_fields(self):
        with patch.dict(os.environ, {
            'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted',
            'RUNNER_OS': 'Windows', 'RUNNER_ARCH': 'X64', 'ImageOS': 'win22',
            'GITHUB_REPOSITORY': 'shen-E/cedar-auth-engine', 'GITHUB_RUN_ID': '123',
            'USERNAME': 'private-user', 'GITHUB_WORKSPACE': 'C:/private/home',
        }, clear=True):
            value = report.metadata()
        self.assertEqual(value['runner']['source'], 'github-hosted')
        self.assertEqual(value['runner']['os'], 'Windows')
        self.assertEqual(value['runner']['arch'], 'X64')
        self.assertTrue(value['runner']['run_url'].endswith('/actions/runs/123'))
        self.assertNotIn('private', json.dumps(value))
        self.assertEqual(len(value['python'].split('.')), 3)

    def test_labels_reject_paths_and_arbitrary_environment(self):
        self.assertEqual(report.revision('ABCDEF123'), 'abcdef123')
        self.assertEqual(report.toolchain('moonc 0.10.18+6c83a7f62'), 'moonc 0.10.18+6c83a7f62')
        for bad in ('local build', '/private/home', 'abcdef1; uname'):
            with self.assertRaises(ValueError):
                report.revision(bad)
        for bad in ('/private/toolchain', 'moonc 0.10.18 /private'):
            with self.assertRaises(ValueError):
                report.toolchain(bad)


if __name__ == '__main__':
    unittest.main()
