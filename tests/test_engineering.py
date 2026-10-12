import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

MODULE = Path(__file__).resolve().parents[1] / 'engineering' / 'check.py'
spec = importlib.util.spec_from_file_location('engineering_check', MODULE)
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


class EvidenceTests(unittest.TestCase):
    def test_inventory_includes_hidden_files_and_excludes_dependency_tree(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / '.env').write_text('secret-value-never-read')
            (root / 'node_modules').mkdir()
            (root / 'node_modules' / 'ignored.js').write_text('')
            (root / 'file.txt').write_text('hi')
            listing = check.inventory(root)
            self.assertEqual([f['path'] for f in listing['files']], ['.env', 'file.txt'])
            self.assertEqual(listing['excluded'], ['node_modules'])
            self.assertNotIn('secret-value', json.dumps(listing))

    def test_symlink_directory_not_traversed(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'loop').symlink_to(root, target_is_directory=True)
            self.assertEqual(check.inventory(root)['excluded'], ['loop'])

    def test_shell_string_and_invalid_timeouts_rejected(self):
        for command, timeout in [('echo test', 1), (['echo'], 0), (['echo'], True), ([], 1)]:
            with self.assertRaises(ValueError):
                check.validate_gates({'gates': [{'name': 'test', 'command': command,
                                                 'timeout_seconds': timeout}]})

    def test_duplicate_gates_rejected(self):
        gate = {'name': 'test', 'command': ['echo']}
        with self.assertRaises(ValueError):
            check.validate_gates({'gates': [gate, gate]})

    def test_audit_never_executes_gates(self):
        with tempfile.TemporaryDirectory() as folder:
            gate = {'name': 'test', 'command': ['{python}', '-c', 'raise RuntimeError()']}
            self.assertEqual(check.run_gate(gate, Path(folder))['status'], 'not_run')

    def test_gate_exit_failure_and_missing_executable(self):
        with tempfile.TemporaryDirectory() as folder:
            for code, status in [(0, 'passed'), (7, 'failed')]:
                gate = {'name': 'test', 'command': ['{python}', '-c', f'raise SystemExit({code})']}
                result = check.run_gate(gate, Path(folder), True)
                self.assertEqual((result['status'], result['exit_code']), (status, code))
            result = check.run_gate({'name': 'missing', 'command': ['/missing/aegis-executable']}, Path(folder), True)
            self.assertEqual(result['status'], 'blocked')

    def test_timeout_stops_process(self):
        with tempfile.TemporaryDirectory() as folder:
            gate = {'name': 'slow', 'command': ['{python}', '-c', 'import time;time.sleep(10)'],
                    'timeout_seconds': .05}
            self.assertEqual(check.run_gate(gate, Path(folder), True)['status'], 'timeout')

    def test_credentials_not_inherited_and_output_discarded(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as folder, patch.dict('os.environ', {'AEGIS_SECRET': 'test-secret'}):
            gate = {'name': 'env', 'command': ['{python}', '-c',
                    "import os;assert 'AEGIS_SECRET' not in os.environ;print('test-secret')"]}
            result = check.run_gate(gate, Path(folder), True)
            self.assertEqual(result['status'], 'passed')
            self.assertNotIn('test-secret', json.dumps(result))

    def test_html_embedded_data_cannot_close_script(self):
        html = check.render({'path': '</script><img src=x onerror=alert(1)>'}, '__REPORT_JSON__')
        self.assertNotIn('<', html)
        self.assertEqual(json.loads(html)['path'], '</script><img src=x onerror=alert(1)>')

    def test_report_history_and_gate_failure_exit(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            (root / 'engineering').mkdir()
            (root / 'engineering' / 'gates.json').write_text(json.dumps({'gates': [
                {'name': 'failing', 'command': ['{python}', '-c', 'raise SystemExit(1)']}]}))
            output = root / '.engineering' / 'reports'
            self.assertEqual(check.main(['--root', str(root), '--output', str(output), '--run-gates']), 1)
            first = json.loads((output / 'latest.json').read_text())
            self.assertEqual(first['gates'][0]['status'], 'failed')
            self.assertTrue((output / 'index.html').exists())
            self.assertEqual(check.main(['--root', str(root), '--output', str(output)]), 0)
            second = json.loads((output / 'latest.json').read_text())
            self.assertEqual(second['gates'][0]['status'], 'not_run')
            self.assertEqual(len(list(output.glob('*Z.json'))), 2)

    def test_execution_without_gates_fails_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            self.assertEqual(check.main(['--root', folder, '--run-gates']), 2)

    def test_symlink_gate_config_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            (root / 'engineering').mkdir()
            (root / 'outside.json').write_text('{"gates": []}')
            (root / 'engineering' / 'gates.json').symlink_to(root / 'outside.json')
            self.assertEqual(check.main(['--root', str(root)]), 2)

    def test_test_runner_rejects_empty_suite(self):
        import subprocess
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder) / 'tests').mkdir()
            result = subprocess.run([sys.executable, str(MODULE.parent / 'run_tests.py')],
                                    cwd=folder, capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn('No tests discovered', result.stderr)

    def test_output_symlinks_cannot_overwrite_external_files(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            sentinel = root / 'sentinel'
            sentinel.write_text('keep')
            output = root / 'reports'
            output.mkdir()
            (output / 'latest.json').symlink_to(sentinel)
            self.assertEqual(check.main(['--root', str(root), '--output', str(output)]), 2)
            self.assertEqual(sentinel.read_text(), 'keep')
            (root / 'linked').symlink_to(output, target_is_directory=True)
            with self.assertRaises(ValueError):
                check.report_directory(root / 'linked' / 'new', root)

    def test_output_outside_root_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            with self.assertRaises(ValueError):
                check.report_directory(root.parent / 'outside', root)

    def test_output_hardlink_replaced_without_modifying_original(self):
        import os
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            sentinel = root / 'original'
            sentinel.write_text('keep')
            os.link(sentinel, root / 'latest.json')
            check.write_report(root, 'latest.json', 'new')
            self.assertEqual(sentinel.read_text(), 'keep')

    def test_custom_report_directory_excluded_from_inventory(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            output = root / 'reports'
            output.mkdir()
            (output / 'latest.json').write_text('{}')
            self.assertEqual(check.inventory(root, output)['files'], [])

    @unittest.skipUnless(sys.platform in ('darwin', 'linux'), 'POSIX signals required')
    def test_interruption_terminates_gate_process(self):
        import signal
        import subprocess
        from unittest.mock import patch
        real_popen, children = subprocess.Popen, []
        def start(*args, **kwargs):
            child = real_popen(*args, **kwargs)
            children.append(child)
            return child
        def interrupt(*args):
            raise KeyboardInterrupt()
        old = signal.signal(signal.SIGALRM, interrupt)
        try:
            with tempfile.TemporaryDirectory() as folder, patch.object(check.subprocess, 'Popen', start):
                signal.setitimer(signal.ITIMER_REAL, .05)
                with self.assertRaises(KeyboardInterrupt):
                    check.run_gate({'name': 'sleep', 'command': ['{python}', '-c',
                                   'import time;time.sleep(10)']}, Path(folder), True)
                self.assertIsNotNone(children[0].poll())
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, old)

    @unittest.skipUnless(sys.platform in ('darwin', 'linux'), 'POSIX process groups required')
    def test_group_cleanup_when_leader_already_exited(self):
        import signal
        import subprocess
        from unittest.mock import patch
        gate = {'name': 'quick', 'command': ['{python}', '-c', 'pass']}
        with tempfile.TemporaryDirectory() as folder, patch.object(check.os, 'killpg', wraps=check.os.killpg) as kill:
            result = check.run_gate(gate, Path(folder), True)
            self.assertEqual(result['status'], 'passed')
            kill.assert_called_once()
            self.assertEqual(kill.call_args.args[1], signal.SIGKILL)


if __name__ == '__main__':
    unittest.main()
