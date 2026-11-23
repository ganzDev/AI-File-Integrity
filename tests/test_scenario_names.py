"""Local, unprivileged regression tests for the revised scenario simulator."""
import importlib.util
import pathlib
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

SRC = pathlib.Path(__file__).resolve().parents[1] / 'src' / 'attack_simulator.py'
spec = importlib.util.spec_from_file_location('afi_simulator', SRC)
sim = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sim)


class ScenarioNameTests(unittest.TestCase):
    def test_seven_existing_scenarios_preserved(self):
        self.assertEqual(set(sim.SCENARIOS), set(sim.SCENARIO_FOLDERS))
        self.assertEqual(len(sim.SCENARIOS), 7)

    def test_realistic_document_names_not_run_labels(self):
        for filenames in (sim.DELETION_DOCUMENTS,
                          sim.RAPID_MODIFICATION_DOCUMENTS,
                          sim.PROCESS_DOCUMENTS):
            self.assertEqual(len(filenames), 5)
            self.assertEqual(len(set(filenames)), 5)
            for name in filenames:
                self.assertTrue(name.endswith('.txt'))
                self.assertNotIn('test', name)
                self.assertNotIn('delete_', name)
                self.assertNotIn('rapid_', name)
                self.assertNotIn('process_', name)

    def test_unique_isolated_directories(self):
        with tempfile.TemporaryDirectory() as td, \
                patch.object(sim, 'FINANCE', pathlib.Path(td)), \
                patch.object(sim.grp, 'getgrnam', return_value=types.SimpleNamespace(gr_gid=1001)), \
                patch.object(sim.pwd, 'getpwnam', return_value=types.SimpleNamespace(pw_uid=1001)), \
                patch.object(sim.os, 'chown'):
            first = sim.prepare_directory('deletion')
            second = sim.prepare_directory('deletion')
            self.assertNotEqual(first, second)
            self.assertIn('quarterly_reports', str(first))
            self.assertNotIn('d3_tests', str(first))
            self.assertTrue(first.is_dir())

    def test_three_finance_scenarios_execute_as_unprivileged_test(self):
        def simulate_python(code, *args):
            return subprocess.run([sys.executable, '-c', code, *map(str, args)],
                                  capture_output=True, text=True, timeout=10)
        with tempfile.TemporaryDirectory() as td, patch.object(sim, 'run_python', simulate_python):
            for fn in (sim.deletion, sim.rapid_modification, sim.process_interaction,
                       sim.permission_change):
                directory = pathlib.Path(td) / fn.__name__
                directory.mkdir()
                passed, result = fn(directory)
                self.assertTrue(passed, f'{fn.__name__}: {result.stderr}')
            self.assertEqual(len(list((pathlib.Path(td) / 'deletion').iterdir())), 0)
            self.assertEqual(len(list((pathlib.Path(td) / 'rapid_modification').iterdir())), 5)
            self.assertEqual(len(list((pathlib.Path(td) / 'process_interaction').iterdir())), 5)
            self.assertEqual((pathlib.Path(td) / 'permission_change' / 'budget_summary.txt').stat().st_mode & 0o777, 0o666)

if __name__ == '__main__':
    unittest.main()
