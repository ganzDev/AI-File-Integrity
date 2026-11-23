"""Offline checks for the local-only dashboard simulation controls."""
from pathlib import Path
import ast
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
APP = (ROOT / 'dashboard/app.py').read_text(encoding='utf-8')
HELPER = (ROOT / 'deployment/afi-admin').read_text(encoding='utf-8')
PAGE = (ROOT / 'dashboard/templates/index.html').read_text(encoding='utf-8')
JS = (ROOT / 'dashboard/static/app.js').read_text(encoding='utf-8')

class SimulationTabChecks(unittest.TestCase):
    def test_sources_parse(self):
        ast.parse(APP)
        ast.parse(HELPER)

    def test_fixed_scenarios_match_simulator(self):
        expected = ['unauthorized_access','unauthorized_modification','deletion',
                    'permission_change','compromised_account','rapid_modification','process_interaction']
        for name in expected:
            self.assertIn(repr(name), APP)
            self.assertIn(repr(name), HELPER)
        self.assertIn("if scenario not in SIM_SCENARIOS:", APP)
        self.assertIn('if scenario not in scenarios:', HELPER)

    def test_simulator_is_fixed_command(self):
        self.assertIn("str(root / 'src' / 'attack_simulator.py'), '--scenario', scenario", HELPER)
        self.assertNotIn('shell=True', HELPER)
        self.assertIn("for unit in (UNITS['monitor'], UNITS['detector'], UNITS['auditd'])", HELPER)

    def test_ui_confirmation_and_csrf(self):
        self.assertIn('id="view-simulations"', PAGE)
        self.assertIn('data-view="simulations"', PAGE)
        self.assertIn("confirmDialog('Run controlled simulation'", JS)
        self.assertIn("'X-AFI-CSRF'", JS)
        self.assertIn('id="simulationCards"', PAGE)

    def test_simulation_status_is_not_ai_investigation(self):
        self.assertIn("command('simulate', scenario", APP)
        self.assertIn('AI investigations are launched separately', PAGE)

if __name__ == '__main__':
    unittest.main()
