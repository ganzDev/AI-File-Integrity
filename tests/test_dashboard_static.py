"""Dependency-free packaging checks; run with Python from the project root."""
from pathlib import Path
import ast
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]

class DashboardStaticTests(unittest.TestCase):
    def test_python_syntax(self):
        for rel in ('dashboard/app.py','deployment/afi-admin'):
            ast.parse((ROOT/rel).read_text(encoding='utf-8'),filename=rel)
    def test_service_controls_limited(self):
        source=(ROOT/'deployment/afi-admin').read_text()
        self.assertIn("'monitor': 'ai-file-integrity-monitor.service'",source)
        self.assertIn("'detector': 'ai-file-integrity-detector.service'",source)
        self.assertNotIn('shell=True',source)
        self.assertNotIn('eval(',source)
    def test_frontend_has_no_external_assets(self):
        html=(ROOT/'dashboard/templates/index.html').read_text()
        self.assertNotIn('http://',html)
        self.assertNotIn('https://',html)
        for name in ('overview','findings','investigations','evaluation','events','logs'):
            self.assertIn(f'id="view-{name}"',html)
    def test_js_syntax(self):
        try:
            process=subprocess.run(['node','--check',str(ROOT/'dashboard/static/app.js')],capture_output=True,text=True)
        except FileNotFoundError:
            return
        self.assertEqual(process.returncode,0,process.stderr)

if __name__=='__main__':unittest.main()
