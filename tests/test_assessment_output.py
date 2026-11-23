"""Offline regression tests for the streamlined AI assessment output."""
import ast
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
SRC=(ROOT/'src/ai_investigator.py').read_text(encoding='utf-8')
DASH=(ROOT/'dashboard/static/app.js').read_text(encoding='utf-8')

class AssessmentOutputTests(unittest.TestCase):
    def test_valid_python(self):
        ast.parse(SRC)
    def test_authorization_removed_from_new_schema(self):
        self.assertNotIn('authorization_status', SRC)
    def test_console_shows_recommendations(self):
        self.assertIn('RECOMMENDED ACTIONS', SRC)
        self.assertNotIn('print("EVIDENCE VALIDATION")', SRC)
    def test_validator_still_persisted(self):
        self.assertIn('save_assessment_and_validation(', SRC)
        self.assertIn('"evidence_validation": validation', SRC)
    def test_dashboard_recommendations(self):
        self.assertIn('Recommended actions</h3>', DASH)
if __name__=='__main__': unittest.main()
