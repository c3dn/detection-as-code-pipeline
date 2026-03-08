#!/usr/bin/env python3
"""Tests that validate the validator catches errors correctly."""

import os
import sys
import unittest
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
from validate_rules import validate_rule

INVALID_RULES_DIR = Path(__file__).parent / "test_invalid_rules"


class TestValidatorCatchesErrors(unittest.TestCase):
    """Ensure the validator correctly rejects invalid rules."""

    def test_catches_missing_fields(self):
        """Validator should catch rules with missing required fields."""
        filepath = str(INVALID_RULES_DIR / "invalid_missing_fields.toml")
        errors = validate_rule(filepath)
        self.assertGreater(len(errors), 0, "Should detect missing fields")
        # Should catch missing metadata fields
        field_errors = [e for e in errors if "Missing" in e]
        self.assertGreater(len(field_errors), 0, "Should specifically mention missing fields")

    def test_catches_bad_severity(self):
        """Validator should catch invalid severity values."""
        filepath = str(INVALID_RULES_DIR / "invalid_bad_severity.toml")
        errors = validate_rule(filepath)
        severity_errors = [e for e in errors if "severity" in e.lower()]
        self.assertGreater(len(severity_errors), 0, "Should catch invalid severity")

    def test_catches_bad_risk_score(self):
        """Validator should catch risk_score outside 0-100 range."""
        filepath = str(INVALID_RULES_DIR / "invalid_risk_score.toml")
        errors = validate_rule(filepath)
        score_errors = [e for e in errors if "risk_score" in e.lower()]
        self.assertGreater(len(score_errors), 0, "Should catch risk_score > 100")

    def test_valid_rules_pass(self):
        """Valid rules should produce no errors."""
        rules_dir = Path(__file__).parent.parent / "rules"
        for filepath in sorted(rules_dir.glob("*.toml")):
            errors = validate_rule(str(filepath))
            self.assertEqual(len(errors), 0, f"{filepath.name} should be valid but got: {errors}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
