#!/usr/bin/env python3
"""Unit tests for detection rule files."""

import glob
import os
import re
import unittest
import toml
import yaml
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent
CONFIG_PATH = BASE_DIR / "_config.yaml"

with open(CONFIG_PATH, "r") as f:
    CONFIG = yaml.safe_load(f)

# Load test config for skips
TEST_CONFIG_PATH = BASE_DIR / CONFIG["files"]["test_config"]
with open(TEST_CONFIG_PATH, "r") as f:
    TEST_CONFIG = yaml.safe_load(f)
SKIPS = TEST_CONFIG.get("skips", [])


def get_all_rules():
    """Load all rule files."""
    rules = []
    for rule_dir in CONFIG.get("rule_dirs", ["rules"]):
        rule_path = BASE_DIR / rule_dir
        for filepath in sorted(glob.glob(str(rule_path / "*.toml"))):
            data = toml.load(filepath)
            rules.append((filepath, data))
    return rules


RULES = get_all_rules()


class TestRuleFiles(unittest.TestCase):
    """Test each rule file for correctness."""

    def test_all_rules_parse(self):
        """Every .toml in rules/ must parse without errors."""
        for filepath, data in RULES:
            self.assertIn("rule", data, f"{filepath} missing [rule] section")
            self.assertIn("metadata", data, f"{filepath} missing [metadata] section")

    def test_rule_has_required_fields(self):
        """Every rule must have all required fields."""
        required = ["name", "rule_id", "description", "risk_score", "severity", "type", "query"]
        for filepath, data in RULES:
            rule = data["rule"]
            for field in required:
                self.assertIn(field, rule, f"{Path(filepath).name} missing rule.{field}")

    def test_rule_id_format(self):
        """rule_id must be a valid UUID-like string."""
        pattern = re.compile(r"^[a-zA-Z0-9\]\[]{8}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{12}$")
        for filepath, data in RULES:
            rule_id = data["rule"].get("rule_id", "")
            self.assertTrue(
                pattern.match(rule_id),
                f"{Path(filepath).name}: rule_id '{rule_id}' is not a valid format"
            )

    def test_risk_score_range(self):
        """risk_score must be between 0 and 100."""
        for filepath, data in RULES:
            score = data["rule"].get("risk_score", 0)
            self.assertGreaterEqual(score, 0, f"{Path(filepath).name}: risk_score < 0")
            self.assertLessEqual(score, 100, f"{Path(filepath).name}: risk_score > 100")

    def test_severity_values(self):
        """severity must be one of the valid values."""
        valid = {"low", "medium", "high", "critical"}
        for filepath, data in RULES:
            severity = data["rule"].get("severity", "")
            self.assertIn(severity, valid, f"{Path(filepath).name}: invalid severity '{severity}'")

    def test_rule_type_values(self):
        """type must be one of the valid Elastic rule types."""
        valid = {"query", "eql", "threshold", "machine_learning", "threat_match", "new_terms", "esql"}
        for filepath, data in RULES:
            rule_type = data["rule"].get("type", "")
            self.assertIn(rule_type, valid, f"{Path(filepath).name}: invalid type '{rule_type}'")

    def test_tags_non_empty(self):
        """Every rule must have at least one tag."""
        for filepath, data in RULES:
            tags = data["rule"].get("tags", [])
            self.assertGreater(len(tags), 0, f"{Path(filepath).name}: tags must not be empty")

    def test_mitre_threat_mapping(self):
        """Every rule must have at least one MITRE ATT&CK threat mapping."""
        for filepath, data in RULES:
            threats = data["rule"].get("threat", [])
            if not isinstance(threats, list):
                threats = [threats]
            self.assertGreater(
                len(threats), 0,
                f"{Path(filepath).name}: must have at least one threat mapping"
            )
            for threat in threats:
                self.assertIn("tactic", threat, f"{Path(filepath).name}: threat missing tactic")

    @unittest.skipIf(
        "tests.test_all_rules.TestRuleFiles.test_rule_file_name_tactic" in SKIPS,
        "Skipped via test_config.yaml"
    )
    def test_rule_file_name_tactic(self):
        """Rule filename should hint at the tactic (informational)."""
        for filepath, data in RULES:
            # Soft check — just ensure filename is descriptive
            stem = Path(filepath).stem
            self.assertGreater(len(stem), 5, f"{stem}: filename too short to be descriptive")

    def test_no_duplicate_rule_ids(self):
        """No two rules should share the same rule_id."""
        ids = [data["rule"]["rule_id"] for _, data in RULES]
        self.assertEqual(len(ids), len(set(ids)), "Duplicate rule_ids found")

    def test_no_duplicate_rule_names(self):
        """No two rules should share the same name."""
        names = [data["rule"]["name"] for _, data in RULES]
        self.assertEqual(len(names), len(set(names)), "Duplicate rule names found")

    def test_query_not_empty(self):
        """Every rule query must contain actual content."""
        for filepath, data in RULES:
            query = data["rule"].get("query", "").strip()
            self.assertGreater(
                len(query), 10,
                f"{Path(filepath).name}: query is too short or empty"
            )

    def test_severity_risk_score_consistency(self):
        """severity and risk_score must be in the same Elastic range."""
        ranges = {
            "low": (0, 21),
            "medium": (22, 47),
            "high": (48, 73),
            "critical": (74, 100),
        }
        for filepath, data in RULES:
            rule = data["rule"]
            sev = rule.get("severity", "")
            score = rule.get("risk_score", 0)
            if sev in ranges:
                lo, hi = ranges[sev]
                self.assertTrue(
                    lo <= score <= hi,
                    f"{Path(filepath).name}: risk_score {score} doesn't match "
                    f"severity '{sev}' (expected {lo}–{hi})"
                )

    def test_eql_rules_have_eql_syntax(self):
        """EQL-typed rules must contain EQL keywords like 'where' or 'sequence'."""
        eql_keywords = ["where", "sequence"]
        for filepath, data in RULES:
            rule = data["rule"]
            if rule.get("type") == "eql":
                query = rule.get("query", "").lower()
                self.assertTrue(
                    any(kw in query for kw in eql_keywords),
                    f"{Path(filepath).name}: type is 'eql' but query has no EQL keywords"
                )

    def test_threat_has_techniques(self):
        """Each threat mapping should have at least one technique."""
        for filepath, data in RULES:
            threats = data["rule"].get("threat", [])
            if not isinstance(threats, list):
                threats = [threats]
            for i, threat in enumerate(threats):
                techniques = threat.get("technique", [])
                self.assertGreater(
                    len(techniques), 0,
                    f"{Path(filepath).name}: threat[{i}] has tactic but no techniques"
                )

    def test_min_stack_version(self):
        """min_stack_version must match a known version in stack-schema-map."""
        schema_map_path = BASE_DIR / CONFIG["files"]["stack_schema_map"]
        with open(schema_map_path, "r") as f:
            schema_map = yaml.safe_load(f)
        known_versions = set(schema_map.keys()) if schema_map else set()

        for filepath, data in RULES:
            version = data["metadata"].get("min_stack_version", "")
            if version and known_versions:
                self.assertIn(
                    version, known_versions,
                    f"{Path(filepath).name}: min_stack_version '{version}' not in stack-schema-map"
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
