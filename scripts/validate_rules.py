#!/usr/bin/env python3
"""Validate detection rule TOML files against the expected schema."""
from __future__ import annotations

import sys
import os
import glob
import toml
import yaml
from pathlib import Path

REQUIRED_METADATA = ["creation_date", "updated_date", "maturity", "min_stack_version"]
REQUIRED_RULE_FIELDS = ["name", "rule_id", "description", "risk_score", "severity", "type", "query", "tags"]
VALID_SEVERITIES = ["low", "medium", "high", "critical"]
VALID_TYPES = ["query", "eql", "threshold", "machine_learning", "threat_match", "new_terms", "esql"]
VALID_MATURITIES = ["development", "experimental", "beta", "production", "deprecated"]


def load_config():
    """Load the main _config.yaml."""
    config_path = Path(__file__).parent.parent / "_config.yaml"
    with open(config_path, "r") as f:
        return yaml.safe_load(f)


def validate_rule(filepath: str) -> list[str]:
    """Validate a single rule file. Returns list of error strings."""
    errors = []
    filename = os.path.basename(filepath)

    if not filepath.endswith(".toml"):
        errors.append(f"{filename}: Rule file must have .toml extension")
        return errors

    stem = Path(filepath).stem
    if stem != stem.lower():
        errors.append(f"{filename}: Filename must be lowercase")
    if " " in stem:
        errors.append(f"{filename}: Filename must not contain spaces")

    try:
        rule_data = toml.load(filepath)
    except toml.TomlDecodeError as e:
        errors.append(f"{filename}: Invalid TOML syntax -- {e}")
        return errors

    # Check metadata section
    metadata = rule_data.get("metadata")
    if not metadata:
        errors.append(f"{filename}: Missing [metadata] section")
    else:
        for field in REQUIRED_METADATA:
            if field not in metadata:
                errors.append(f"{filename}: Missing metadata.{field}")
        maturity = metadata.get("maturity", "")
        if maturity and maturity not in VALID_MATURITIES:
            errors.append(f"{filename}: Invalid maturity '{maturity}', must be one of {VALID_MATURITIES}")

    # Check rule section
    rule = rule_data.get("rule")
    if not rule:
        errors.append(f"{filename}: Missing [rule] section")
        return errors

    for field in REQUIRED_RULE_FIELDS:
        if field not in rule:
            errors.append(f"{filename}: Missing rule.{field}")

    severity = rule.get("severity", "")
    if severity and severity not in VALID_SEVERITIES:
        errors.append(f"{filename}: Invalid severity '{severity}', must be one of {VALID_SEVERITIES}")

    rule_type = rule.get("type", "")
    if rule_type and rule_type not in VALID_TYPES:
        errors.append(f"{filename}: Invalid rule type '{rule_type}', must be one of {VALID_TYPES}")

    risk_score = rule.get("risk_score")
    if risk_score is not None:
        if not isinstance(risk_score, (int, float)) or risk_score < 0 or risk_score > 100:
            errors.append(f"{filename}: risk_score must be between 0 and 100, got {risk_score}")

    tags = rule.get("tags")
    if tags is not None and (not isinstance(tags, list) or len(tags) == 0):
        errors.append(f"{filename}: tags must be a non-empty list")

    query = rule.get("query", "").strip()
    if not query:
        errors.append(f"{filename}: query must not be empty")

    # Severity <-> risk_score consistency (Elastic ranges)
    severity = rule.get("severity", "")
    risk_score = rule.get("risk_score")
    if severity and risk_score is not None:
        expected_ranges = {
            "low": (0, 21),
            "medium": (22, 47),
            "high": (48, 73),
            "critical": (74, 100),
        }
        if severity in expected_ranges:
            lo, hi = expected_ranges[severity]
            if not (lo <= risk_score <= hi):
                errors.append(
                    f"{filename}: risk_score {risk_score} does not match severity "
                    f"'{severity}' (expected {lo}-{hi})"
                )

    # EQL rules must contain EQL keywords
    if rule_type == "eql" and query:
        eql_keywords = ["where", "sequence", "any where", "process where", "file where",
                        "network where", "registry where", "dns where"]
        if not any(kw in query.lower() for kw in eql_keywords):
            errors.append(
                f"{filename}: type is 'eql' but query doesn't contain EQL keywords "
                f"(where, sequence, etc.)"
            )

    # MITRE ATT&CK threat mapping
    threats = rule.get("threat", [])
    if not isinstance(threats, list):
        threats = [threats]
    for i, threat in enumerate(threats):
        if "framework" not in threat:
            errors.append(f"{filename}: threat[{i}] missing framework")
        tactic = threat.get("tactic", {})
        if not tactic.get("id") or not tactic.get("name"):
            errors.append(f"{filename}: threat[{i}].tactic missing id or name")
        techniques = threat.get("technique", [])
        if not techniques:
            errors.append(
                f"{filename}: threat[{i}] has tactic but no techniques"
            )
        for j, technique in enumerate(techniques):
            if not technique.get("id") or not technique.get("name"):
                errors.append(f"{filename}: threat[{i}].technique[{j}] missing id or name")

    return errors


def main():
    config = load_config()
    rule_dirs = config.get("rule_dirs", ["rules"])
    base_dir = Path(__file__).parent.parent

    all_errors = []
    rule_count = 0

    for rule_dir in rule_dirs:
        rule_path = base_dir / rule_dir
        rule_files = sorted(glob.glob(str(rule_path / "*.toml")))

        if not rule_files:
            print(f"WARNING: No rule files found in {rule_path}")
            continue

        for filepath in rule_files:
            rule_count += 1
            errors = validate_rule(filepath)
            if errors:
                all_errors.extend(errors)

    print(f"\n{'='*60}")
    print(f"Rule Validation Summary")
    print(f"{'='*60}")
    print(f"Rules scanned:  {rule_count}")
    print(f"Errors found:   {len(all_errors)}")

    if all_errors:
        print(f"\nErrors:")
        for err in all_errors:
            print(f"  x {err}")
        print(f"\n{'='*60}")
        print("VALIDATION FAILED")
        sys.exit(1)
    else:
        print(f"\n{'='*60}")
        print("ALL RULES VALID")
        sys.exit(0)


if __name__ == "__main__":
    main()
