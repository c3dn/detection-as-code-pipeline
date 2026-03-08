#!/usr/bin/env python3
"""Check for duplicate rule IDs and names across all rule files."""

import sys
import glob
import toml
import yaml
from pathlib import Path
from collections import defaultdict


def load_config():
    config_path = Path(__file__).parent.parent / "_config.yaml"
    with open(config_path, "r") as f:
        return yaml.safe_load(f)


def main():
    config = load_config()
    rule_dirs = config.get("rule_dirs", ["rules"])
    base_dir = Path(__file__).parent.parent

    ids_seen = defaultdict(list)
    names_seen = defaultdict(list)
    errors = []

    for rule_dir in rule_dirs:
        rule_path = base_dir / rule_dir
        rule_files = sorted(glob.glob(str(rule_path / "*.toml")))

        for filepath in rule_files:
            filename = Path(filepath).name
            try:
                data = toml.load(filepath)
                rule = data.get("rule", {})
                rule_id = rule.get("rule_id", "")
                name = rule.get("name", "")
                if rule_id:
                    ids_seen[rule_id].append(filename)
                if name:
                    names_seen[name].append(filename)
            except Exception as e:
                errors.append(f"{filename}: Failed to parse — {e}")

    # Check for duplicate IDs
    for rule_id, files in ids_seen.items():
        if len(files) > 1:
            errors.append(f"Duplicate rule_id '{rule_id}' in: {', '.join(files)}")

    # Check for duplicate names
    for name, files in names_seen.items():
        if len(files) > 1:
            errors.append(f"Duplicate rule name '{name}' in: {', '.join(files)}")

    print(f"\n{'='*60}")
    print(f"Duplicate Check Summary")
    print(f"{'='*60}")
    print(f"Unique rule IDs:  {len(ids_seen)}")
    print(f"Unique names:     {len(names_seen)}")
    print(f"Issues found:     {len(errors)}")

    if errors:
        for err in errors:
            print(f"  ✗ {err}")
        sys.exit(1)
    else:
        print("NO DUPLICATES FOUND ✓")
        sys.exit(0)


if __name__ == "__main__":
    main()
