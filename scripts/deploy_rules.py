#!/usr/bin/env python3
"""Deploy validated detection rules to Kibana via the Detection Engine API."""
from __future__ import annotations

import sys
import os
import glob
import time
import toml
import yaml
import requests
from pathlib import Path

# All configuration via environment variables -- set these in GitLab CI/CD Settings
KIBANA_URL = os.environ.get("KIBANA_URL", "http://localhost:5601")
KIBANA_SPACE = os.environ.get("KIBANA_SPACE", "default")
KIBANA_USER = os.environ.get("KIBANA_USER", "elastic")
KIBANA_PASSWORD = os.environ.get("KIBANA_PASSWORD", "")
KIBANA_API_KEY = os.environ.get("KIBANA_API_KEY", "")


def load_config():
    """Load the main _config.yaml."""
    config_path = Path(__file__).parent.parent / "_config.yaml"
    with open(config_path, "r") as f:
        return yaml.safe_load(f)


def get_auth():
    """Return auth tuple or None if using API key."""
    if KIBANA_API_KEY:
        return None
    return (KIBANA_USER, KIBANA_PASSWORD)


def get_headers():
    """Return request headers, including API key if configured."""
    headers = {
        "kbn-xsrf": "true",
        "Content-Type": "application/json",
    }
    if KIBANA_API_KEY:
        headers["Authorization"] = f"ApiKey {KIBANA_API_KEY}"
    return headers


def wait_for_kibana(timeout=120):
    """Wait for Kibana to become available."""
    print(f"Waiting for Kibana at {KIBANA_URL}...")
    start = time.time()
    while time.time() - start < timeout:
        try:
            resp = requests.get(
                f"{KIBANA_URL}/api/status",
                headers=get_headers(),
                auth=get_auth(),
                timeout=5,
            )
            if resp.status_code == 200:
                print("Kibana is ready.")
                return True
        except requests.ConnectionError:
            pass
        time.sleep(5)
    print("ERROR: Kibana did not become available in time.")
    return False


def toml_to_kibana_rule(rule_data: dict) -> dict:
    """Convert a TOML rule definition to Kibana Detection Engine API format."""
    rule = rule_data["rule"]

    kibana_rule = {
        "rule_id": rule["rule_id"],
        "name": rule["name"],
        "description": rule["description"],
        "risk_score": rule["risk_score"],
        "severity": rule["severity"],
        "type": rule["type"],
        "query": rule["query"],
        "tags": rule.get("tags", []),
        "enabled": False,
        "interval": rule.get("interval", "5m"),
        "from": rule.get("from", "now-6m"),
        "language": "eql" if rule["type"] == "eql" else "kuery",
        "index": rule.get("index", ["logs-*", "filebeat-*", "winlogbeat-*"]),
    }

    # Add threat mapping
    threats = rule.get("threat", [])
    if not isinstance(threats, list):
        threats = [threats]
    kibana_threats = []
    for threat in threats:
        t = {
            "framework": threat.get("framework", "MITRE ATT&CK"),
            "tactic": {
                "id": threat["tactic"]["id"],
                "name": threat["tactic"]["name"],
                "reference": threat["tactic"].get("reference", ""),
            },
            "technique": [],
        }
        for technique in threat.get("technique", []):
            tech = {
                "id": technique["id"],
                "name": technique["name"],
                "reference": technique.get("reference", ""),
                "subtechnique": [],
            }
            for sub in technique.get("subtechnique", []):
                tech["subtechnique"].append({
                    "id": sub["id"],
                    "name": sub["name"],
                    "reference": sub.get("reference", ""),
                })
            t["technique"].append(tech)
        kibana_threats.append(t)
    kibana_rule["threat"] = kibana_threats

    return kibana_rule


def get_space_prefix() -> str:
    """Return the URL prefix for the target Kibana space."""
    if KIBANA_SPACE and KIBANA_SPACE != "default":
        return f"/s/{KIBANA_SPACE}"
    return ""


def deploy_rule(kibana_rule: dict) -> tuple[bool, str]:
    """Deploy a single rule to Kibana. Returns (success, message)."""
    auth = get_auth()
    headers = get_headers()
    prefix = get_space_prefix()

    resp = requests.post(
        f"{KIBANA_URL}{prefix}/api/detection_engine/rules",
        headers=headers,
        json=kibana_rule,
        auth=auth,
        timeout=30,
    )

    if resp.status_code == 200:
        return True, "Created"
    elif resp.status_code == 409:
        resp = requests.put(
            f"{KIBANA_URL}{prefix}/api/detection_engine/rules",
            headers=headers,
            json=kibana_rule,
            auth=auth,
            timeout=30,
        )
        if resp.status_code == 200:
            return True, "Updated"
        else:
            return False, f"Update failed ({resp.status_code}): {resp.text}"
    else:
        return False, f"Create failed ({resp.status_code}): {resp.text}"


def main():
    config = load_config()
    rule_dirs = config.get("rule_dirs", ["rules"])
    base_dir = Path(__file__).parent.parent

    space_label = KIBANA_SPACE if KIBANA_SPACE != "default" else "default"
    print(f"Target Kibana space: {space_label}")

    if not wait_for_kibana():
        sys.exit(1)

    deployed = 0
    failed = 0

    for rule_dir in rule_dirs:
        rule_path = base_dir / rule_dir
        rule_files = sorted(glob.glob(str(rule_path / "*.toml")))

        for filepath in rule_files:
            filename = os.path.basename(filepath)
            try:
                rule_data = toml.load(filepath)
                kibana_rule = toml_to_kibana_rule(rule_data)
                success, message = deploy_rule(kibana_rule)
                if success:
                    print(f"  + {filename}: {message} -- {kibana_rule['name']}")
                    deployed += 1
                else:
                    print(f"  x {filename}: {message}")
                    failed += 1
            except Exception as e:
                print(f"  x {filename}: Exception -- {e}")
                failed += 1

    print(f"\n{'='*60}")
    print(f"Deployment Summary")
    print(f"{'='*60}")
    print(f"Deployed:  {deployed}")
    print(f"Failed:    {failed}")

    if failed > 0:
        print(f"\nDEPLOYMENT COMPLETED WITH ERRORS")
        sys.exit(1)
    else:
        print(f"\nALL RULES DEPLOYED SUCCESSFULLY")
        sys.exit(0)


if __name__ == "__main__":
    main()
