# Detection-as-Code Pipeline

GitLab CI/CD pipeline for managing Elastic Security detection rules as code. Rules are versioned as TOML files in Git, validated on every push, and deployed to Kibana via the Detection Engine API.

```
┌──────────────────────────────────────────────────────────────┐
│  STAGE 1 -- VALIDATE                                         │
│  ┌──────────────────────────┐  ┌──────────────────────────┐  │
│  │  validate-rules          │  │  check-duplicates        │  │
│  │  Schema & syntax check   │  │  Duplicate ID/name check │  │
│  └──────────────────────────┘  └──────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│  STAGE 2 -- TEST                                             │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  unit-tests                                            │  │
│  │  pytest: field checks, MITRE mapping, severity ranges  │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│  STAGE 3 -- DEPLOY                                           │
│  ┌──────────────────────────┐  ┌──────────────────────────┐  │
│  │  deploy-dev              │  │  deploy-prod             │  │
│  │  Auto on every push      │  │  Manual, main only       │  │
│  └──────────────────────────┘  └──────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### 1. Clone & configure

```bash
git clone <this-repo>
cd ci_pipeline
cp .env.example .env   # edit with your Kibana URL and credentials
```

### 2. Set GitLab CI/CD variables

Go to **Settings > CI/CD > Variables** and add:

| Variable | Value | Flags |
|----------|-------|-------|
| `KIBANA_URL` | `https://your-kibana:5601` | Protected, Masked |
| `KIBANA_API_KEY` | Your Kibana API key | Protected, Masked |

Or use basic auth instead of an API key:

| Variable | Value | Flags |
|----------|-------|-------|
| `KIBANA_USER` | `elastic` | Protected |
| `KIBANA_PASSWORD` | Your password | Protected, Masked |

### 3. Add your rules

Copy `rules/_example_rule.toml`, rename it, and fill in your detection logic. Each rule must have:

- `[metadata]` -- creation_date, updated_date, maturity, min_stack_version
- `[rule]` -- name, rule_id (UUID), description, risk_score, severity, type, query, tags
- `[[rule.threat]]` -- at least one MITRE ATT&CK tactic + technique

### 4. Push & deploy

```bash
git add rules/my_new_rule.toml
git commit -m "Add my new detection rule"
git push
```

The pipeline validates, tests, and deploys to the Dev space automatically. Production deploy requires manual approval on `main`.

---

## Project Structure

```
.
├── .gitlab-ci.yml              # Pipeline definition (validate → test → deploy)
├── _config.yaml                # Rule directories and file references
├── requirements.txt            # Python dependencies
├── .env.example                # Environment variable template
│
├── rules/                      # Detection rules (TOML)
│   ├── _example_rule.toml      # Template -- copy this to create new rules
│   ├── windows_credential_dumping_lsass.toml
│   ├── linux_reverse_shell_detection.toml
│   └── network_dns_tunneling.toml
│
├── scripts/
│   ├── validate_rules.py       # Schema & syntax validation
│   ├── check_duplicates.py     # Duplicate rule ID/name detection
│   └── deploy_rules.py         # Deploy rules to Kibana via API
│
├── tests/
│   ├── test_all_rules.py       # Unit tests for all rules
│   ├── test_validation_errors.py  # Tests that validator catches bad rules
│   └── test_invalid_rules/     # Intentionally broken rules for testing
│
└── etc/
    ├── stack-schema-map.yaml   # Supported Elastic Stack versions
    └── test_config.yaml        # Test skip configuration
```

---

## What Gets Validated

The pipeline catches these errors before rules reach production:

| Check | Source | Blocks deploy? |
|-------|--------|---------------|
| Invalid TOML syntax | `validate_rules.py` | Yes |
| Missing required fields (name, rule_id, severity, query, etc.) | `validate_rules.py` | Yes |
| Missing metadata fields (creation_date, updated_date, maturity, min_stack_version) | `validate_rules.py` | Yes |
| Invalid severity (must be low/medium/high/critical) | `validate_rules.py` | Yes |
| Invalid maturity (must be development/experimental/beta/production/deprecated) | `validate_rules.py` | Yes |
| Invalid rule type | `validate_rules.py` | Yes |
| risk_score outside 0-100 | `validate_rules.py` | Yes |
| risk_score / severity mismatch (e.g. `high` with score 20) | `validate_rules.py` | Yes |
| EQL rule without EQL keywords (`where`, `sequence`) | `validate_rules.py` | Yes |
| Missing MITRE ATT&CK framework, tactic, or technique | `validate_rules.py` | Yes |
| Index patterns don't match OS tags (e.g. Windows index but Linux tag) | `validate_rules.py` | Yes |
| Filename not lowercase or contains spaces | `validate_rules.py` | Yes |
| Empty query | `validate_rules.py` | Yes |
| Empty tags list | `validate_rules.py` | Yes |
| Duplicate rule IDs or names across all rules | `check_duplicates.py` | Yes |
| rule_id not in UUID format | `test_all_rules.py` | Yes |
| min_stack_version not in stack-schema-map | `test_all_rules.py` | Yes |
| Query too short (< 10 chars) | `test_all_rules.py` | Yes |

---

## Kibana Spaces

The pipeline uses two Kibana spaces:

- **Dev** -- rules deploy here automatically on every push. Use this for testing.
- **Prod** -- manual deploy gate, only available on the `main` branch.

The `KIBANA_SPACE` variable is set per job in `.gitlab-ci.yml`. The deploy script prepends `/s/{space}` to all API calls automatically.

Rules are deployed **disabled** by default with a 5-minute interval and 6-minute lookback window. Enable them manually in Kibana after reviewing.

---

## Rule Format

Rules follow the Elastic detection-rules TOML format. See `rules/_example_rule.toml` for a complete template.

**Filename conventions:**
- Lowercase only, no spaces: `my_detection_rule.toml`
- Must be `.toml` extension

**Required fields:**

| Section | Fields |
|---------|--------|
| `[metadata]` | `creation_date`, `updated_date`, `maturity`, `min_stack_version` |
| `[rule]` | `name`, `rule_id`, `description`, `risk_score`, `severity`, `type`, `query`, `tags` |
| `[[rule.threat]]` | `framework`, `tactic.id`, `tactic.name`, at least one `technique` |

**`rule_id`** must be a UUID (e.g. `a1b2c3d4-e5f6-7890-abcd-ef1234567890`).

**Severity / risk_score ranges (Elastic standard):**

| Severity | risk_score |
|----------|-----------|
| low | 0 - 21 |
| medium | 22 - 47 |
| high | 48 - 73 |
| critical | 74 - 100 |

**Maturity values:** `development`, `experimental`, `beta`, `production`, `deprecated`

**Supported rule types:** `query`, `eql`, `threshold`, `machine_learning`, `threat_match`, `new_terms`, `esql`

---

## Authentication

The deploy script supports two authentication methods:

**API Key (recommended):**
Set `KIBANA_API_KEY` in CI/CD variables. The script sends it as `Authorization: ApiKey <key>`.

**Basic Auth:**
Set `KIBANA_USER` and `KIBANA_PASSWORD`. The script uses HTTP basic auth.

If both are set, API key takes precedence.

---

## Local Development

```bash
pip install -r requirements.txt

# Validate all rules
python scripts/validate_rules.py

# Check for duplicates
python scripts/check_duplicates.py

# Run unit tests
python -m pytest tests/ -v
```

---

## Configuration Files

**`_config.yaml`** -- Main config. Points to the `rules/` directory and references files in `etc/`. Normally you don't need to change this unless you want multiple rule directories.

**`etc/stack-schema-map.yaml`** -- Lists known Elastic Stack versions. When a rule sets `min_stack_version = "9.3.1"`, the pipeline checks that `9.3.1` exists in this file. Add your version if it's missing:

```yaml
"8.17.0":
  beats: {}
  ecs: {}
  endgame: {}
```

**`etc/test_config.yaml`** -- Lists test methods to skip. Currently skips the filename-tactic check (informational only).

---

## Example Rules

The repo ships with 3 working detection rules you can use as reference:

| Rule | Type | Severity | MITRE Tactic |
|------|------|----------|-------------|
| Credential Dumping via LSASS Memory Access | EQL | high (73) | Credential Access (T1003.001) |
| Potential Reverse Shell via Netcat | EQL | medium (47) | Execution (T1059.004) |
| Potential DNS Tunneling Activity | KQL | low (21) | Exfiltration (T1048) |

Delete or replace these with your own rules. Keep `_example_rule.toml` as a template reference.

---

## Requirements

| Component | Version |
|-----------|---------|
| Python | 3.8+ |
| GitLab Runner | Docker executor with `python:3.12-slim` |
| Elastic Stack | 8.x or 9.x |
| Kibana | API access with Detection Engine permissions |
