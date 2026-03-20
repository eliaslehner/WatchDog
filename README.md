# WatchDog

A GitLab Duo agent that scans for leaked credentials, client-side secret exposure, and security misconfigurations before deployment. Uses Claude for contextual reasoning about whether findings are actually exploitable.

---

## Problem

Secret scanners pattern-match strings in git commits. They don't understand context. A `DATABASE_URL` in a server file is fine — until a bad import pulls it into a public JS bundle. WatchDog catches that by reasoning about the framework, the file's role, and the deployment target.

## What gets scanned

| Area | What's checked |
|---|---|
| Hardcoded secrets | API keys, tokens, passwords in source or comments |
| Client-side exposure | Server secrets bundled into frontend JS by build tools |
| Env variable flow | Traces vars from definition to usage to browser reachability |
| Debug flags | `DEBUG=True`, `NODE_ENV=development`, verbose errors in prod |
| CORS & headers | Wildcard origins, missing security headers, permissive configs |
| IaC | Terraform, Pulumi, k8s manifests, docker-compose for hardcoded creds |
| Dependencies | Known CVEs, unpinned deps |
| Build artifacts | Scans compiled output — where real leaks hide |

## Severity levels

- **Critical** — pipeline blocked, deploy halted
- **Warning** — MR comment with the exploit path explained
- **Info** — logged in the report, does not block
- **Auto-fix** — for common issues, WatchDog opens a remediation MR

---

## Architecture

```
Push to main / pipeline trigger
        |
        v
+---------------------+
|  Orchestrator Agent  |  <- GitLab Duo Flow
+---------+-----------+
          | spawns
    +-----+------+
    |            |
    v            v
Sub-agents (parallel)
+-- secret-scanner
+-- client-exposure-analyzer
+-- env-flow-tracer
+-- config-flag-checker
+-- iac-scanner
+-- dependency-checker
+-- artifact-inspector
          |
          v
+---------------------+
|   Claude reasoning   |  <- Anthropic API via GitLab
|   (exploitability    |
|    analysis)         |
+---------+-----------+
          |
    +-----+----------------+
    |                      |
    v                      v
Block pipeline       MR comment +
                     remediation MR
```

---

## Local development

Everything works locally without GitLab access.

### Requirements

- Python 3.11+
- Node.js 18+ (for build artifact scanning)
- Git
- Anthropic API key (https://console.anthropic.com)

### Setup

```bash
git clone https://github.com/YOUR_USERNAME/watchdog.git
cd watchdog

python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

pip install -r requirements.txt

cp .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY
```

### Run a scan

```bash
# Scan a local project directory
python watchdog.py scan ./path/to/your/project

# Specify framework (auto-detected by default)
python watchdog.py scan ./my-app --framework nextjs

# Specify deployment target
python watchdog.py scan ./my-app --target vercel

# JSON output
python watchdog.py scan ./my-app --output json

# Run specific scanners only
python watchdog.py scan ./my-app --scanners secrets,client-exposure,artifacts
```

### Tests

```bash
pytest tests/
```

Test fixtures in `tests/fixtures/` contain intentionally vulnerable sample projects for each scanner type.

---

## Project structure

```
watchdog/
├── watchdog.py               # CLI entrypoint
├── orchestrator.py           # Coordinates sub-agents, aggregates results
├── agents/
│   ├── secret_scanner.py
│   ├── client_exposure.py
│   ├── env_tracer.py
│   ├── config_checker.py
│   ├── iac_scanner.py
│   ├── dep_checker.py
│   └── artifact_inspector.py
├── reasoning/
│   ├── claude_client.py      # Anthropic API integration
│   └── prompts/              # Framework-specific reasoning prompts
├── reporters/
│   ├── console.py            # CLI output
│   ├── gitlab_mr.py          # MR comment formatter
│   └── pipeline.py           # Pipeline block/pass signal
├── tests/
│   ├── fixtures/             # Sample vulnerable projects
│   └── test_*.py
├── .gitlab-ci.yml
├── .env.example
├── requirements.txt
└── README.md
```

---

## GitLab CI/CD integration

Add to `.gitlab-ci.yml`:

```yaml
watchdog-scan:
  stage: pre-deploy
  image: python:3.11
  before_script:
    - pip install -r requirements.txt
  script:
    - python watchdog.py scan . --target $DEPLOY_TARGET --output gitlab
  variables:
    ANTHROPIC_API_KEY: $ANTHROPIC_API_KEY
  rules:
    - if: '$CI_COMMIT_BRANCH == "main"'
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
  allow_failure: false
```

Set `ANTHROPIC_API_KEY` as a masked CI/CD variable in GitLab project settings.

---

## GitLab Hackathon

Built for the GitLab AI Hackathon. To deploy on GitLab Duo:

1. Request access to the GitLab AI Hackathon group (approval takes time)
2. Push this repo into your project in the hackathon group
3. Set `ANTHROPIC_API_KEY` as a masked CI/CD variable
4. Trigger a pipeline

Local development works fully without GitLab access — do that first.

## Submission

- **Event:** GitLab AI Hackathon 2026
- **Category:** Security & Compliance agents
- **Repo:** *(add when GitLab access is granted)*
- **Demo video:** *(add before submission)*

## License

MIT — see [LICENSE](LICENSE)
