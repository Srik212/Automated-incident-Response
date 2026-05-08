# SecureBank API — A Deliberately Vulnerable App Secured by a 7-Gate CI/CD Pipeline

> I built a vulnerable banking API. Then I built a pipeline that catches every vulnerability automatically.

A DevSecOps portfolio project demonstrating how to secure a CI/CD pipeline end-to-end — from the first commit to production deployment. Built following the Secure SDLC methodology.

Part of my [90-day DevSecOps journey on LinkedIn](https://linkedin.com/in/srikanth-narayanan).

---

## What This Project Is

A Flask-based banking REST API with **7 intentional vulnerabilities**, secured by a **7-gate CI/CD security pipeline** using GitHub Actions. Every push and every pull request triggers automated security scanning across all 7 gates. If any gate finds a critical issue, the pipeline blocks the merge.

The project also includes an ELK stack for runtime log monitoring and ElastAlert2 detection rules as an additional security layer.

---

## Why I Built This

Most DevSecOps content explains security concepts in theory. This project puts them into practice — a real vulnerable app, real scanners, real findings, and a real pipeline that enforces security automatically.

The goal: demonstrate that security isn't something you bolt on after development. It's something you design in from the start.

---

## The Secure SDLC Process

This project wasn't built by jumping straight into code. It followed the Secure SDLC:

| Phase | What I Did | Document |
|-------|-----------|----------|
| 1. Requirements | Defined scope, target app, 8 threat scenarios, functional and non-functional requirements | [requirements.md](docs/requirements.md) |
| 2. Threat Modeling | Applied STRIDE to every component, identified 27 threats across 8 components | [threat-model.md](docs/threat-model.md) |
| 3. Architecture | Designed 4-layer architecture, made every design choice a security decision | [architecture.md](docs/architecture.md) |
| 4. Implementation | Built the app, pipeline, and monitoring stack | This repo |
| 5. Testing | Ran all 7 gates, verified scan results, tested detection rules | [GitHub Actions](../../actions) |

---

## Architecture

```
                        ┌─────────────┐
                        │   Attacker   │
                        └──────┬──────┘
                               │
                ┌──────────────▼──────────────┐
  Layer 1       │     SecureBank API (Flask)    │
  The Target    │  7 intentional vulnerabilities │
                └──────────────┬──────────────┘
                               │ logs
                ┌──────────────▼──────────────┐
  Layer 2       │     ELK Stack (monitoring)    │
  The Eyes      │ Filebeat → Logstash → Elastic │
                │         → Kibana              │
                └──────────────┬──────────────┘
                               │
                ┌──────────────▼──────────────┐
  Layer 3       │  ElastAlert2 (detection)      │
  The Brain     │  5 rules mapped to ATT&CK     │
                └──────────────┬──────────────┘
                               │ alert
                ┌──────────────▼──────────────┐
  Layer 4       │  Evidence + Response          │
  The Hands     │  (future enhancement)         │
                └───────────────────────────────┘
```

**Parallel to the runtime monitoring, the CI/CD pipeline enforces security on every push:**

```
Developer pushes code
        │
        ▼
┌─── GitHub Actions Security Pipeline ───┐
│                                         │
│  Gate 1: Secret Scanning (Gitleaks)     │
│  Gate 2: SAST (Bandit)                  │
│  Gate 3: SCA (pip-audit)                │
│  Gate 4: Container Scanning (Trivy)     │
│  Gate 5: IaC Scanning (Checkov)         │
│  Gate 6: DAST (OWASP ZAP)              │
│  Gate 7: SBOM Generation (Syft)         │
│                                         │
│  All pass? → Merge allowed              │
│  Any fail? → Merge blocked              │
└─────────────────────────────────────────┘
```

---

## The 7 Security Gates

| Gate | Tool | What It Scans | What It Catches |
|------|------|--------------|-----------------|
| 1. Secret Scanning | Gitleaks | Git history and staged files | Hardcoded API keys, tokens, passwords |
| 2. SAST | Bandit | Python source code | SQL injection, command injection, debug mode, insecure functions |
| 3. SCA | pip-audit | Python dependencies (requirements.txt) | Known CVEs in third-party packages |
| 4. Container Scanning | Trivy | Docker image | Vulnerable OS packages, outdated base image |
| 5. IaC Scanning | Checkov | Dockerfile, docker-compose.yml | Misconfigurations — root user, missing health checks, exposed ports |
| 6. DAST | OWASP ZAP | Running application | Runtime vulnerabilities — XSS, injection, missing headers |
| 7. SBOM Generation | Syft + Trivy | Built container image | Full component inventory + vulnerability scan against SBOM |

**Local layer (pre-commit hooks):**

Gitleaks and Bandit also run locally via pre-commit hooks. The CI/CD pipeline is the enforced safety net — it catches anything the local hooks missed.

---

## Tech Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Application | Python, Flask, SQLite | Deliberately vulnerable banking REST API |
| Containerization | Docker, Docker Compose | Packages app and all services |
| CI/CD | GitHub Actions | Runs the 7-gate security pipeline |
| Secret Scanning | Gitleaks | Detects hardcoded secrets |
| SAST | Bandit | Static code analysis for Python |
| SCA | pip-audit | Dependency vulnerability scanning |
| Container Scanning | Trivy | Image vulnerability scanning |
| IaC Scanning | Checkov | Dockerfile and Compose misconfiguration scanning |
| DAST | OWASP ZAP | Dynamic testing against running app |
| SBOM | Syft | Software Bill of Materials generation |
| Log Collection | Filebeat | Ships container logs |
| Log Processing | Logstash | Parses, filters, enriches logs |
| Search and Storage | Elasticsearch | Indexes and stores security events |
| Visualization | Kibana | Dashboard for alerts and logs |
| Detection Engine | ElastAlert2 | Runs detection rules against incoming data |
| Pre-commit | pre-commit framework | Local security hooks |

---

## SecureBank API — Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | /api/health | None | Health check |
| POST | /api/auth/register | None | Register new user |
| POST | /api/auth/login | None | Login and get JWT token |
| GET | /api/account/balance | JWT | Check account balance |
| POST | /api/account/transfer | JWT | Transfer funds |
| GET | /api/account/history | JWT | View transaction history |
| GET | /api/admin/users | JWT + Admin | List all users |
| POST | /api/admin/config | JWT + Admin | Update app configuration |

---

## Intentional Vulnerabilities

Each vulnerability exists for a specific reason — to create a realistic, detectable attack surface.

| # | Vulnerability | Location | Risk | Which Gate Catches It |
|---|--------------|----------|------|----------------------|
| 1 | Weak JWT secret | app.py config | Token forgery, account takeover | Gate 2 (Bandit) |
| 2 | No rate limiting on login | /api/auth/login | Brute force attacks | Gate 6 (ZAP) |
| 3 | SQL injection on transfer | /api/account/transfer | Data manipulation, data theft | Gate 2 (Bandit) + Gate 6 (ZAP) |
| 4 | Command injection on admin config | /api/admin/config | Remote code execution | Gate 2 (Bandit) |
| 5 | Debug mode enabled | app.py config | Information disclosure | Gate 2 (Bandit) + Gate 5 (Checkov) |
| 6 | Passwords stored in plain text | Database | Credential theft | Gate 2 (Bandit) |
| 7 | Container runs as root | Dockerfile | Privilege escalation | Gate 5 (Checkov) |

---

## ELK Stack — Runtime Monitoring (Additional Feature)

Beyond the CI/CD pipeline, this project includes an ELK stack for runtime log monitoring.

SecureBank API logs every security-relevant event. Filebeat collects these logs. Logstash parses and enriches them, tagging security events. Elasticsearch stores and indexes everything. Kibana provides a real-time dashboard.

**ElastAlert2 Detection Rules:**

| Rule | Detects | Trigger | Severity |
|------|---------|---------|----------|
| Brute Force | Multiple failed logins from same IP | 5 failures in 2 minutes | Medium |
| Privilege Escalation | Non-admin accessing admin endpoints | Every occurrence | Critical |
| Access Denied | Requests without authentication tokens | 3 attempts in 5 minutes | High |
| Admin Config Change | Any admin configuration modification | Every occurrence | High |
| Login After Failures | Successful login following failed attempts | 3 failures in 5 minutes | Critical |

---

## How to Run

### Prerequisites

- Python 3.12+
- Docker and Docker Compose
- Git

### Option 1 — Run the app locally (without ELK)

```bash
git clone https://github.com/Srik212/automated-ir-pipeline.git
cd automated-ir-pipeline/vulnerable-app

python -m venv venv
# Windows
venv\Scripts\activate
# Linux/Mac
source venv/bin/activate

pip install -r requirements.txt
python app.py
```

App runs at http://localhost:5000

### Option 2 — Run everything with Docker (app + ELK)

```bash
git clone https://github.com/Srik212/automated-ir-pipeline.git
cd automated-ir-pipeline

docker-compose up --build
```

Wait 60 seconds for all services to start:

- SecureBank API: http://localhost:5000
- Elasticsearch: http://localhost:9200
- Kibana: http://localhost:5601

### Testing the API

```bash
# Health check
curl http://localhost:5000/api/health

# Register a user
curl -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "test123"}'

# Login
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "test123"}'

# Check balance (use token from login response)
curl http://localhost:5000/api/account/balance \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Setting up pre-commit hooks

```bash
pip install pre-commit
pre-commit install
```

---

## Project Structure

```
automated-ir-pipeline/
├── .github/
│   └── workflows/
│       └── security-pipeline.yml    # 7-gate CI/CD pipeline
├── .pre-commit-config.yaml          # Local security hooks
├── pyproject.toml                   # Bandit configuration
├── docker-compose.yml               # Full stack orchestration
├── .env.example                     # Environment variables template
│
├── vulnerable-app/                  # Layer 1 — The Target
│   ├── app.py                       # SecureBank API (Flask)
│   ├── requirements.txt             # Python dependencies
│   └── Dockerfile                   # Container definition
│
├── logstash/                        # Layer 2 — The Eyes
│   └── pipeline.conf                # Log parsing and enrichment
│
├── filebeat/                        # Layer 2 — The Eyes
│   └── filebeat.yml                 # Log collection config
│
├── elastalert/                      # Layer 3 — The Brain
│   ├── config.yaml                  # ElastAlert2 config
│   └── rules/                       # Detection rules
│       ├── brute_force.yaml
│       ├── privilege_escalation.yaml
│       ├── access_denied.yaml
│       ├── admin_config_change.yaml
│       └── login_after_failures.yaml
│
├── docs/                            # SSDLC documentation
│   ├── requirements.md
│   ├── threat-model.md
│   └── architecture.md
│
└── screenshots/                     # Pipeline and dashboard captures
```

---

## Future Enhancements

- Kubernetes deployment with pod security, RBAC, and network policies
- Automated evidence collection on alert triggers
- Semi-automated incident response handler
- MITRE ATT&CK mapping JSON file linking detections to techniques
- Attack simulator scripts for all 8 threat scenarios
- Slack and email alert integration
- Azure deployment with Defender for Cloud
- ML-based anomaly detection for unusual API patterns

---

## What I Learned Building This

**The Secure SDLC works.** Three days of planning caught 27 threats before writing any code. 19 of them were addressed through design decisions alone.

**Defaults are dangerous.** Docker, Flask, Kubernetes — every tool works out of the box. None of them are secure out of the box.

**One gate isn't enough.** Each gate catches things the others miss. SAST catches code patterns. SCA catches dependency CVEs. Container scanning catches OS vulnerabilities. Layering them is the only real strategy.

**AI accelerates building, not thinking.** I used AI as a pair programmer for implementation. The planning, debugging, and security decisions were mine.

**Building teaches more than reading.** Every debugging session — silent container crashes, YAML indentation errors, permission issues — taught me more than any tutorial.

---

## Follow My Journey

This project is part of my 90-day DevSecOps learning journey.

- [LinkedIn](https://linkedin.com/in/srikanth-narayanan) — Daily posts
- [GitHub](https://github.com/Srik212) — Projects and code
