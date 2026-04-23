# Requirements — Automated IR Pipeline

## What is this project?

A semi-automated incident response system that watches
containers in real time, detects attacks, maps them to
MITRE ATT&CK, collects evidence automatically, and helps
the responder take action — all running locally on Docker.

## Why am I building this?

Most DevSecOps content focuses on the pipeline — scanning
code, dependencies, and containers before deployment.
But what happens after deployment? What's watching
production?

This project answers that question with a working system,
not just a concept.

## The target application — SecureBank API

A Flask-based banking REST API with intentional
vulnerabilities. I chose banking because it naturally
handles sensitive data (credentials, financial info, PII)
which makes the monitoring and detection use case
realistic.

### Endpoints:

- POST /api/auth/register — create a new user
- POST /api/auth/login — authenticate and get a JWT
- GET /api/account/balance — check account balance
- POST /api/account/transfer — transfer funds
- GET /api/account/history — view transactions
- GET /api/admin/users — admin only: list all users
- POST /api/admin/config — admin only: update app config

### Intentional vulnerabilities:

- Weak JWT secret (allows token forgery)
- No rate limiting on login (allows brute force)
- SQL injection on the transfer endpoint
- Debug mode enabled (exposes internal info)
- No input validation on admin config (command injection)
- Container runs as root (allows privilege escalation)
- No network restrictions (allows outbound C2 connections)

Each vulnerability exists for a reason — to create a
realistic attack surface that the IR pipeline can detect.

## What attacks will this system detect?

8 scenarios, each mapped to MITRE ATT&CK:

1. Reverse shell inside a container
   ATT&CK: T1059.004 (Enterprise) / T1609 (Containers)
   Severity: Critical

2. Privilege escalation attempt
   ATT&CK: T1068 (Enterprise) / T1611 (Containers)
   Severity: Critical

3. Container escape attempt
   ATT&CK: T1611
   Severity: Critical

4. Unusual outbound network connection
   ATT&CK: T1071.001
   Severity: High

5. Unauthorized binary execution
   ATT&CK: T1204.002 (Enterprise) / T1610 (Containers)
   Severity: High

6. Cryptocurrency mining (high CPU simulation)
   ATT&CK: T1496
   Severity: High

7. Brute force login attempts
   ATT&CK: T1110.001
   Severity: Medium

8. File system tampering inside a container
   ATT&CK: T1565.001
   Severity: Medium

## What should the system do when it detects something?

Two things — collect evidence and help the responder act.

### Evidence collection (automatic):

When a detection rule fires, the system automatically grabs:
- Running processes from the affected container
- Active network connections
- File system changes (docker diff)
- Container logs (last 200 lines)
- Container metadata (image, labels, env)
- Timestamp and a correlation ID linking it to the alert

Everything gets saved as a structured JSON report.

### Response actions (semi-automated):

Some things run automatically:
- Evidence collection
- Alert notification
- Audit logging

Some things wait for a human to approve:
- Isolate the container from the network
- Stop the container
- Trigger credential rotation

Why semi-automated? Because auto-isolating the wrong
container in production can cause more damage than the
attack itself. The system recommends actions. A human
decides.

## What does the dashboard show?

Kibana dashboard with:
- Real-time alert feed with severity indicators
- MITRE ATT&CK technique breakdown
- Evidence reports linked to each alert
- Response status tracking (pending, in-progress, resolved)
- Incident timeline view
- Container health overview

## Tech stack

Everything is free and open-source:

- Vulnerable app: Flask (Python) + SQLite
- Log collection: Filebeat
- Log processing: Logstash
- Storage and search: Elasticsearch
- Visualization: Kibana
- Detection engine: ElastAlert2
- Evidence collector: Python script
- Response handler: Python script
- Attack simulator: Python scripts
- Orchestration: Docker Compose
- Optional: Kubernetes manifests (Minikube)

Total cost: $0. Runs entirely on local Docker.

## Security decisions for the project itself

- All containers run as non-root
- No hardcoded credentials anywhere in the code
- Secrets go in a .env file (.env.example provided)
- Elasticsearch and Kibana don't use default passwords
- Inter-container communication on a dedicated Docker network
- Minimal base images (Alpine where possible)
- Log shipping uses TLS between Filebeat and Logstash

## What's NOT in scope (for now)

- Fully automated response (no human approval)
- Cloud provider integration (Azure/AWS)
- ML-based anomaly detection
- Production-grade high availability
- Web UI for response approval

These are future enhancements. Version 1 stays focused.

## How do I know this project is done?

- All 8 attacks detected within 60 seconds
- Evidence collected automatically for every alert
- Every detection mapped to MITRE ATT&CK
- Kibana dashboard shows real-time alerts
- Full SSDLC docs in the repo
- Runs with one command: docker-compose up
- Someone can read the README and understand
  the project without running it