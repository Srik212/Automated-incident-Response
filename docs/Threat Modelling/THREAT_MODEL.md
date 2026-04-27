# Threat Model — Automated Incident Response

**Project:** SecureBank API + ELK-Based SOC Detection & Response Pipeline  
**Methodology:** STRIDE  
**Last Updated:** April 2026  
**Author:** Srikanth Narayanan Sundararajan
**Status:** Draft — Work in Progress

> **Note to self:** This is my first full threat model. I followed the STRIDE methodology after reading about it in the OWASP threat modeling guide. The goal was to go through each component of my pipeline and ask: "what could go wrong here, and who would do it?" Some of these threats I discovered while building the system; others I found by reading about real-world attacks on similar stacks.

---

## Table of Contents

1. [What Is Threat Modeling?](#what-is-threat-modeling)
2. [System Overview](#system-overview)
3. [What I'm Trying to Protect](#what-im-trying-to-protect)
4. [Threat Actors](#threat-actors)
5. [The STRIDE Framework](#the-stride-framework)
6. [Threat Register](#threat-register)
   - [Critical Threats](#critical-threats)
   - [High Threats](#high-threats)
   - [Medium Threats](#medium-threats)
7. [Risk Summary by Component](#risk-summary-by-component)
8. [Mitigation Tracking](#mitigation-tracking)
9. [What I'd Do Differently / Open Questions](#what-id-do-differently--open-questions)
10. [Revision History](#revision-history)

---

## What Is Threat Modeling?

Threat modeling is the process of thinking like an attacker to identify what could go wrong in a system before it actually does. Instead of waiting for something to break, the idea is to map out your system, figure out who might want to attack it, and document how they might do it — then plan mitigations.

There are many frameworks for doing this. This document uses **STRIDE**, which was developed by Microsoft and is one of the most widely taught approaches. It's not perfect, but it's a solid starting point for categorizing threats systematically.

**Why bother?** Without a threat model, security decisions tend to be reactive ("we got hacked, now let's fix it"). With one, you can prioritize what to secure first based on actual risk — not just intuition.

---

## System Overview

This pipeline was built as a capstone project combining an intentionally vulnerable banking API (SecureBank) with a full SOC detection and automated response pipeline.

```
[User / Attacker]
      │
      ▼
[SecureBank API] ──── generates logs ────▶ [Filebeat]
                                                │
                                                ▼
                                          [Logstash]
                                                │
                                                ▼
                                       [Elasticsearch]
                                          │        │
                                          ▼        ▼
                                     [Kibana]  [ElastAlert2]
                                                   │
                                                   ▼
                                        [Evidence Collector]
                                                   │
                                                   ▼
                                        [Response Handler]
                                                   │
                                                   ▼
                                       [SOC Analyst Approval]
```

**Components and their roles:**

| Component | Role |
|---|---|
| SecureBank API | Intentionally vulnerable Flask API simulating a banking app |
| Filebeat | Ships logs from the API container to Logstash |
| Logstash | Parses, filters, and forwards structured logs to Elasticsearch |
| Elasticsearch | Stores all log data and alert indices |
| Kibana | Visual dashboard for the SOC analyst |
| ElastAlert2 | Monitors Elasticsearch and fires alerts on detection rules |
| Evidence Collector | Captures forensic snapshots when an alert fires |
| Response Handler | Executes containment actions (e.g., isolating a container) after analyst approval |

All components run as Docker containers and communicate over an internal Docker network. The SecureBank API is the only component that intentionally faces external traffic.

---

## What I'm Trying to Protect

Before listing threats, it helps to define what assets actually matter. This is something I learned — threat modeling without knowing your assets leads to unfocused results.

**Key assets in this system:**

- **Integrity of audit logs** — if logs are tampered with, the whole detection pipeline is worthless
- **Confidentiality of alert data** — evidence files may contain sensitive tokens or credentials captured during incident response
- **Availability of the detection pipeline** — if Filebeat, Logstash, or ElastAlert2 goes down, the SOC is blind
- **Integrity of detection rules** — if an attacker can modify ElastAlert2 rules, they can silence alerts about their own activity
- **Authenticity of response commands** — the Response Handler can isolate or stop containers; a fake command could cause serious damage

---

## Threat Actors

Not every threat comes from the same type of attacker. It's worth thinking about who is realistically targeting this system and what their capabilities are.

| Actor | Description | Likely Goals |
|---|---|---|
| **External attacker** | Unauthenticated user reaching the SecureBank API over the network | Steal data, escalate privileges, move laterally |
| **Authenticated insider** | User with a valid JWT token trying to go beyond their role | Access admin endpoints, exfiltrate data |
| **Attacker with container foothold** | Has already compromised one container via RCE or similar | Lateral movement, covering tracks, persisting |
| **Alert-aware attacker** | Knows a SOC is monitoring and tries to evade detection | Suppress alerts, corrupt evidence, blind the pipeline |

> **Learning note:** I initially only thought about the "external attacker" scenario. The "alert-aware attacker" category came up later when I realized that an attacker who knows they're being monitored has completely different goals — they'll target the detection stack itself, not just the application.

---

## The STRIDE Framework

STRIDE is an acronym where each letter represents a category of threat. The value of using it is that it forces you to think about threats from six different angles for every component — instead of only thinking about the obvious ones.

| Letter | Category | Core Question |
|---|---|---|
| **S** | Spoofing | Can someone pretend to be a legitimate user or service? |
| **T** | Tampering | Can someone modify data, logs, or code without authorization? |
| **R** | Repudiation | Can someone deny they did something because there's no proof? |
| **I** | Information Disclosure | Can unauthorized people access data they shouldn't see? |
| **D** | Denial of Service | Can someone make a component unavailable? |
| **E** | Elevation of Privilege | Can someone gain more access than they're supposed to have? |

The process is: take each component in the architecture, apply each STRIDE category, and ask "is this possible here?" If yes, document it and think about a mitigation.

---

## Threat Register

Threats are ranked **Critical**, **High**, or **Medium** based on a rough combination of:
- **Impact** — how bad is it if this succeeds?
- **Likelihood** — how easy is this to exploit?
- **Position in the kill chain** — threats that let an attacker cover their tracks or escalate are ranked higher

> **Honest note:** Formal risk scoring (like DREAD or CVSS) is more rigorous than what I've done here. For now, I've used judgment based on what I've read about real attacks. In a production environment, each of these would get a proper numeric score.

---

### Critical Threats

These are the threats I'd prioritize first. They either directly compromise data integrity, allow privilege escalation, or undermine the detection pipeline itself.

| # | Component | STRIDE | Threat Description | Why It's Critical | Mitigation |
|---|---|---|---|---|---|
| 1 | SecureBank API | Spoofing | Attacker forges JWT to impersonate users and access admin endpoints | JWTs are the entire auth mechanism — a forged one bypasses everything | Strong JWT secret, short expiration, server-side signature validation |
| 2 | SecureBank API | Tampering | SQL injection on transfer endpoint manipulates financial data | Direct manipulation of financial records; classic and high-impact | Parameterized queries, input validation |
| 3 | SecureBank API | Elevation | Attacker modifies JWT role claim to escalate from user to admin | The API must never trust what the client sends for role — this is a common mistake | Server-side role enforcement, never trust client-side claims |
| 4 | Filebeat → Logstash | Tampering | Logs altered in transit — attacker covers their tracks before data reaches ELK | If logs are tampered mid-transit, the SOC never sees the real evidence | TLS encryption between Filebeat and Logstash |
| 5 | Elasticsearch | Spoofing | Unauthorized access to Elasticsearch API — attacker reads or deletes all data | By default, Elasticsearch has no auth — this is a well-known misconfiguration that has caused real breaches | Authentication enabled, no default credentials, bind to internal network only |
| 6 | Elasticsearch | Tampering | Attacker deletes evidence and alert indices to erase detection history | Destroying evidence is worse than the original attack in some ways — it prevents forensic analysis | Read-only indices for evidence, append-only alert logs, snapshot backups |
| 7 | ElastAlert2 | Tampering | Attacker modifies detection rules to suppress alerts for their activity | If an attacker can edit detection rules, they become invisible to the SOC | Rules stored in version control, file integrity monitoring, container runs as non-root |
| 8 | Evidence Collector | Tampering | Attacker tampers with forensic evidence before analyst reviews it | Tampered evidence is worse than no evidence — it could lead the analyst to wrong conclusions | SHA-256 hash at collection time, immutable storage |
| 9 | Response Handler | Spoofing | Fake approval triggers destructive response — isolates or stops the wrong container | The response system can take real actions; a forged approval could cause an outage | Authenticate all approvals, SOC analyst identity verification |
| 10 | Response Handler | Elevation | Handler has Docker socket access — attacker escalates to host | Docker socket access is effectively root on the host — this is a known container escape vector | Read-only Docker socket, restrict API calls, least privilege |

---

### High Threats

These matter a lot but are either harder to exploit, have slightly less catastrophic outcomes, or have straightforward mitigations.

| # | Component | STRIDE | Threat Description | Mitigation |
|---|---|---|---|---|
| 11 | SecureBank API | Info Disclosure | Debug mode leaks stack traces, internal paths, and config details | Disable debug in production, custom error handlers |
| 12 | Filebeat | Denial of Service | Attacker kills Filebeat process — pipeline goes blind, no logs collected | Docker restart policy (always), health monitoring |
| 13 | Logstash | Tampering | Crafted log entries injected to manipulate parsing logic and create false data | Strict grok patterns, input validation in filters |
| 14 | Logstash | Denial of Service | Garbage data floods Logstash to overwhelm processing | Persistent queue, dead letter queue, rate limiting |
| 15 | Elasticsearch | Info Disclosure | Port 9200 exposed outside Docker network — anyone can query indices | Bind to internal Docker network only, RBAC on indices |
| 16 | ElastAlert2 | Denial of Service | Attacker generates noise to flood alerts and hide real attacks | Alert correlation, deduplication, rate-based suppression |
| 17 | Evidence Collector | Info Disclosure | Evidence files contain passwords or tokens captured during container inspection | Encrypt evidence at rest, role-based access |
| 18 | Response Handler | Tampering | Response command modified in transit — "isolate" becomes "delete" | Signed response commands, integrity validation |
| 19 | Kibana | Spoofing | Unauthorized user accesses dashboard and views all alerts and evidence | Authentication required, no anonymous access |



---

### Medium Threats

Important to address eventually, but lower urgency. Mostly involve audit gaps, availability of non-critical components, or secondary information disclosure.

| # | Component | STRIDE | Threat Description | Mitigation |
|---|---|---|---|---|
| 20 | SecureBank API | Repudiation | Attacker performs actions with no audit trail — can't prove who did what | Log all requests with timestamp, user ID, IP, and action |
| 21 | SecureBank API | Denial of Service | Brute force floods login endpoint | Rate limiting, account lockout after failed attempts |
| 22 | Logstash | Info Disclosure | Config files expose Elasticsearch connection strings | Secrets in environment variables, not config files |
| 23 | Elasticsearch | Denial of Service | Index flooding exhausts disk space | Index lifecycle management, disk watermark alerts |
| 24 | ElastAlert2 | Repudiation | Alert fires but no record of who saw it or acted on it | Audit log for every alert state change |
| 25 | Evidence Collector | Repudiation | Collection fails silently — no error logged, evidence gap unnoticed | Log success/failure for every collection attempt |
| 26 | Response Handler | Repudiation | Response action taken but not logged — no accountability | Audit trail with timestamp, actor, action, and result |
| 27 | Kibana | Denial of Service | Attacker crashes Kibana to blind the SOC analyst | Docker restart policy, health monitoring |

---

## Risk Summary by Component

| Component | Critical | High | Medium | Total |
|---|---|---|---|---|
| SecureBank API | 3 | 1 | 2 | **6** |
| Filebeat / Filebeat → Logstash | 1 | 1 | 0 | **2** |
| Logstash | 0 | 2 | 1 | **3** |
| Elasticsearch | 2 | 1 | 1 | **4** |
| ElastAlert2 | 1 | 1 | 1 | **3** |
| Evidence Collector | 1 | 1 | 1 | **3** |
| Response Handler | 2 | 1 | 1 | **4** |
| Kibana | 0 | 1 | 1 | **2** |
| **Total** | **10** | **9** | **8** | **27** |

The SecureBank API and Response Handler carry the most risk. The API is the external-facing entry point, so that's expected. The Response Handler risk surprised me — it's an internal component, but Docker socket access makes it one of the most dangerous escalation paths in the system.

---

## Mitigation Tracking

> This table is updated as mitigations are implemented. Statuses follow the key below.

**Status Key:** `⬜ Not Started` · `🟡 In Progress` · `✅ Implemented` · `🔴 Accepted Risk`

| # | Component | Mitigation | Status | Notes |
|---|---|---|---|---|
| 1 | SecureBank API | Strong JWT secret, short expiration, server-side validation | ⬜ Not Started | Need to move secret to env var, add expiry check |
| 2 | SecureBank API | Parameterized queries | ⬜ Not Started | Transfer endpoint currently uses string formatting — needs rewrite |
| 3 | SecureBank API | Server-side role enforcement | ⬜ Not Started | Role decoded from JWT; need to re-validate against DB |
| 4 | Filebeat → Logstash | TLS between Filebeat and Logstash | ⬜ Not Started | Need to generate certs and update both configs |
| 5 | Elasticsearch | Auth + network binding | ⬜ Not Started | Currently no auth, bound to 0.0.0.0 — high priority |
| 6 | Elasticsearch | Read-only indices, snapshot backups | ⬜ Not Started | ILM policy needed |
| 7 | ElastAlert2 | Rules in version control, FIM | ⬜ Not Started | Rules are already in Git; need to add FIM |
| 8 | Evidence Collector | SHA-256 hash at collection | ⬜ Not Started | Need to add hashing step to collector script |
| 9 | Response Handler | Authenticate approvals | ⬜ Not Started | Currently no verification on approval trigger |
| 10 | Response Handler | Least privilege Docker socket | ⬜ Not Started | Currently full socket access — need to scope down |
| 11 | SecureBank API | Disable debug, custom error handlers | ⬜ Not Started | `DEBUG=True` still set in dev config |
| 12 | Filebeat | Docker restart policy | ⬜ Not Started | Easy fix — update docker-compose.yml |
| 13 | Logstash | Strict grok patterns | ⬜ Not Started | Current patterns are too permissive |
| 14 | Logstash | Persistent queue, DLQ, rate limiting | ⬜ Not Started | |
| 15 | Elasticsearch | Bind to internal network only | ⬜ Not Started | Related to #5 |
| 16 | ElastAlert2 | Deduplication, rate-based suppression | ⬜ Not Started | |
| 17 | Evidence Collector | Encrypt evidence at rest, RBAC | ⬜ Not Started | |
| 18 | Response Handler | Signed response commands | ⬜ Not Started | |
| 19 | Kibana | Require auth, no anonymous access | ⬜ Not Started | |
| 20 | SecureBank API | Structured request logging | ⬜ Not Started | |
| 21 | SecureBank API | Rate limiting + account lockout | ⬜ Not Started | Flask-Limiter could handle this |
| 22 | Logstash | Secrets in env vars, not config files | ⬜ Not Started | |
| 23 | Elasticsearch | ILM + disk watermark alerts | ⬜ Not Started | |
| 24 | ElastAlert2 | Audit log for alert state changes | ⬜ Not Started | |
| 25 | Evidence Collector | Log every collection attempt | ⬜ Not Started | |
| 26 | Response Handler | Audit trail for all response actions | ⬜ Not Started | |
| 27 | Kibana | Docker restart policy | ⬜ Not Started | Same fix as #12 |

---

## What I'd Do Differently / Open Questions

This section captures things I'm unsure about or would approach differently with more experience:

- **Formal risk scoring:** I ranked threats as Critical/High/Medium based on judgment. A proper DREAD or CVSS-based score would be more defensible. Something to add in a future revision.

- **Data Flow Diagrams (DFDs):** Most threat modeling guides recommend drawing formal DFDs before doing STRIDE analysis. I worked from my architecture diagram instead. DFDs force you to identify every trust boundary, which probably would have surfaced more threats.

- **Trust boundaries weren't fully mapped:** For example, I didn't explicitly model the boundary between the Docker host and the containers. Threat #10 (Docker socket escalation) came from reading about container escapes separately — not from a systematic trust boundary review.

- **Missing STRIDE categories:** Looking at the table, some components are missing entire STRIDE categories (e.g., no Repudiation threats for Kibana, no Spoofing threats for Logstash). This might mean I missed real threats, or those categories genuinely don't apply. Worth revisiting.

- **Automation:** Tracking mitigations in a markdown table works for now, but in a real team environment this would live in a proper issue tracker (Jira, GitHub Issues) with owners and due dates.

---

## Revision History

| Version | Date | Author | Notes |
|---|---|---|---|
| 1.0 | April 2026 | [Your Name] | Initial threat model — 27 STRIDE threats across 8 components |

