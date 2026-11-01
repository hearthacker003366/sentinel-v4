# Sentinel V4 — Chief Sentinel Orchestrator & Red Team Bot Design
**Document Path:** `docs/designs/orchestrator-bots-design.md`  
**Platform:** Meta Global AI Developer Hackathon 2026 (Track: *Build for Your World*)  
**Status:** Step 1 Architectural Design Specification (Pre-Implementation Review)  
**Date:** November 2026  

---

## 1. Executive Summary & Objective

In **Sentinel V4**, defense orchestration shifts from fragile static automation to an adaptive, dual-system cognitive architecture. Security Operations Centers (SOCs) are overwhelmed by alert fatigue (where over 70% of alerts are noise) while sophisticated multi-hop intrusions and living-off-the-land attacks slip past perimeter defenses.

This specification details the architecture for:
1. **Chief Sentinel Orchestrator (`orchestrator/chief_sentinel.py`)**: The master coordinator binding local edge triage (System-1 Laya), cloud cognitive reasoning (System-2 Meta Muse Spark), and Human-in-the-Loop (HITL) approval gates.
2. **Red Team Bot Engine (`redteam/bot.py`)**: An adversarial simulator enforcing strict lab network containment (`ScopeViolation`) while executing **FIVE distinct adversary personas** across three end-to-end benchmark scenarios.

---

## 2. High-Level System Architecture

```
   [ Telemetry Stream / Syslog / EDR / Network ]
                         │
                         ▼
             ┌─────────────────────────┐
             │ Chief Sentinel          │
             │ Orchestrator Engine     │
             └───────────┬─────────────┘
                         │
        ┌────────────────┴────────────────┐
        ▼                                 ▼
┌─────────────────────────┐     ┌─────────────────────────┐
│ System-1: Edge Triage   │     │ System-2: Cognitive LLM │
│ Laya Classifier (Local) │     │ Meta Muse Spark 1.3     │
│ • Sub-55ms latency      │     │ • Tool Use via MCP      │
│ • RTX 4050 / CPU        │     │ • Multi-Hop Path Reason │
│ • 0.85 Auto-Act Gate    │     │ • Propose-Only Policy   │
└───────────┬─────────────┘     └───────────┬─────────────┘
            │                               │
    Confidence >= 0.85              Confidence < 0.85
   (83.2% Autonomous)              (16.8% Escalation)
            │                               │
            ▼                               ▼
┌─────────────────────────┐     ┌─────────────────────────┐
│ Autonomous Local SOAR   │     │ Telegram & CLI HITL     │
│ & Honeypot Trap Routing │     │ Approval Queue          │
└─────────────────────────┘     └───────────┬─────────────┘
                                            │ Human Analyst
                                            │ Confirmation
                                            ▼
                                ┌─────────────────────────┐
                                │ Reversible Containment  │
                                │ (TTL + Dry-Run Capable) │
                                └─────────────────────────┘
```

---

## 3. Chief Sentinel Orchestrator (`orchestrator/chief_sentinel.py`)

### 3.1 Core Responsibilities
1. **Telemetry Ingestion & Pre-Processing**: Continuously ingests normalized event logs (`auth.log`, EDR, Zeek/Suricata NIDS, Honeypot captures).
2. **System-1 Triage Dispatch**: Submits each event to the local fine-tuned Laya model (`laya-tuned-v1`), receiving:
   - `verdict` (`benign`, `suspicious`, `malicious`)
   - `winner_confidence` ($P \in [0.0, 1.0]$)
   - `is_attack` boolean
   - `severity` continuous scalar ($[0.0, 1.0]$)
3. **Cognitive Routing Gate**:
   - If `winner_confidence >= 0.85`: Event is handled autonomously by System-1 (direct local containment or passive logging).
   - If `winner_confidence < 0.85`: Event is escalated to System-2 (Meta Muse Spark) with enriched topological and historic context.
4. **System-2 Tool Orchestration**: Exposes the MCP Blue Team Tool Registry to Muse Spark via the Meta Model API with `tool_choice="auto"`.
5. **Human-in-the-Loop (HITL) Gate**: Enforces the **propose-only invariant**: no mutating network or endpoint change can be applied without verified operator sign-off via Telegram inline buttons or CLI approval.

### 3.2 Tool Registry Specification (`TOOL_REGISTRY_VERSION 0.1.0-draft`)

| Tool Identifier | Parameters | Description | Mutating? |
| :--- | :--- | :--- | :---: |
| `blue.get_alerts` | `min_severity: str, limit: int` | Retrieves active unhandled security alerts filtered by severity. | No |
| `blue.query_telemetry` | `query: str, time_range_s: int` | Performs granular queries across historical EDR/network logs. | No |
| `blue.threat_path` | `entity: str, max_hops: int` | Computes attack graph traversal using NetworkX knowledge graph. | No |
| `blue.propose_containment` | `target: str, action: str, dry_run: bool, ttl_seconds: int, reason: str` | Generates a reversible containment proposal with automatic TTL expiration. | No |
| `hitl.request_approval` | `proposal_id: str, summary: str, actions: list` | Dispatches an approval card to Telegram and CLI approval queue. | No |
| `hitl.approval_status` | `proposal_id: str` | Polls current status (`pending`, `approved`, `rejected`, `expired`). | No |
| `blue.apply_containment` | `proposal_id: str` | Executes containment strictly following verified HITL authorization. | **Yes** |
| `blue.revoke_containment` | `containment_id: str` | Reverses an active containment rule immediately. | **Yes** |

### 3.3 Safety Invariants for Containment
- **Propose-Only Invariant**: Meta Muse Spark cannot invoke `blue.apply_containment` directly. It can only call `blue.propose_containment` followed by `hitl.request_approval`. The orchestrator executes the mutation only upon external human confirmation.
- **Dry-Run Default**: All containment proposals default to `dry_run=True` unless explicitly promoted.
- **Mandatory TTL**: Every containment proposal must specify a non-zero `ttl_seconds` (default: 3600 seconds), ensuring automated reversal if an analyst is unreachable, preventing permanent network paralysis.

---

## 4. Red Team Bot Engine (`redteam/bot.py`)

### 4.1 Strict Lab Boundary Guardrail
To guarantee zero accidental operational impact on production networks, the bot engine hard-codes the allowed lab CIDR blocks:
```python
LAB_NETWORKS = [
    ipaddress.ip_network("192.168.56.0/24"),
    ipaddress.ip_network("10.10.10.0/24"),
]
```
Before any network probe, port connection, or simulation payload is dispatched, the destination IP is validated against `LAB_NETWORKS`. Any target outside these ranges immediately raises `ScopeViolation(f"Target {target} violates lab scope.")` and halts execution.

### 4.2 The FIVE Red Team Personas

The Red Team Bot operates under **FIVE distinct behavioral personas** required by the hackathon demonstration scenarios:

#### Persona 1: Brute-Force Infiltrator
- **Objective**: Initial access via aggressive credential guessing.
- **Behavior**: Emits rapid failed authentication bursts (e.g. 180 failed SSH attempts in 4 minutes against user `admin` on bastion `192.168.56.20`), culminating in one successful authenticated login.
- **Primary Signals**: `auth.log` failed password spikes, PAM auth failures, single anomalous success from same source.

#### Persona 2: Lateral Mover
- **Objective**: Network traversal and domain privilege expansion.
- **Behavior**: Originates from compromised workstation `lab-win10-03` (`192.168.56.31`), establishes an internal SMB session to `lab-dc-01` (`192.168.56.10`), and executes an obfuscated, base64-encoded PowerShell child process within 40 seconds of session creation.
- **Primary Signals**: EDR process creation tree (`powershell.exe -enc ...`), anomalous SMB Named Pipe activity.

#### Persona 3: Privilege Escalator
- **Objective**: Host-level privilege escalation and defensive evasion.
- **Behavior**: Attempts local token impersonation, shadow copy deletion (`vssadmin delete shadows /quiet`), and SAM/LSASS memory credential dumping.
- **Primary Signals**: Process memory access violations, high-severity endpoint Sigma rule matches (`proc_creation_win_vssadmin_shadow_delete`).

#### Persona 4: C2 Exfiltrator *(Mandatory for Scenario 2)*
- **Objective**: Persistent command channel establishment and bulk data egress.
- **Behavior**:
  1. Low-and-slow command-and-control beaconing from `lab-win10-03` to `10.10.10.88:8443` every 60s with uniform 184-byte payloads (Cobalt Strike JA3 fingerprint).
  2. High-entropy DNS TXT tunneling (3,900 queries to `*.data.example-cdn.net` from `lab-db-01` [10.10.10.21] within 10 minutes; entropy 4.6 bits).
  3. Bulk file exfiltration staging from `lab-file-01` (`10.10.10.32`) to external cloud storage (4.2GB upload).
- **Primary Signals**: Egress proxy telemetry, Zeek DNS query entropy spikes, DLP bulk upload alerts.

#### Persona 5: Benign User *(Mandatory for Scenario 3 — Credibility Discriminator)*
- **Objective**: Simulating legitimate enterprise operations to stress-test false-positive suppression.
- **Behavior**:
  1. Legitimate remote worker VPN login for user `prabhu` from a new external ASN at 03:12 IST with valid corporate device certificate and successful MFA.
  2. Scheduled, pre-announced internal security audit SYN port sweep of `10.10.10.0/24` from authorized scanner `lab-kali-01`.
  3. Routine OpenSSL package update (3.0.12 → 3.0.15) on `lab-db-01` with clean service restart and zero config drift.
  4. Internet scanner noise: 412 unauthenticated web probes on honeypot `web-01` (`192.168.56.40`) probing `/.git/HEAD` and `/wp-admin` with zero sessions established.
- **Primary Signals**: Valid MFA logs, scheduled scanner maintenance windows, clean patch audits, session-less honeypot probe counters.
- **Mandatory Policy Response**: Must output an explicit **"No Containment"** verdict. Zero containment proposals or HITL interrupts permitted.

---

## 5. End-to-End Demonstration Scenarios

### Scenario 1: Brute Force → Lateral Movement (Intrusion Kill-Chain)
1. **Input**: Persona 1 attacks `192.168.56.20` → Persona 2 pivots from `lab-win10-03` to `lab-dc-01` with encoded PowerShell.
2. **System-1 Triage**: Flags initial brute-force as `malicious` (Auto-Act isolation of attacker IP `192.168.56.20`). The subsequent SMB+PowerShell event confidence lands at 0.76 (< 0.85 threshold), triggering System-2 escalation.
3. **System-2 (Muse Spark) Flow**:
   - Calls `blue.get_alerts(min_severity="high")`
   - Calls `blue.threat_path(entity="lab-win10-03", max_hops=3)`
   - Proposes containment: Isolate `lab-win10-03` (`dry_run=true`, `ttl_seconds=3600`) and disable compromised `admin` credential. Crucially: leaves the Domain Controller online to prevent network outage.
   - Calls `hitl.request_approval(...)`
4. **Pass Criteria**: All 3 outputs produced (threat-path explanation, containment recommendation, remediation draft); no containment applied prior to HITL approval.

### Scenario 2: C2 Beacon + Exfiltration Attempt (Dual Egress Discrimination)
1. **Input**: Persona 4 initiates C2 beaconing on `lab-win10-03`, DNS tunneling on `lab-db-01`, and bulk 4.2GB upload on `lab-file-01`.
2. **System-1 Triage**: Detects high-volume egress anomalies; escalates to Muse Spark due to overlapping simultaneous alerts across multiple hosts.
3. **System-2 (Muse Spark) Flow**:
   - Calls `blue.query_telemetry` to inspect beacon cadence (60s) vs bulk data transfer.
   - Calls `blue.threat_path("lab-win10-03")`.
   - Proposes granular containment: Block egress to `10.10.10.88:8443`, isolate beaconing host `lab-win10-03`, inspect DNS tunnel on `lab-db-01`. **Rejects blanket lab subnet shutdown.**
   - Calls `hitl.request_approval(...)`.
4. **Pass Criteria**: Accurately distinguishes beaconing host from bulk-upload host; containment is reversible with TTL; zero blanket subnet disruptions.

### Scenario 3: Benign Discriminator (False-Positive Suppression)
1. **Input**: Persona 5 executes valid MFA VPN login, scheduled vulnerability scan from `lab-kali-01`, and routine database patching.
2. **System-1 Triage**: Correctly identifies valid MFA and known scanner IP; confidence exceeds 0.85 for `benign` classification.
3. **System-2 (Muse Spark) Flow** *(Verification audit mode)*:
   - Queries telemetry for MFA token status and scheduled maintenance window.
   - **Stops**. Does NOT call `blue.propose_containment` or `hitl.request_approval`.
4. **Pass Criteria**: Exactly zero containment proposals and zero human interruptions. Provides transparent justification for every benign signal.

---

## 6. Implementation Plan & Directory Structure

```
sentinel-v4/
├── docs/
│   ├── designs/
│   │   └── orchestrator-bots-design.md     <-- THIS DESIGN DOCUMENT
│   ├── sentinel-v4-days2-3-scenarios.md
│   └── DEMO_VIDEO_SCREENPLAY.md
├── orchestrator/
│   ├── __init__.py
│   ├── chief_sentinel.py                 <-- Master Dual-System Loop
│   ├── routing_gate.py                   <-- 0.85 Confidence Decision Logic
│   └── hitl_manager.py                   <-- Telegram & CLI Approval Bridge
├── redteam/
│   ├── __init__.py
│   ├── bot.py                            <-- Red Team Bot Engine (Scope Guardrail)
│   └── personas/
│       ├── __init__.py
│       ├── brute_force.py                <-- Persona 1
│       ├── lateral_mover.py              <-- Persona 2
│       ├── privilege_escalator.py        <-- Persona 3
│       ├── c2_exfiltrator.py             <-- Persona 4
│       └── benign_user.py                <-- Persona 5
├── model_adapter/
│   ├── laya_adapter.py                   <-- Local System-1 Laya Wrapper
│   └── muse_spark_adapter.py             <-- Meta Model API System-2 Wrapper
├── tools/
│   ├── registry.py                       <-- MCP Blue & Red Team Tools
│   └── containment.py                    <-- Reversible SOAR Handlers
└── tests/
    ├── test_orchestrator.py              <-- Unit tests for routing gate
    ├── test_redteam_scope.py             <-- ScopeViolation enforcement tests
    └── test_scenarios.py                 <-- End-to-end tests for Scenarios 1-3
```

---

## 7. Quality & Verification Gates Before Code Execution

Per our strict project guardrails:
1. **Design Approval Gate**: This document must be reviewed and approved prior to creating or modifying any python implementation code in `orchestrator/` or `redteam/`.
2. **Karpathy Coding Standards**: Implementation must touch only required lines, write minimal code, and reproduce any bug with a test before fixing.
3. **Scope Enclosure**: Every test against `redteam/bot.py` must verify that out-of-scope destination IPs (e.g. `103.21.244.9` or `8.8.8.8`) raise `ScopeViolation`.
