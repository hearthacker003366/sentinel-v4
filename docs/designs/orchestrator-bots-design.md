# Sentinel V4 — Chief Sentinel Orchestrator & Red Team Bot Design
**Document Path:** `docs/designs/orchestrator-bots-design.md`  
**Platform:** Meta Global AI Developer Hackathon 2026 (Track: *Build for Your World*)  
**Status:** Step 1 Architectural Design Specification (Amended & Hardened per Review)  
**Date:** November 2026  

---

## 1. Executive Summary & Objective

In **Sentinel V4**, defense orchestration shifts from fragile static automation to an adaptive, dual-system cognitive architecture. Security Operations Centers (SOCs) are overwhelmed by alert fatigue (where over 70% of alerts are noise) while sophisticated multi-hop intrusions and living-off-the-land attacks slip past perimeter defenses.

This specification details the architecture for:
1. **Chief Sentinel Orchestrator (`orchestrator/chief_sentinel.py`)**: The master dual-system coordinator binding local edge triage (System-1 Laya), cloud cognitive reasoning (System-2 Meta Muse Spark), a tamper-resistant Human-in-the-Loop (HITL) approval gate, and a deterministic offline fallback engine.
2. **Red Team Bot Engine (`redteam/bot.py`)**: An adversarial simulator enforcing strict lab network containment (`ScopeViolation`) while executing **FIVE atomic single-shot adversary personas** paced across three end-to-end benchmark scenarios.

---

## 2. High-Level System Architecture

```
   [ Telemetry Stream / Syslog / EDR / Network ]
                         │
                         ▼
             ┌─────────────────────────┐
             │ Chief Sentinel          │
             │ Orchestrator Engine     │
             │ (Daemon or Interactive) │
             └───────────┬─────────────┘
                         │
        ┌────────────────┴────────────────┐
        ▼                                 ▼
┌─────────────────────────┐     ┌─────────────────────────┐
│ System-1: Edge Triage   │     │ System-2: Cognitive LLM │
│ Laya Classifier (Local) │     │ Meta Muse Spark 1.3     │
│ • Verified 45ms latency │     │ • Tool Use via MCP      │
│ • RTX 4050 GPU / CPU    │     │ • Multi-Hop Path Reason │
│ • 0.85 Auto-Act Gate    │     │ • Propose-Only Policy   │
│ • Dry-Run ONLY Actions  │     │ • Fallback Banner Mode  │
└───────────┬─────────────┘     └───────────┬─────────────┘
            │                               │
    Confidence >= 0.85              Confidence < 0.85
   (83.2% Autonomous)              (16.8% Escalation)
            │                               │
            ▼                               ▼
┌─────────────────────────┐     ┌─────────────────────────┐
│ Dry-Run SOAR Simulation │     │ Unified HITL Gate       │
│ & Honeypot Trap Routing │     │ (Telegram & CLI Shared) │
└─────────────────────────┘     └───────────┬─────────────┘
                                            │ APPROVE <token>
                                            │ Human Analyst
                                            ▼
                                ┌─────────────────────────┐
                                │ Orchestrator-Internal   │
                                │ Reversible Containment  │
                                │ (Config-Stamped TTL)    │
                                └─────────────────────────┘
```

---

## 3. Chief Sentinel Orchestrator Architecture

### 3.1 Dual Operating Modes, Single Pipeline
The orchestrator supports two operational interfaces, both driving the exact same underlying `ChiefSentinelEngine` pipeline:
- **Headless Daemon Mode (Default)**: `python -m orchestrator.chief_sentinel`
  Runs continuously in the background, listening to incoming telemetry sockets or tailing log sources (`auth.log`, Zeek JSON, EDR event pipes), emitting asynchronous triage alerts and queuing HITL tokens.
- **Interactive Console Mode**: `python -m orchestrator.chief_sentinel --interactive`
  Launches an interactive operator REPL for security analysts to observe live triage streams, inspect threat graphs, review proposals, and input console approvals (`APPROVE <token>`).

### 3.2 System-1 Triage & The 0.85 Gate
1. Telemetry events are normalized into schema-compliant dictionaries (`source_ip`, `dest_ip`, `event_type`, `payload`, `timestamp`).
2. The event is triaged by local **Laya** (`training/laya-tuned-v1` on RTX 4050 / CPU), running with a verified **45ms mean latency** (51ms median).
3. Laya outputs four calibrated attributes:
   - `verdict` (`benign`, `suspicious`, `malicious`)
   - `winner_confidence` ($P \in [0.0, 1.0]$)
   - `is_attack` (boolean)
   - `severity` (continuous scale $[0.0, 1.0]$)
4. **The 0.85 Routing Gate**:
   - `winner_confidence >= 0.85`: Handled autonomously by System-1. To preserve operational safety, System-1 auto-act is strictly **dry-run ONLY**. It records simulated honeypot routes or containment actions in the telemetry ledger, but **never** performs mutating live network changes unilaterally.
   - `winner_confidence < 0.85`: Escalated immediately to System-2 (Meta Muse Spark) along with local host topology and historical alert context.

### 3.3 System-2 (Meta Muse Spark) & Tool Registry Specification

System-2 is invoked via the Meta Model API. Only non-mutating query and proposal tools are exposed to the model via the MCP Blue Team Tool Registry.

#### Tool Registry (`TOOL_REGISTRY_VERSION 0.1.0-draft`)

| Tool Identifier | Parameters | Description | Exposed to Model? |
| :--- | :--- | :--- | :---: |
| `blue.get_alerts` | `min_severity: str, limit: int` | Retrieves active unhandled security alerts filtered by severity. | **Yes** |
| `blue.query_telemetry` | `query: str, time_range_s: int` | Queries historical EDR, proxy, and network telemetry. | **Yes** |
| `blue.threat_path` | `entity: str, max_hops: int` | Computes attack graph traversal using NetworkX knowledge graph. | **Yes** |
| `blue.propose_containment` | `target: str, action: str, reason: str` | Generates a containment proposal. **Model cannot set dry-run or TTL.** | **Yes** |
| `hitl.request_approval` | `proposal_id: str, summary: str` | Dispatches an approval card with token to Telegram and CLI. | **Yes** |
| `hitl.approval_status` | `proposal_id: str` | Polls current status (`pending`, `approved`, `rejected`, `expired`). | **Yes** |
| `blue.apply_containment` | `proposal_id: str, auth_token_hash: str` | **Orchestrator-Internal Only.** Executes authorized containment. | **NO (Hidden)** |
| `blue.revoke_containment` | `containment_id: str` | **Orchestrator-Internal Only.** Reverses active containment upon TTL expiry. | **NO (Hidden)** |

#### Crucial Tool Governance Invariant
In `blue.propose_containment`, `dry_run`, `ttl_seconds`, and allowed action validation are **stamped strictly by the orchestrator** from operator configuration (`config.yaml`), NEVER set by the model:
- The model passes only `target`, `action`, and `reason`.
- The orchestrator stamps `dry_run=True`, sets `ttl_seconds=3600`, validates `action` against an operator whitelist, assigns a cryptographically unique `proposal_id`, and generates the single-use HITL approval token.
- `blue.apply_containment` is completely hidden from the model's tool definitions. The model has zero capability to trigger mutations directly.

---

## 4. Human-in-the-Loop (HITL) Subsystem Specification

To prevent catastrophic unauthorized actions while maintaining auditability, the HITL subsystem enforces five cryptographic and operational invariants:

```
┌────────────────────────────────────────────────────────┐
│ Muse Spark calls blue.propose_containment(...)         │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│ Orchestrator stamps dry_run=True, TTL=3600s,           │
│ generates random single-use token: e.g. "a9f4c2e1",   │
│ stores SHA-256(token) bound to (target + action).      │
└───────────────────────────┬────────────────────────────┘
                            │
             ┌──────────────┴──────────────┐
             ▼                             ▼
┌─────────────────────────┐   ┌─────────────────────────┐
│ Telegram Inline Card    │   │ Terminal Console Queue  │
│ [Approve] / [Reject]    │   │ Command: APPROVE <token>│
└────────────┬────────────┘   └────────────┬────────────┘
             │                             │
             └──────────────┬──────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│ Unified Shared Lockout Check:                          │
│ • Max 3 failed attempts across BOTH Telegram & Console │
│ • 4th failure triggers 15-minute global lockout        │
│ • Token verified against SHA-256 hash (single-use)     │
└───────────────────────────┬────────────────────────────┘
                            │ Valid Approval
                            ▼
┌────────────────────────────────────────────────────────┐
│ Orchestrator executes blue.apply_containment internal  │
│ Audit log records: SHA-256(token), NEVER raw token     │
│ Token is IMMEDIATELY invalidated and destroyed         │
└────────────────────────────────────────────────────────┘
```

1. **Single-Use Cryptographic Token**:
   - Generated using `secrets.token_hex(4)` (8-character alphanumeric string).
   - Strictly single-use. Once verified, the token is burned immediately. Any secondary attempt with the same token fails with `TokenAlreadyConsumed`.
2. **Short Time-to-Live (TTL)**:
   - Approval tokens expire automatically after 300 seconds (5 minutes) if unconfirmed. Expired tokens transition the proposal to `EXPIRED` status and revoke pending dry-runs.
3. **Strict Target/Action Binding**:
   - The token is cryptographically bound in state to `hash(proposal_id + target + action)`. It cannot be replayed or transposed to authorize any other action or target.
4. **Console Door & Telegram Interface**:
   - Terminal interactive command: `APPROVE <token>` or `REJECT <token>`.
   - Telegram Bot: Inline callback button passing the approval payload to the webhook handler.
5. **Unified Shared Lockout Counter**:
   - Telegram and Console share **ONE** atomic, thread-safe failed-attempt counter.
   - Any incorrect or malformed token submitted via Telegram or Console increments the shared counter.
   - Upon **3 consecutive failed attempts**, the entire HITL interface locks out for **15 minutes**, raising an alert.
6. **Audit Privacy & Zero Auto-Approve**:
   - The security audit log (`sentinel.db` / audit JSONL) stores ONLY the SHA-256 fingerprint (`hashlib.sha256(token.encode()).hexdigest()`), NEVER the plaintext token.
   - **Zero Auto-Approve Invariant**: No automatic approval bypass or fallback exists under any circumstance. Unapproved actions permanently abort.

---

## 5. System-2 Fallback & Offline Resilience

To ensure deterministic evaluation and graceful degradation during network partitions or missing API credentials:

1. **Key Configuration**:
   - The Meta Model API key is read strictly from environment variables: `META_MODEL_API_KEY` (or alias `MUSE_API_KEY`). Documented clearly in `.env.example`.
   - No API keys are ever committed to repository code or config files.
2. **Offline Deterministic Fallback**:
   - If `META_MODEL_API_KEY` is missing, empty, or if network connectivity to the Meta Model API fails/times out, System-2 seamlessly switches to deterministic recorded scenario responses (`fixtures/scenarios/scenario_{1,2,3}_muse_response.json`).
3. **Mandatory Visual Fallback Banner**:
   - Whenever offline fallback is active, all terminal outputs, CLI logs, and web dashboard payloads must prominently carry the exact banner:
     ```
     [WARNING] LIVE MODEL UNAVAILABLE — RECORDED RESPONSE
     ```
4. **Zero Local-Model Reasoning Fallback**:
   - Sentinel V4 does **NOT** attempt to fall back to a heavy local LLM or down-sample reasoning to Laya. Laya is exclusively an edge triage classifier; high-order reasoning without the Meta API relies strictly on verified recorded fixtures carrying the explicit visual banner.

---

## 6. Red Team Bot Engine (`redteam/bot.py`)

### 6.1 Network Enclosure Guardrail
The adversary simulator operates strictly inside the isolated simulated lab CIDRs:
```python
LAB_NETWORKS = [
    ipaddress.ip_network("192.168.56.0/24"),
    ipaddress.ip_network("10.10.10.0/24"),
]
```
Any target IP outside these two networks triggers an immediate `ScopeViolation` exception before emitting any packets or simulated logs.

### 6.2 Atomic Single-Shot Personas with 1–3s Loop Pacing
Rather than stateful, unpredictable background daemons, all personas are implemented as **atomic single-shot trigger functions** that emit discrete, deterministic event batches. The runner loop introduces **1–3 seconds of pacing** between bursts:

```python
# Atomic Persona Functions
def trigger_brute_force(target_ip: str = "192.168.56.20", count: int = 180) -> list[dict]: ...
def trigger_lateral_move(src_host: str = "192.168.56.31", dst_host: str = "192.168.56.10") -> list[dict]: ...
def trigger_privilege_escalation(host: str = "192.168.56.31") -> list[dict]: ...
def trigger_c2_exfiltration(host: str = "192.168.56.31", sink_ip: str = "10.10.10.99") -> list[dict]: ...
def trigger_benign_user(username: str = "prabhu", host: str = "192.168.56.31") -> list[dict]: ...
```

#### Persona 1: Brute-Force Infiltrator
- **Trigger**: `trigger_brute_force(target_ip="192.168.56.20", count=180)`
- **Behavior**: Emits 180 failed SSH authentication attempts within 4 minutes against user `admin` on bastion `192.168.56.20`, followed by 1 successful login.

#### Persona 2: Lateral Mover
- **Trigger**: `trigger_lateral_move(src_host="192.168.56.31", dst_host="192.168.56.10")`
- **Behavior**: Emits SMB session establishment from `lab-win10-03` (`192.168.56.31`) to Domain Controller `lab-dc-01` (`192.168.56.10`), followed within 40 seconds by an obfuscated `powershell.exe -enc <base64>` execution.

#### Persona 3: Privilege Escalator
- **Trigger**: `trigger_privilege_escalation(host="192.168.56.31")`
- **Behavior**: Simulates local privilege escalation via `vssadmin delete shadows /quiet` and LSASS memory access violations on `lab-win10-03`.

#### Persona 4: C2 Exfiltrator *(Mandatory for Scenario 2)*
- **Trigger**: `trigger_c2_exfiltration(host="192.168.56.31", sink_ip="10.10.10.99")`
- **Behavior**:
  1. Low-and-slow C2 beaconing to lab egress proxy `10.10.10.88:8443` every 60s (184-byte uniform payloads, JA3 Cobalt Strike fingerprint).
  2. High-entropy DNS TXT queries (3,900 requests, 4.6 bits entropy) from `lab-db-01` (`10.10.10.21`).
  3. Bulk exfiltration staging: 4.2 GB data transfer from `lab-file-01` (`10.10.10.32`) sinking strictly into simulated internal lab sink **`10.10.10.99`** inside `10.10.10.0/24`. Zero packets exit lab scope.

#### Persona 5: Benign User *(Mandatory for Scenario 3 — Credibility Discriminator)*
- **Trigger**: `trigger_benign_user(username="prabhu", host="192.168.56.31")`
- **Behavior**:
  1. Legitimate remote worker VPN authentication for `prabhu` from external ASN with valid device certificate and passing MFA at 03:12 IST.
  2. Scheduled, in-scope security audit SYN port sweep of `10.10.10.0/24` from authorized audit workstation `lab-kali-01`.
  3. Clean OpenSSL package upgrade (3.0.12 → 3.0.15) on `lab-db-01` with clean daemon restart.
  4. Routine unauthenticated honeypot noise on `web-01` (`192.168.56.40`) (412 probes to `/.git/HEAD`, zero authenticated sessions).
- **Mandatory Policy Verdict**: Explicit **"No Containment"**. Zero HITL cards generated, zero disruption.

---

## 7. End-to-End Demonstration Scenarios

### Scenario 1: Brute Force → Lateral Movement (Intrusion Kill-Chain)
1. **Paced Execution**: `trigger_brute_force()` → 2s pause → `trigger_lateral_move()`.
2. **System-1 Triage**: Triage classifies brute-force as `malicious` with 0.96 confidence; records dry-run attacker block. The subsequent SMB lateral pivot drops confidence to 0.76 (< 0.85 threshold), escalating to Muse Spark.
3. **System-2 Reasoning**:
   - Calls `blue.get_alerts(min_severity="high")`
   - Calls `blue.threat_path(entity="lab-win10-03", max_hops=3)`
   - Proposes containment via `blue.propose_containment(target="lab-win10-03", action="isolate", reason="Compromised staging host")`. (Orchestrator stamps `dry_run=True, ttl=3600`).
   - Calls `hitl.request_approval(proposal_id=...)`.
4. **Analyst Approval**: Human inputs `APPROVE <token>` via console or Telegram button.
5. **Pass Criteria**: Containment applied only after token validation; Domain Controller remains untouched; full threat path documented.

### Scenario 2: C2 Beacon + Exfiltration Attempt (Dual Egress Discrimination)
1. **Paced Execution**: `trigger_c2_exfiltration()`.
2. **System-1 Triage**: Flags overlapping anomalous egress; escalates ambiguous multi-host correlation to System-2.
3. **System-2 Reasoning**:
   - Calls `blue.query_telemetry` to separate 60s periodic beaconing from bulk file transfer.
   - Proposes targeted egress block for `10.10.10.88:8443` and host isolation for `lab-win10-03`. Explicitly rejects blanket subnet shutdown.
4. **Pass Criteria**: Reversible containment proposed with TTL; accurately discriminates beaconing host from bulk-upload host; zero out-of-scope traffic.

### Scenario 3: Benign Discriminator (False-Positive Suppression)
1. **Paced Execution**: `trigger_benign_user()`.
2. **System-1 Triage**: Evaluates valid MFA token and scheduled maintenance tag; confidence exceeds 0.85 for `benign`.
3. **System-2 Reasoning**: Audits telemetry, verifies valid credentials, and explicitly terminates without generating any containment proposals or approval requests.
4. **Pass Criteria**: Zero HITL interrupts, zero containment applied, transparent reasoning log explaining why alerts are benign.

---

## 8. Verification & Test Plan

Before implementation code is signed off, the following automated test suite must execute and pass:

| Test Identifier | File | Objective |
| :--- | :--- | :--- |
| `test_gate_boundary_exact_0_85` | `tests/test_routing_gate.py` | Verifies score $0.8500 \implies$ System-1 auto-act; score $0.8499 \implies$ System-2 escalation. |
| `test_atomic_trigger_determinism` | `tests/test_personas.py` | Confirms all 5 persona functions return deterministic, schema-compliant events. |
| `test_lab_scope_violation_raised` | `tests/test_personas.py` | Verifies that injecting an out-of-scope IP (e.g. `8.8.8.8`) raises `ScopeViolation`. |
| `test_hitl_token_single_use` | `tests/test_hitl.py` | Proves re-using a consumed approval token raises `TokenAlreadyConsumed`. |
| `test_shared_lockout_counter` | `tests/test_hitl.py` | Confirms 3 failed token attempts across Telegram/CLI triggers 15-minute lockout. |
| `test_token_hash_in_audit_log` | `tests/test_hitl.py` | Asserts the raw token is never written to DB or logs; only SHA-256 hash is stored. |
| `test_system2_fallback_banner` | `tests/test_system2_fallback.py` | Validates that missing `META_MODEL_API_KEY` triggers recorded fixtures and stamps `"LIVE MODEL UNAVAILABLE — RECORDED RESPONSE"`. |
| `test_laya_latency_boundary` | `tests/test_laya_adapter.py` | Verifies Laya steady-state inference averages **45ms** (sub-55ms ceiling). |

---

## 9. Implementation Plan & Directory Structure

```
sentinel-v4/
├── docs/
│   ├── designs/
│   │   └── orchestrator-bots-design.md     <-- THIS AMENDED DESIGN DOCUMENT
│   ├── sentinel-v4-days2-3-scenarios.md
│   └── DEMO_VIDEO_SCREENPLAY.md
├── fixtures/
│   └── scenarios/
│       ├── scenario_1_muse_response.json  <-- Recorded System-2 Fixture
│       ├── scenario_2_muse_response.json  <-- Recorded System-2 Fixture
│       └── scenario_3_muse_response.json  <-- Recorded System-2 Fixture
├── orchestrator/
│   ├── __init__.py
│   ├── chief_sentinel.py                 <-- Daemon & Interactive Engine
│   ├── routing_gate.py                   <-- Calibrated 0.85 Boundary Gate
│   └── hitl_manager.py                   <-- Unified Token & Lockout Gate
├── redteam/
│   ├── __init__.py
│   ├── bot.py                            <-- Runner with 1-3s Pacing
│   └── personas/
│       ├── __init__.py
│       ├── brute_force.py                <-- Persona 1 Trigger
│       ├── lateral_mover.py              <-- Persona 2 Trigger
│       ├── privilege_escalator.py        <-- Persona 3 Trigger
│       ├── c2_exfiltrator.py             <-- Persona 4 Trigger (Lab Sink)
│       └── benign_user.py                <-- Persona 5 Trigger
├── model_adapter/
│   ├── laya_adapter.py                   <-- Local 45ms System-1 Wrapper
│   └── muse_spark_adapter.py             <-- Meta Model API + Fallback Banner
├── tools/
│   ├── registry.py                       <-- Model-Exposed MCP Blue Tools
│   └── containment.py                    <-- Orchestrator-Internal SOAR Handlers
└── tests/
    ├── test_routing_gate.py
    ├── test_personas.py
    ├── test_hitl.py
    ├── test_system2_fallback.py
    └── test_laya_adapter.py
```
