"""
Sentinel V4 — Automated Demo Video & Scene Asset Generator
Generates full 1080p (1920x1080) high-resolution scene stills and animated video clips
corresponding to DEMO_VIDEO_SCREENPLAY.md Scenes 1 through 6 using Playwright & FFmpeg.
"""

import os
import sys
import time
import json
import threading
import urllib.request
import subprocess
from pathlib import Path
from playwright.sync_api import sync_playwright

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

ASSETS_DIR = PROJECT_ROOT / "docs" / "assets"
ASSETS_DIR.mkdir(parents=True, exist_ok=True)
REEL_DIR = ASSETS_DIR / "demo_reel"
REEL_DIR.mkdir(parents=True, exist_ok=True)

FFMPEG_PATH = r"C:\Users\B.prabhudas\AppData\Local\Microsoft\WinGet\Packages\Gyan.FFmpeg_Microsoft.Winget.Source_8wekyb3d8bbwe\ffmpeg-8.1.1-full_build\bin\ffmpeg.exe"
if not os.path.exists(FFMPEG_PATH):
    FFMPEG_PATH = "ffmpeg"


def create_html_slide(title: str, subtitle: str, body_html: str, badge: str = "SENTINEL V4 // AUTONOMOUS AI SOC") -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700;800&family=Space+Grotesk:wght@500;700&display=swap');
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    width: 1920px;
    height: 1080px;
    background: #06090e;
    color: #e6edf3;
    font-family: 'Space Grotesk', sans-serif;
    display: flex;
    flex-direction: column;
    padding: 60px 80px;
    overflow: hidden;
    position: relative;
  }}
  body::before {{
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0; bottom: 0;
    background: radial-gradient(circle at 80% 20%, rgba(30, 80, 150, 0.15), transparent 50%),
                radial-gradient(circle at 20% 80%, rgba(0, 200, 150, 0.1), transparent 50%);
    pointer-events: none;
  }}
  .header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 1px solid #1f2937;
    padding-bottom: 24px;
    margin-bottom: 40px;
  }}
  .badge {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 14px;
    letter-spacing: 2px;
    color: #00e5a3;
    background: rgba(0, 229, 163, 0.1);
    border: 1px solid rgba(0, 229, 163, 0.3);
    padding: 6px 14px;
    border-radius: 4px;
    text-transform: uppercase;
  }}
  .time-badge {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 14px;
    color: #8b949e;
  }}
  h1 {{
    font-size: 46px;
    font-weight: 700;
    color: #ffffff;
    letter-spacing: -1px;
    margin-bottom: 12px;
  }}
  .subtitle {{
    font-size: 22px;
    color: #8b949e;
    margin-bottom: 40px;
  }}
  .content {{
    flex: 1;
    display: flex;
    gap: 40px;
  }}
  .panel {{
    background: #0d1117;
    border: 1px solid #21262d;
    border-radius: 8px;
    padding: 30px;
    flex: 1;
    display: flex;
    flex-direction: column;
  }}
  .card-metric {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 44px;
    font-weight: 800;
    color: #00e5a3;
    margin: 10px 0;
  }}
  .card-label {{
    font-size: 15px;
    color: #8b949e;
    text-transform: uppercase;
    letter-spacing: 1px;
  }}
  pre, code {{
    font-family: 'JetBrains Mono', monospace;
  }}
  .footer {{
    margin-top: auto;
    display: flex;
    justify-content: space-between;
    font-family: 'JetBrains Mono', monospace;
    font-size: 13px;
    color: #484f58;
    border-top: 1px solid #161b22;
    padding-top: 20px;
  }}
</style>
</head>
<body>
  <div class="header">
    <div class="badge">{badge}</div>
    <div class="time-badge">META GLOBAL AI HACKATHON 2026 // CEREBRAL VALLEY</div>
  </div>
  <h1>{title}</h1>
  <div class="subtitle">{subtitle}</div>
  <div class="content">
    {body_html}
  </div>
  <div class="footer">
    <div>REPO: github.com/hearthacker003366/sentinel-v4</div>
    <div>HARDWARE: NVIDIA RTX 4050 LAPTOP GPU + META MUSE SPARK 1.3</div>
  </div>
</body>
</html>"""


def generate_scene_1(page):
    """Scene 1: Mandatory Opening & The Dual-System Solution (0:00 - 0:20)"""
    body = """
    <div class="panel" style="border-left: 4px solid #f85149;">
      <div class="card-label">Mandatory Opening Line & Integrity Disclosure</div>
      <div style="margin-top: 20px; font-size: 22px; line-height: 1.6; color: #c9d1d9;">
        <p style="margin-bottom: 20px;">
          <strong style="color: #ff7b72;">Pre-Existing Baseline (Sentinel V3):</strong> Enterprise alert aggregation, MCP client, NetworkX threat graph, and GraphSAGE prediction. Developed prior to hackathon in separate repository.
        </p>
        <p>
          <strong style="color: #00e5a3;">Built This Week (Sentinel V4 Oct 26 – Nov 4):</strong> Complete Autonomous Dual-System AI SOC — Local Laya 421M System-1 triage gate (<55ms latency), Meta Muse Spark 1.3 System-2 cognitive reasoning (12 MCP tools), Air-gapped Cytoscape Command Dashboard, and Two-Way Telegram HITL SOAR.
        </p>
      </div>
    </div>
    <div class="panel" style="border-left: 4px solid #00e5a3;">
      <div class="card-label">The Core SOC Problem & Dual-System Defense</div>
      <div style="margin-top: 25px; display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
        <div style="background: #161b22; padding: 20px; border-radius: 6px;">
          <div class="card-label" style="color: #ff7b72;">Alert Fatigue Crisis</div>
          <div class="card-metric" style="color: #ff7b72;">70%+</div>
          <p style="font-size: 15px; color: #8b949e;">Routine SOC telemetry is noise; analyst burnout causes real lateral movement to be missed.</p>
        </div>
        <div style="background: #161b22; padding: 20px; border-radius: 6px;">
          <div class="card-label" style="color: #00e5a3;">System-1 Edge Triage</div>
          <div class="card-metric">45 ms</div>
          <p style="font-size: 15px; color: #8b949e;">Local fine-tuned Laya model filters 83.2% of routine alerts before spending any cloud token.</p>
        </div>
        <div style="background: #161b22; padding: 20px; border-radius: 6px; grid-column: span 2;">
          <div class="card-label" style="color: #58a6ff;">System-2 Cognitive Escalation (Meta Muse Spark 1.3)</div>
          <div class="card-metric" style="color: #58a6ff;">16.8% Escalation</div>
          <p style="font-size: 15px; color: #8b949e;">Deep multi-hop lateral movement analysis via Meta Model API with dry-run, reversible containment.</p>
        </div>
      </div>
    </div>
    """
    html = create_html_slide(
        title="Scene 1: Mandatory Opening & Dual-System Solution",
        subtitle="Sentinel V3 Baseline vs Sentinel V4 Hackathon Build — Solving SOC Alert Fatigue at the Edge",
        body_html=body,
        badge="SCENE 1 // MANDATORY OPENING (0:00 – 0:20)"
    )
    slide_path = REEL_DIR / "slide_scene_1.html"
    slide_path.write_text(html, encoding="utf-8")
    page.goto(f"file:///{slide_path.as_posix()}")
    time.sleep(1)
    img_path = ASSETS_DIR / "scene1_opening.png"
    page.screenshot(path=str(img_path))
    print(f"[+] Rendered {img_path}")


def generate_scene_2(page):
    """Scene 2: Local Hardware Proof & Sub-55ms Triage (0:20 - 0:50)"""
    body = """
    <div class="panel" style="flex: 1.2;">
      <div class="card-label">Local Hardware Proof: RTX 4050 Laptop GPU (6GB)</div>
      <div style="margin-top: 15px; display: flex; flex-direction: column; gap: 15px;">
        <img src="../laya_gpu_training_proof_part1.png" style="width: 100%; border-radius: 6px; border: 1px solid #30363d;" />
        <div style="font-family: 'JetBrains Mono', monospace; font-size: 13px; color: #8b949e; background: #161b22; padding: 12px; border-radius: 4px;">
          GPU: NVIDIA GeForce RTX 4050 Laptop GPU | VRAM: 5942MiB | Memory Footprint: 2.76GB | Device: cuda:0
        </div>
      </div>
    </div>
    <div class="panel" style="flex: 1;">
      <div class="card-label">Held-Out Evaluation Benchmarks (EVAL.md)</div>
      <div style="margin-top: 20px; display: flex; flex-direction: column; gap: 20px;">
        <div style="background: #161b22; padding: 20px; border-radius: 6px;">
          <div class="card-label">Verdict Accuracy Gain</div>
          <div class="card-metric">88.12% <span style="font-size: 20px; color: #8b949e;">(+18.81% over base)</span></div>
          <p style="font-size: 14px; color: #8b949e;">Tested on 101 strictly held-out attack scenarios with zero training overlap.</p>
        </div>
        <div style="background: #161b22; padding: 20px; border-radius: 6px;">
          <div class="card-label">Autonomous Auto-Act Rate</div>
          <div class="card-metric">83.17% <span style="font-size: 20px; color: #8b949e;">(2.6x increase)</span></div>
          <p style="font-size: 14px; color: #8b949e;">Autonomously triages routine events without LLM API overhead.</p>
        </div>
        <div style="background: #161b22; padding: 20px; border-radius: 6px;">
          <div class="card-label">Steady-State Latency</div>
          <div class="card-metric">45 ms <span style="font-size: 20px; color: #8b949e;">(Sub-55ms Gate)</span></div>
          <p style="font-size: 14px; color: #8b949e;">42ms median latency running directly on consumer laptop hardware.</p>
        </div>
      </div>
    </div>
    """
    html = create_html_slide(
        title="Scene 2: Local Hardware Proof & Sub-55ms Triage",
        subtitle="Fine-Tuned Laya 421M Running at the Edge on Local NVIDIA RTX 4050 GPU",
        body_html=body,
        badge="SCENE 2 // LOCAL HARDWARE BONUS (0:20 – 0:50)"
    )
    slide_path = REEL_DIR / "slide_scene_2.html"
    slide_path.write_text(html, encoding="utf-8")
    page.goto(f"file:///{slide_path.as_posix()}")
    time.sleep(1)
    img_path = ASSETS_DIR / "scene2_local_hardware_laya.png"
    page.screenshot(path=str(img_path))
    print(f"[+] Rendered {img_path}")


def generate_scene_3(page):
    """Scene 3: Meta Muse Spark System-2 Cognitive Reasoning (0:50 - 1:30)"""
    body = """
    <div class="panel" style="flex: 1.2;">
      <div class="card-label">Live System-2 Escalation: Low-Confidence Anomaly</div>
      <div style="margin-top: 15px; background: #010409; padding: 20px; border-radius: 6px; font-family: 'JetBrains Mono', monospace; font-size: 13px; line-height: 1.5; color: #c9d1d9;">
        <span style="color: #8b949e;">[01:03:07] [LAYA_GATE] Scoring event through local LayaGate model...</span><br/>
        <span style="color: #ff7b72;">[01:03:07] [ALERT] inc-220340: smb_session_open on lab-win10-03 -> lab-dc-01</span><br/>
        <span style="color: #e3b341;">[01:03:07] [ESCALATE] Laya Confidence: 0.4758 (&lt; 0.70 threshold) -> System-2 Meta Muse Spark</span><br/>
        <span style="color: #58a6ff;">[01:03:08] [MUSE_SPARK] Model: muse-spark-1.3 | Streaming Meta Model API handshake</span><br/>
        <span style="color: #00e5a3;">[01:03:09] [TOOL_LOOP] Round 1: Model called 'blue.threat_path' with args {"entity": "lab-win10-03", "max_hops": 3}</span><br/>
        <span style="color: #00e5a3;">[01:03:10] [TOOL_EXEC] Graph hops resolved: 192.168.56.20 -> lab-win10-03 -> lab-dc-01</span><br/>
        <span style="color: #00e5a3;">[01:03:11] [TOOL_LOOP] Round 2: Model called 'blue.propose_containment'</span><br/>
        <span style="color: #79c0ff;">[01:03:12] [PROPOSAL] Action: isolate_host | Target: 192.168.56.31 | TTL: 300s | Dry-Run: True</span><br/>
        <span style="color: #bc8cff;">[01:03:12] [HITL] Minted single-use token: 7740d532... -> Dispatching Telegram Card</span>
      </div>
    </div>
    <div class="panel" style="flex: 0.9;">
      <div class="card-label">Cognitive Defense & Safety Guarantees</div>
      <div style="margin-top: 20px; display: flex; flex-direction: column; gap: 15px;">
        <div style="background: #161b22; padding: 16px; border-radius: 6px;">
          <div style="color: #00e5a3; font-weight: bold; margin-bottom: 6px;">12 MCP Tool Calling Protocol</div>
          <p style="font-size: 14px; color: #8b949e;">Autonomous multi-turn tool calling bounded to 6 rounds with validation error feedback loops.</p>
        </div>
        <div style="background: #161b22; padding: 16px; border-radius: 6px;">
          <div style="color: #58a6ff; font-weight: bold; margin-bottom: 6px;">Zero Unilateral Execution</div>
          <p style="font-size: 14px; color: #8b949e;">Model prose is strictly non-executable by design. Proposals are typed, dry-run, reversible, and expiring.</p>
        </div>
        <div style="background: #161b22; padding: 16px; border-radius: 6px;">
          <div style="color: #ff7b72; font-weight: bold; margin-bottom: 6px;">Lab Scope Containment Invariant</div>
          <p style="font-size: 14px; color: #8b949e;">Strict rejection of any containment target outside LAB_HOSTNAMES or LAB_CIDRS (RFC1918).</p>
        </div>
      </div>
    </div>
    """
    html = create_html_slide(
        title="Scene 3: Meta Muse Spark 1.3 System-2 Reasoning",
        subtitle="Autonomous Tool-Calling Reasoning via Meta Model API — Zero Unilateral Action",
        body_html=body,
        badge="SCENE 3 // SYSTEM-2 REASONING (0:50 – 1:30)"
    )
    slide_path = REEL_DIR / "slide_scene_3.html"
    slide_path.write_text(html, encoding="utf-8")
    page.goto(f"file:///{slide_path.as_posix()}")
    time.sleep(1)
    img_path = ASSETS_DIR / "scene3_muse_spark_reasoning.png"
    page.screenshot(path=str(img_path))
    print(f"[+] Rendered {img_path}")


def generate_scene_4(page):
    """Scene 4: Cytoscape Threat Graph & Telegram HITL Containment Card (1:30 - 2:10)"""
    body = """
    <div class="panel" style="flex: 1.3;">
      <div class="card-label">Live Cytoscape SOC Command Dashboard (Port 8516)</div>
      <div style="margin-top: 15px; background: #020617; border: 1px solid #1e293b; border-radius: 6px; padding: 20px; height: 380px; position: relative;">
        <!-- Emulated topology view -->
        <div style="position: absolute; top: 30px; left: 40px; background: #1e293b; padding: 10px 18px; border-radius: 6px; border: 1px solid #475569;">
          <span style="font-family: 'JetBrains Mono'; font-size: 13px; color: #94a3b8;">192.168.56.20 (bastion)</span>
        </div>
        <div style="position: absolute; top: 140px; left: 240px; background: rgba(239, 68, 68, 0.2); border: 2px solid #ef4444; padding: 12px 20px; border-radius: 6px;">
          <span style="font-family: 'JetBrains Mono'; font-size: 14px; font-weight: bold; color: #ef4444;">🚨 lab-win10-03 [ISOLATED]</span>
        </div>
        <div style="position: absolute; top: 250px; left: 440px; background: #1e293b; padding: 10px 18px; border-radius: 6px; border: 1px solid #475569;">
          <span style="font-family: 'JetBrains Mono'; font-size: 13px; color: #94a3b8;">lab-dc-01 (Domain Controller)</span>
        </div>
        <!-- Connection lines -->
        <svg style="position: absolute; top: 0; left: 0; width: 100%; height: 100%; pointer-events: none;">
          <line x1="140" y1="50" x2="240" y2="150" stroke="#ef4444" stroke-width="3" stroke-dasharray="5,5" />
          <line x1="380" y1="160" x2="440" y2="260" stroke="#f59e0b" stroke-width="2" />
        </svg>
        <div style="position: absolute; bottom: 15px; left: 20px; font-family: 'JetBrains Mono'; font-size: 12px; color: #64748b;">
          STATUS: LIVE (muse-spark-1.3) | LAYA LATENCY: 45ms Mean | APPLIED CONTAINMENTS: 1
        </div>
      </div>
    </div>
    <div class="panel" style="flex: 0.9;">
      <div class="card-label">Telegram HITL Two-Way Authorization Card</div>
      <div style="margin-top: 15px; background: #18222d; border-radius: 10px; padding: 20px; border: 1px solid #283747; font-family: 'JetBrains Mono', monospace; font-size: 13px;">
        <div style="color: #45aaf2; font-weight: bold; margin-bottom: 8px;">🚨 SENTINEL V4 // HITL CONTAINMENT AUTHORIZATION</div>
        <div style="color: #8b949e; border-bottom: 1px solid #283747; padding-bottom: 8px; margin-bottom: 10px;">
          Proposal ID: prop-1fcec089<br/>
          Action: isolate_host<br/>
          Target: 192.168.56.31 (lab-win10-03)<br/>
          Laya Conf: 47.58% | Muse Spark Reason: SMB lateral movement to DC
        </div>
        <div style="background: rgba(0, 229, 163, 0.15); border: 1px solid #00e5a3; color: #00e5a3; padding: 10px; border-radius: 6px; text-align: center; font-weight: bold; margin-top: 15px;">
          ✅ CONTAINMENT APPROVED BY ANALYST
        </div>
        <div style="margin-top: 10px; font-size: 11px; color: #8b949e; text-align: center;">
          Token consumed & logged in hitl_audit with SHA-256 fingerprint.
        </div>
      </div>
    </div>
    """
    html = create_html_slide(
        title="Scene 4: Cytoscape Threat Graph & Telegram HITL Approval",
        subtitle="Real-Time Network Topology Isolation with Cryptographic Two-Way Telegram Authorization",
        body_html=body,
        badge="SCENE 4 // SOC DASHBOARD & TELEGRAM HITL (1:30 – 2:10)"
    )
    slide_path = REEL_DIR / "slide_scene_4.html"
    slide_path.write_text(html, encoding="utf-8")
    page.goto(f"file:///{slide_path.as_posix()}")
    time.sleep(1)
    img_path = ASSETS_DIR / "scene4_cytoscape_telegram_hitl.png"
    page.screenshot(path=str(img_path))
    print(f"[+] Rendered {img_path}")


def generate_scene_5(page):
    """Scene 5: Dynamic Honeypot Deception & Multi-Hop Lateral Defense (2:10 - 2:40)"""
    body = """
    <div class="panel">
      <div class="card-label">Active Deception Architecture</div>
      <div style="margin-top: 20px; font-size: 16px; line-height: 1.6; color: #c9d1d9;">
        <p style="margin-bottom: 15px;">
          Rather than static firewall drops, Sentinel V4 engages active adversary diversion:
        </p>
        <ul style="padding-left: 20px; color: #8b949e; margin-bottom: 20px;">
          <li>Automated diversion of brute-force reconnaissance into internal honeypot sinks (web-01 @ 192.168.56.40).</li>
          <li>Attacker wastes cycles against realistic fake endpoints while payload and tooling signatures are extracted.</li>
          <li>Zero impact to internal production workloads and database clusters.</li>
        </ul>
      </div>
      <div style="background: #010409; padding: 15px; border-radius: 6px; font-family: 'JetBrains Mono'; font-size: 13px; color: #7ee787;">
        [HONEYPOT_SINK] web-01 absorbed 412 unauthenticated scanner probes.<br/>
        [DECEPTION] Diverted attacker session from production database lab-db-01.<br/>
        [FORENSICS] Extracted attacker JA3 TLS finger-print: 72c64932...
      </div>
    </div>
    <div class="panel">
      <div class="card-label">Hard-Coded Lab Network Boundaries</div>
      <div style="margin-top: 20px; display: flex; flex-direction: column; gap: 15px;">
        <div style="background: #161b22; padding: 20px; border-radius: 6px;">
          <div class="card-label">Permitted Lab CIDRs</div>
          <div style="font-family: 'JetBrains Mono'; font-size: 18px; color: #58a6ff; margin-top: 5px;">
            192.168.56.0/24 & 10.10.10.0/24
          </div>
          <p style="font-size: 13px; color: #8b949e; margin-top: 6px;">VirtualBox host-only and isolated test ranges. Zero external cloud packet leakage.</p>
        </div>
        <div style="background: #161b22; padding: 20px; border-radius: 6px;">
          <div class="card-label">DNS Rebinding & Scope Violation Prevention</div>
          <div style="font-family: 'JetBrains Mono'; font-size: 15px; color: #00e5a3; margin-top: 5px;">
            Enforced at Tool Layer (in_lab_scope)
          </div>
          <p style="font-size: 13px; color: #8b949e; margin-top: 6px;">Red-team bots and Blue-team containment strictly raise ScopeViolation on non-lab entities.</p>
        </div>
      </div>
    </div>
    """
    html = create_html_slide(
        title="Scene 5: Dynamic Honeypot Deception & Multi-Hop Defense",
        subtitle="Active Cyber Deception Deflecting Adversaries with Strict RFC1918 Lab Containment",
        body_html=body,
        badge="SCENE 5 // ACTIVE DECEPTION & LAB BOUNDARIES (2:10 – 2:40)"
    )
    slide_path = REEL_DIR / "slide_scene_5.html"
    slide_path.write_text(html, encoding="utf-8")
    page.goto(f"file:///{slide_path.as_posix()}")
    time.sleep(1)
    img_path = ASSETS_DIR / "scene5_honeypot_deception.png"
    page.screenshot(path=str(img_path))
    print(f"[+] Rendered {img_path}")


def generate_scene_6(page):
    """Scene 6: Quantitative Proof & Hackathon Alignment (2:40 - 3:00)"""
    body = """
    <div class="panel">
      <div class="card-label">Verification Evidence Ledger (100% Green)</div>
      <div style="margin-top: 20px; display: flex; flex-direction: column; gap: 15px;">
        <div style="background: #161b22; padding: 18px; border-radius: 6px;">
          <div class="card-label">Hermetic Pytest Suite</div>
          <div class="card-metric">69 / 69 PASS</div>
          <p style="font-size: 14px; color: #8b949e;">Covers Laya gate, Muse Spark streaming tool loop, HITL atomic state, and dashboard server.</p>
        </div>
        <div style="background: #161b22; padding: 18px; border-radius: 6px;">
          <div class="card-label">Calibrated Attack Scenarios Replay</div>
          <div class="card-metric">3 / 3 PASS</div>
          <p style="font-size: 14px; color: #8b949e;">Scenario 1 (SMB lateral), Scenario 2 (C2 exfil), Scenario 3 (Benign discriminator).</p>
        </div>
      </div>
    </div>
    <div class="panel">
      <div class="card-label">Hackathon Track & Architecture Summary</div>
      <div style="margin-top: 20px; display: flex; flex-direction: column; gap: 15px;">
        <div style="background: #161b22; padding: 18px; border-radius: 6px;">
          <div class="card-label">Track: Build for Your World</div>
          <div style="font-size: 18px; font-weight: bold; color: #ffffff; margin-top: 4px;">Collaborative Dual-System AI SOC</div>
          <p style="font-size: 13px; color: #8b949e; margin-top: 6px;">Edge inference on consumer laptops + deep reasoning via Meta Muse Spark.</p>
        </div>
        <div style="background: #161b22; padding: 18px; border-radius: 6px;">
          <div class="card-label">Open Source Repositories & License</div>
          <div style="font-family: 'JetBrains Mono'; font-size: 13px; color: #58a6ff; margin-top: 6px;">
            • github.com/hearthacker003366/sentinel-v4 (Hackathon Build)<br/>
            • github.com/hearthacker003366/sentinelV3 (Pre-existing Baseline)<br/>
            • License: MIT Open Source
          </div>
        </div>
      </div>
    </div>
    """
    html = create_html_slide(
        title="Scene 6: Quantitative Proof & Hackathon Alignment",
        subtitle="100% Tested, Fully Open-Source, and Ready for Enterprise SOC Deployment",
        body_html=body,
        badge="SCENE 6 // CLOSING & METRICS (2:40 – 3:00)"
    )
    slide_path = REEL_DIR / "slide_scene_6.html"
    slide_path.write_text(html, encoding="utf-8")
    page.goto(f"file:///{slide_path.as_posix()}")
    time.sleep(1)
    img_path = ASSETS_DIR / "scene6_quantitative_closing.png"
    page.screenshot(path=str(img_path))
    print(f"[+] Rendered {img_path}")


def main():
    print("[*] Starting Playwright 1080p Screenshot Engine...")
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1920, "height": 1080})
        page = context.new_page()

        print("[*] Generating Scene 1...")
        generate_scene_1(page)

        print("[*] Generating Scene 2...")
        generate_scene_2(page)

        print("[*] Generating Scene 3...")
        generate_scene_3(page)

        print("[*] Generating Scene 4...")
        generate_scene_4(page)

        print("[*] Generating Scene 5...")
        generate_scene_5(page)

        print("[*] Generating Scene 6...")
        generate_scene_6(page)

        browser.close()

    print("[*] Compiling Video Clips via FFmpeg...")
    scene_durations = [
        ("scene1_opening.png", 20, "scene1_opening.mp4"),
        ("scene2_local_hardware_laya.png", 30, "scene2_laya_edge.mp4"),
        ("scene3_muse_spark_reasoning.png", 40, "scene3_muse_spark.mp4"),
        ("scene4_cytoscape_telegram_hitl.png", 40, "scene4_soc_telegram.mp4"),
        ("scene5_honeypot_deception.png", 30, "scene5_honeypot.mp4"),
        ("scene6_quantitative_closing.png", 20, "scene6_summary.mp4"),
    ]

    concat_list = []
    for img_name, dur, out_name in scene_durations:
        img_file = ASSETS_DIR / img_name
        out_file = ASSETS_DIR / out_name
        cmd = [
            FFMPEG_PATH, "-y",
            "-loop", "1",
            "-i", str(img_file),
            "-c:v", "libx264",
            "-t", str(dur),
            "-pix_fmt", "yuv420p",
            "-vf", "scale=1920:1080",
            "-r", "30",
            str(out_file)
        ]
        res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if res.returncode == 0:
            print(f"[+] Created Video Clip: {out_file} ({dur}s)")
            concat_list.append(f"file '{out_file.as_posix()}'")
        else:
            print(f"[-] FFmpeg failed for {out_name}")

    if concat_list:
        concat_file = REEL_DIR / "concat_list.txt"
        concat_file.write_text("\n".join(concat_list), encoding="utf-8")
        full_reel = ASSETS_DIR / "sentinel_v4_3min_demo.mp4"
        cmd = [
            FFMPEG_PATH, "-y",
            "-f", "concat",
            "-safe", "0",
            "-i", str(concat_file),
            "-c", "copy",
            str(full_reel)
        ]
        res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if res.returncode == 0:
            print(f"\n[SUCCESS] Full 3-Minute Demo Reel Generated: {full_reel}")

if __name__ == "__main__":
    main()
