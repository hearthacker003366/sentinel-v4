# Security Policy

Sentinel V4 is an AI SOC copilot built for the Meta Global AI Developer Hackathon. It defends a **simulated lab network only** (RFC1918 addresses): LLM red-team bots attack the lab while the Laya triage gate and Muse Spark reasoning defend it, with a human approving every containment action. Nothing in this repo is intended to run against real networks or real systems.

---

## Supported Versions

Security patches are applied to the current development line. There are no released versions yet.

| Version | Supported          | Status |
| :--- | :---: | :--- |
| `main` | :white_check_mark: | Current development line; security fixes land here |
| Any released version (when one exists) | :white_check_mark: | Current release line only; older releases are not patched |

---

## Reporting a Vulnerability

If you believe you have found a security vulnerability in Sentinel V4, **please do not disclose it in a public GitHub issue, pull request, or discussion.**

### Reporting Channels

1. **GitHub Private Vulnerability Reporting (Preferred):**
   Submit an encrypted disclosure via [GitHub Security Advisories](https://github.com/hearthacker003366/sentinel-v4/security/advisories/new). This enables private, coordinated patching with the maintainer before publication.

2. **Direct Maintainer Contact:**
   If private vulnerability reporting is unavailable or you prefer direct contact, email the maintainer at:
   `boorgulaprabhudas@gmail.com` with the subject line:
   `[SECURITY] Sentinel V4 Vulnerability Report - <Brief Summary>`

### What to Include

To accelerate triage and verification, please provide:

- **Vulnerability classification**: (e.g. authentication bypass, denial of service, prompt injection, unsafe deserialization, path traversal, scope escape outside the simulated lab).
- **Affected component**: (e.g. triage gate, orchestrator, MCP server, dashboard, red-team bots, replay harness).
- **Affected versions**: Specific commit SHA or release tag.
- **Reproduction steps**: A minimal script, command, or payload demonstrating the vulnerability.
- **Impact assessment**: Practical severity, threat model, prerequisites, and realistic exploit scenarios.
- **Remediation**: (Optional) Suggested patch or mitigation strategy if already identified.

### Coordinated Disclosure Timeline

- **Acknowledgment**: Within 48 hours of initial report.
- **Triage & Reproduction**: Within 5 business days, including confirmation of severity and affected versions.
- **Remediation & Advisory**: We will collaborate with the reporter to develop, verify, and release a fix before public disclosure. Reporters will be credited in the security advisory and release notes.

Please allow reasonable time for a fix before public disclosure.
