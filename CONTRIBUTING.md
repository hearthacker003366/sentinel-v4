# Contributing to Sentinel V4

Thank you for your interest in Sentinel V4! This is an AI SOC copilot built for the Meta Global AI Developer Hackathon: LLM red-team bots attack a simulated lab network while Laya triage and Muse Spark reasoning defend it, with a human approving every action.

## Scope — read this first

Everything in this repo runs against a **simulated lab network only** (RFC1918 addresses, scope hard-coded). Contributions must not extend the project to real networks, real systems, or real credentials. Do not commit secrets, model weights that exceed GitHub's limits, or pre-hackathon code from other repositories.

## How to Contribute

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/amazing-feature`).
3. Commit your changes (`git commit -m 'feat: Add amazing feature'`).
4. Push to the branch (`git push origin feature/amazing-feature`).
5. Open a Pull Request.

## Pull Request Guidelines

- Run the test suite (`python -m pytest tests/`) locally before opening a PR, and make sure it passes.
- Keep `requirements.txt` minimal and pinned. Do not add bloated dependencies.
- Keep changes focused: one concern per PR, no unrelated reformatting.
- If you change behaviour, update the README or docs in the same PR.
- This project is licensed under the MIT License (see `LICENSE`).
