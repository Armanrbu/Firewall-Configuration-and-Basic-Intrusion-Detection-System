# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.x     | ✅ Active  |
| 1.x     | ⚠️ Security fixes only |
| < 1.0   | ❌ Not supported |

## Reporting a Vulnerability

**Please do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please report security issues by emailing:

> **security@netguard-ids.example.com**

You can also use [GitHub Private Security Advisories](https://github.com/Armanrbu/Firewall-Configuration-and-Basic-Intrusion-Detection-System/security/advisories/new).

Include in your report:
- A description of the vulnerability
- Steps to reproduce (proof-of-concept code if applicable)
- Potential impact assessment
- Suggested fix (if you have one)

You will receive an acknowledgment within **48 hours** and a detailed response within **7 days**.

## Security Design Principles

NetGuard IDS follows these security principles:

1. **No command injection** — All firewall rule commands use `subprocess` argument lists (never `shell=True` with string interpolation). See `core/firewall.py`.
2. **API key authentication** — All REST endpoints (and the WebSocket) require a valid `X-API-Key` header. Keys are read from `NETGUARD_API_KEY` env variable or `.env`.
3. **Non-root container** — The Docker image runs as the `netguard` user (UID not root).
4. **Python sandbox** — YAML rules with a `python:` escape hatch execute inside a restricted `exec()` sandbox.
5. **Least privilege** — `NET_ADMIN` capability is only requested when running in Docker on Linux.
6. **Input validation** — All REST API inputs are validated through Pydantic models before reaching business logic.

## Known Limitations

- **Windows Firewall rules** require administrator privileges. The application must be run as Administrator on Windows.
- The Python rule escape hatch is sandboxed but not fully isolated. Avoid loading untrusted rule files from external sources.
