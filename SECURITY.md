# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |
| < 0.1   | No        |

mcp-guard follows semantic versioning. Only the latest minor release series receives security patches.

## Reporting a Vulnerability

We take security seriously. If you discover a vulnerability in mcp-guard itself, please report it **privately**:

- **Email:** security@shovalbenjer.com
- **GitHub Security Advisory:** Use the "Private vulnerability reporting" feature on this repository

**Please do NOT open a public GitHub Issue for security vulnerabilities.**

We will acknowledge your report within 72 hours and provide a detailed response within 7 days. We ask that you do not disclose the vulnerability publicly until we have released a patch.

## Known Threats

mcp-guard is designed to detect the following failure modes in MCP servers it fuzzes:

1. **Server crashes**: A payload crashes the MCP server process, causing transport loss. mcp-guard detects process exit, tracks crash-causing payloads, and classifies them as CRITICAL findings.

2. **Rate limiting / server throttling**: Aggressive fuzzing can trigger rate limits or intentional slowdowns. mcp-guard supports configurable delay (`--delay-ms`) between payloads and classifies rate-limited responses as expected errors (SAFE), not vulnerabilities.

3. **False positives from expected errors**: A tool correctly rejecting bad input with a 400 error must not be flagged as a finding. mcp-guard classifies responses: expected errors = SAFE, unexpected errors = FINDING, crashes = CRASH.

4. **Non-deterministic results**: Same payload producing different results across runs due to server state. mcp-guard documents non-determinism in reports and uses seed-based payload ordering for reproducibility in CI.

5. **MCP protocol version drift**: The MCP protocol spec evolves. mcp-guard pins protocol constants (currently `2024-11-05`) and fails gracefully on unknown message types.

## Mitigation Strategies

### Supply-Chain Hardening
- Zero external runtime dependencies. mcp-guard uses Python 3.11+ stdlib only.
- `bandit` security scanner runs in CI on every PR.
- `ruff` lint enforcement on every PR.
- `mypy --strict` type checking on every PR.

### CI/CD Security Gates
- Matrix testing across Python 3.11, 3.12, 3.13 on Ubuntu.
- Fuzz test suite (`tests/fuzz_test.py`) runs as a CI gate, specifically testing the 5 failure modes above.

### Release Security
- PyPI publishing uses trusted publishing (OIDC) — no long-lived API tokens.
