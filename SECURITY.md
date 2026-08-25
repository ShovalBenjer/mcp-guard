# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.2.x   | Yes       |
| < 0.2   | No        |

mcp-guard follows semantic versioning. Only the latest minor release series receives security patches.

## Reporting a Vulnerability

We take security seriously. If you discover a vulnerability in mcp-guard itself, please report it **privately**:

- **Email:** security@shovalbenjer.com
- **GitHub Security Advisory:** Use the "Private vulnerability reporting" feature on this repository

**Please do NOT open a public GitHub Issue for security vulnerabilities.**

We will acknowledge your report within 72 hours and provide a detailed response within 7 days. We ask that you do not disclose the vulnerability publicly until we have released a patch.

## Known Threats (from `docs/spec.md` Premortem)

mcp-guard is designed to detect the following failure modes in MCP servers it fuzzes:

1. **Server crashes**: A payload crashes the MCP server process, causing transport loss. mcp-guard detects process exit, tracks crash-causing payloads, and classifies them as CRITICAL findings.

2. **Rate limiting / server throttling**: Aggressive fuzzing can trigger rate limits or intentional slowdowns. mcp-guard supports configurable delay (`--delay-ms`) between payloads and classifies rate-limited responses as expected errors (SAFE), not vulnerabilities.

3. **False positives from expected errors**: A tool correctly rejecting bad input with a 400 error must not be flagged as a finding. mcp-guard classifies responses: expected errors = SAFE, unexpected errors = FINDING, crashes = CRASH.

4. **Non-deterministic results**: Same payload producing different results across runs due to server state. mcp-guard documents non-determinism in reports and uses seed-based payload ordering for reproducibility in CI.

5. **MCP protocol version drift**: The MCP protocol spec evolves. mcp-guard pins protocol constants (currently `2024-11-05`) and fails gracefully on unknown message types.

## Mitigation Strategies

### Supply-Chain Hardening
- Zero external runtime dependencies. mcp-guard uses Python 3.11+ stdlib only.
- `pip-audit` runs in CI on every PR to detect known vulnerabilities in dev dependencies.
- `bandit` security scanner runs in CI on every PR.
- SBOM (Software Bill of Materials) generated via CycloneDX on every release.
- Dependabot configured for GitHub Actions, pip, and npm with grouped weekly updates and auto-merge for patch versions.
- CodeQL analysis runs weekly and on every PR for Python and GitHub Actions code.

### CI/CD Security Gates
- Matrix testing across Ubuntu, Windows, macOS × Python 3.11, 3.12.
- `mypy --strict` type checking on every PR.
- `ruff` lint + format enforcement on every PR.
- Fuzz test suite (`tests/fuzz_test.py`) runs as a CI gate, specifically testing the 5 failure modes above.
- Benchmark gate reproduces the leaderboard methodology to prevent regressions.

### Release Security
- PyPI publishing uses trusted publishing (OIDC) — no long-lived API tokens.
- Release artifacts are signed with Sigstore.
- SARIF output supported for GitHub Security tab integration.

## Security.txt

This repository follows the security.txt specification. See `security.txt` in this repository's root or contact `security@shovalbenjer.com`.

For coordinated disclosure timelines: 90-day disclosure policy aligned with industry standards.
