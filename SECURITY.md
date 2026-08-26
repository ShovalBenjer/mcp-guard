# Security Policy

## Supported Versions

| Version  | Supported          |
|----------|--------------------|
| 0.2.x    | :white_check_mark: |
| < 0.2    | :x:                |

mcp-guard follows [Semantic Versioning](https://semver.org/). Only the latest minor release series receives security patches. If you are using an older version, please upgrade to the latest release before reporting a vulnerability.

## Reporting a Vulnerability

We take security seriously. If you discover a vulnerability in mcp-guard itself (not in a target MCP server), please report it **privately**:

- **GitHub Security Advisory**: Use the "Private vulnerability reporting" feature on this repository.
- **Email**: `security@shovalbenjer.com`

### Disclosure Timeline

| Step                     | Timeline     |
|--------------------------|--------------|
| Initial acknowledgment   | Within 72 h  |
| Triage / initial response| Within 7 days|
| Patch under development  | Within 30 days|
| Public disclosure        | Coordinated, after patch release |

We follow a **90-day disclosure policy** aligned with industry standards. If the vulnerability poses an immediate risk to users, we may accelerate the timeline.

**Please do NOT open a public GitHub Issue for security vulnerabilities.** Include the following in your report:

- A description of the vulnerability and its impact
- Steps to reproduce
- Any suggested mitigations
- Your contact information and preferred credit

We will acknowledge your report, keep you informed of progress, and credit you in the fix release (unless you prefer anonymity).

---

## Known Threats and Failure Modes

mcp-guard was designed to address specific failure modes identified in [`docs/spec.md`](docs/spec.md) premortem. The following five categories represent the primary threats that mcp-guard mitigates in MCP servers, and the corresponding safeguards built into our own tooling:

### 1. Server Crashes from Adversarial Payloads

**Threat**: A payload (e.g., `; rm -rf /`, 1MB string, null bytes) crashes the target MCP server process, causing it to exit unexpectedly.

**mcp-guard Mitigation**: The `StdioTransport` uses `select.select()` with a configurable timeout. If the server process exits or closes stdout, a `ConnectionError` is raised and caught by `FuzzEngine._fire_payload`, which classifies the result as `CRASH`. Crash-causing payloads are tracked and surfaced in the report.

**CI Gate**: `tests/test_transport.py` and `tests/fuzz_test.py` verify crash detection under simulated server crashes.

### 2. Rate Limiting / Server Throttling

**Threat**: Aggressive fuzzing triggers rate limits (HTTP 429) or intentional server slowdowns, which could produce false positives if misinterpreted.

**mcp-guard Mitigation**: The `--delay-ms` CLI flag allows operators to throttle payload delivery. Rate-limited responses (where the server returns `isError: true`) are classified as `SAFE` — an expected, correct rejection, not a vulnerability.

### 3. False Positives from Expected Errors

**Threat**: A tool correctly rejects malformed input with an error, which should not be flagged as a security finding.

**mcp-guard Mitigation**: `_classify_response` distinguishes between:
- `isError: true` → `SAFE` (server correctly rejected the payload)
- `isError: false` + info leak keywords → `FINDING` (info disclosure)
- `isError: false` + no leak → `FINDING` (payload silently accepted)
- `ConnectionError` → `CRASH` (server died)

### 4. Non-Deterministic Results

**Threat**: The same payload produces different results across runs due to server state (caches, databases, session data), making findings irreproducible.

**mcp-guard Mitigation**: Payload generation is deterministic — payloads are static strings/objects generated in a fixed order. No randomization or randomness is used in payload values. The `delay_ms` parameter is the only mutable state, and it does not affect payload content.

### 5. MCP Protocol Version Drift

**Threat**: The MCP protocol specification evolves, and servers may implement different protocol versions or message formats, causing the fuzzer to misinterpret responses.

**mcp-guard Mitigation**: The protocol version (`2024-11-05`) is pinned in `StdioTransport._initialize`. The transport filters out server notifications (messages with `method` but no `id`) to avoid protocol drift issues. The `protocolVersion` is sent explicitly during the `initialize` handshake.

---

## Mitigation Strategies

### Supply-Chain Hardening

| Control                  | Description                                              |
|--------------------------|----------------------------------------------------------|
| Zero runtime dependencies | mcp-guard uses Python 3.11+ stdlib only — no third-party runtime packages to compromise. |
| `pip-audit` in CI        | Runs on every PR to detect known CVEs in dev dependencies (pytest, ruff, mypy, bandit, etc.). |
| `bandit` in CI           | AST-based static security scanner. `subprocess` warnings (B603, B404) are intentionally suppressed — spawning server subprocesses is mcp-guard's core function. |
| SBOM generation          | CycloneDX SBOM (JSON + XML) generated on every release and on a weekly CI schedule. Available as a release artifact. |
| Dependabot               | Automated updates for GitHub Actions, pip, and npm with grouped weekly updates and auto-merge for patch versions. |
| CodeQL                   | Deep static analysis for Python source and GitHub Actions workflow files. Runs weekly and on every PR. |

### CI/CD Security Gates

| Gate                    | Tool          | Threshold                                             |
|-------------------------|---------------|-------------------------------------------------------|
| Test matrix             | pytest        | Python 3.11 / 3.12 / 3.13 × Ubuntu / Windows / macOS |
| Coverage                | pytest-cov    | ≥ 80% (fail-under)                                    |
| Type safety             | mypy --strict | All source files must pass strict type checking       |
| Lint/format             | ruff          | `ruff check` + `ruff format --check`                  |
| Security scan           | bandit        | No HIGH/CRITICAL findings                              |
| Dependency audit        | pip-audit     | No known vulnerabilities in dev dependencies           |
| Fuzz test gate          | pytest        | tests/fuzz_test.py — 5 failure-mode tests must pass    |

### Release Security

| Control                    | Description                                           |
|----------------------------|-------------------------------------------------------|
| Trusted publishing (OIDC)  | PyPI releases use OIDC token exchange — no long-lived API tokens stored in GitHub Secrets. |
| Artifact signing           | Release artifacts are signed with Sigstore attestation. |
| SBOM on release            | CycloneDX SBOM is attached to every GitHub Release.   |
| Changelog generation       | Automatically generated from git history.            |

### Runtime Security for Consumers

mcp-guard sends adversarial payloads to a server you control. Follow these practices:

- **Run against test/staging servers only** — do not fuzz production MCP servers directly.
- **Review findings manually** — the fuzzer identifies potential issues; it cannot confirm exploitation.
- **Use `--delay-ms`** when targeting rate-limited servers.
- **Limit the server command scope** — mcp-guard executes whatever command is passed via `--`. Only use trusted server packages.

---

## security.txt

This repository conforms to the [security.txt](https://securitytxt.org/) specification. A machine-readable `security.txt` is available at [`.well-known/security.txt`](.well-known/security.txt).

```text
Contact: mailto:security@shovalbenjer.com
Expires: 2027-12-31T23:59:59+00:00
Canonical: https://github.com/ShovalBenjer/mcp-guard/blob/main/.well-known/security.txt
Preferred-Languages: en
Hiring: https://github.com/ShovalBenjer/mcp-guard
```
