# mcp-guard — MCP Server Security Scanner

## Spec

CLI + library that audits MCP (Model Context Protocol) server endpoints against OWASP Agentic Top 10 security risks.

### Core Behavior
1. Connect to an MCP server via stdio or SSE transport
2. Enumerate exposed tools, resources, and prompts
3. Run a suite of security checks against each
4. Produce a scored report (pass/warn/fail) with remediation advice

### Security Checks (v1)
- **Tool injection**: Detect tools that accept executable code or shell commands
- **SSRF surface**: Flag tools that take URLs or network addresses as parameters
- **Private network exposure**: Test if server exposes internal network access
- **Capability sprawl**: Warn when a server exposes >10 tools (attack surface)
- **Missing input validation**: Detect tools with no schema or type constraints
- **Excessive permissions**: Flag tools that claim filesystem or env access
- **Prompt injection vectors**: Scan prompt templates for unescaped user input
- **Resource leakage**: Detect resources that expose credentials, .env, or secrets
- **Transport security**: Verify SSE endpoints use TLS
- **Auth surface**: Report whether server requires authentication

### Output Formats
- CLI table (default)
- JSON (for CI)
- SARIF (for GitHub Security tab)

## PREMORTEM — 5 Failure Modes

1. **MCP server crashes during scan**: Aggressive probing kills the target. Mitigation: rate-limit tool calls, add per-check timeout, graceful disconnect.

2. **False positives on legitimate tools**: A dev tool legitimately runs shell commands. Mitigation: severity scoring (critical/warning/info), allowlist via config file, context-aware heuristics.

3. **Transport incompatibility**: MCP servers use stdio, SSE, or streamable HTTP — missing one breaks adoption. Mitigation: implement all three transports from day one, use official MCP SDK.

4. **OWASP mapping drift**: OWASP Agentic Top 10 evolves between releases. Mitigation: decouple check definitions from OWASP version, use a rules engine with versioned rule sets.

5. **CI pipeline timeout**: Large MCP servers with many tools take too long in CI. Mitigation: `--max-time` flag, incremental scanning, cache results for unchanged tool schemas.
