# mcp-guard — Adversarial Fuzzer for MCP Servers

## Spec

CLI + library that **dynamically fuzzes** MCP (Model Context Protocol) servers by sending adversarial inputs to exposed tools, detecting crashes, information leakage, and unexpected behavior.

**Differentiation:** microsoft/agent-governance-toolkit does static policy checks ("does this tool declaration look safe?"). mcp-guard does dynamic adversarial testing ("what happens when I ACTUALLY SEND this payload?").

### Core Behavior
1. Spawn/connect to an MCP server via stdio transport
2. Perform MCP handshake, enumerate tools/resources/prompts
3. Generate adversarial payloads per tool based on its schema
4. Fire payloads at each tool, monitor responses
5. Detect: crashes, error leakage, unexpected success, timeouts
6. Produce scored report with findings + reproduction steps

### Fuzz Probes (v1)

| Probe | What It Sends | What It Detects |
|-------|--------------|-----------------|
| **shell_injection** | `; rm -rf /`, `$(whoami)`, backtick expressions | Command execution surface |
| **ssrf** | `http://169.254.169.254/`, `http://localhost:22`, `file:///etc/passwd` | Internal network access |
| **overflow** | 100KB strings, deeply nested JSON, huge arrays | Buffer overflows, memory leaks |
| **type_confusion** | String where int expected, arrays for scalars, null for required | Missing validation |
| **prompt_injection** | "Ignore previous instructions...", system prompt extractions | Prompt leakage, instruction override |

### Payload Intelligence
- Payloads are **schema-aware**: read tool inputSchema, generate targeted payloads per parameter type
- String params get injection/overflow payloads
- URI params get SSRF payloads
- No-schema tools get the full payload suite
- Each payload has a severity and expected-failure pattern

### Transport (v1)
- **stdio**: spawn server as subprocess, communicate via stdin/stdout JSON-RPC
- Future: SSE, streamable HTTP

### Output Formats
- CLI table (default) — colored, readable
- JSON (for CI integration)
- SARIF (for GitHub Security tab)

## PREMORTEM — 5 Failure Modes

1. **Server crashes kill the fuzzer**: A payload crashes the MCP server process, fuzzer loses transport. Mitigation: detect process exit, respawn server between probe groups, track crash-causing payloads.

2. **Rate limiting / server throttling**: Aggressive fuzzing triggers rate limits or intentional slowdowns. Mitigation: configurable delay between payloads (`--delay-ms`), adaptive throttling based on response times.

3. **False positives from expected errors**: A tool correctly rejects bad input with a 400 error — fuzzer flags it as a finding. Mitigation: classify responses: expected errors (safe) vs. unexpected errors (finding) vs. crashes (critical). Only flag the latter two.

4. **Non-deterministic results**: Same payload, different results across runs (server has state). Mitigation: seed-based payload ordering, state reset between probe groups, document non-determinism in report.

5. **MCP protocol version drift**: Protocol spec evolves, handshake changes. Mitigation: implement against current spec, version-pin the protocol constants, fail gracefully on unknown message types.
