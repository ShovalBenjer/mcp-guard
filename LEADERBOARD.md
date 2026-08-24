# MCP Server Security Leaderboard

Results from running [mcp-guard](https://github.com/ShovalBenjer/mcp-guard) against popular MCP servers.

**Last updated: 2026-06-03**
**mcp-guard version: 0.1.0**
**Protocol version: 2024-11-05**

## Rankings

| # | Server | Tools | Payloads | Crashes | Findings | Safe | Verdict |
|---|--------|-------|----------|---------|----------|------|---------|
| 1 | @modelcontextprotocol/server-filesystem | 14 | 490 | 0 | 24 | 466 | FINDINGS |
| 2 | @modelcontextprotocol/server-memory | 9 | 91 | 0 | 41 | 50 | FINDINGS |

## Key Findings

### @modelcontextprotocol/server-memory (9 tools, 41 findings)

**Most vulnerable tools:** `read_graph`, `search_nodes`, `open_nodes`

- Tools with no input schema (`read_graph`, `list_allowed_directories`) accept all payloads without validation
- String-parameter tools (`create_entities`, `search_nodes`) accept shell injection payloads (`$(whoami)`, `` `cat /etc/passwd` ``) without error
- No input sanitization — adversarial strings pass through to internal logic
- **Severity:** The server doesn't crash, but silent acceptance of malicious input means an LLM agent could be tricked into injecting payloads through tool calls

### @modelcontextprotocol/server-filesystem (14 tools, 24 findings)

**Most vulnerable tools:** `list_allowed_directories` (16 findings)

- `list_allowed_directories` ignores all input parameters — accepts shell injection, SSRF, and overflow payloads silently
- 490 payloads tested across 14 tools, 95% handled safely
- File-operation tools (`read_file`, `write_file`, `edit_file`) properly validate paths
- **Severity:** Low-to-medium — the findings are concentrated in tools that ignore input, but the pattern reveals inconsistent input validation across the server

## Scoring Methodology

Servers are ranked by a composite security score (higher is better):

### Score Formula

```
security_score = (safe * 1.0 + findings * 0.3 + crashes * 0.0) / total_payloads * 100
```

| Category | Weight | Rationale |
|----------|--------|-----------|
| Safe | 1.0 | Server correctly rejected payload (expected error) |
| Finding | 0.3 | Server accepted payload without error (potential vulnerability) |
| Crash | 0.0 | Server died (denial of service, worst outcome) |

### Interpretation

- **90-100:** Excellent — server handles almost all adversarial input safely
- **70-89:** Good — minor issues, most payloads handled correctly
- **50-69:** Fair — significant findings, investigation recommended
- **0-49:** Poor — widespread vulnerability to adversarial input

### Current Scores

| Server | Score | Grade |
|--------|-------|-------|
| @modelcontextprotocol/server-filesystem | 96.5% | Excellent |
| @modelcontextprotocol/server-memory | 67.0% | Fair |

## Test Procedure

---

## Methodology

mcp-guard's leaderboard methodology is designed to be reproducible. Every measurement follows the same pipeline.

### 1. Payload Counting

Payloads are counted per tool call, not per parameter. The total payload count for a server is the sum of payloads sent across all tools.

| Tool Input Type | Payloads per Parameter |
|-----------------|------------------------|
| String parameter | 25 |
| URI-typed string parameter | 33 |
| Integer / number parameter | 9 |
| No input schema | 24 |

**Calculation example**: A server with 3 tools, each having one string parameter, produces `3 × 25 = 75` total payloads.

Payloads are schema-aware:
- String parameters receive shell injection (8), prompt injection (6), overflow subset (3), and type confusion (8) payloads.
- URI parameters receive the above string payloads plus SSRF (8).
- No-schema tools receive shell injection (8), SSRF (8), overflow subset (2), and prompt injection (6).
- Integer parameters receive type confusion (8) plus max int64 overflow (1).

### 2. Severity Weighting

Each payload carries a severity assigned at generation time:

| Severity | Weight | Description |
|----------|--------|-----------|
| CRITICAL | 4 | Direct code execution, cloud metadata exposure, local file read |
| HIGH | 3 | SSRF to internal services, prompt injection, SQL injection |
| MEDIUM | 2 | Resource exhaustion, type confusion |
| LOW | 1 | Minor validation gaps, negative numbers |

The leaderboard aggregates findings by count, not weighted score. A finding is counted once per payload-tool pair.

### 3. Benchmarking

Benchmarks are run against a live server instance:

1. Spawn the server via stdio transport.
2. Perform MCP handshake (`initialize` + `notifications/initialized`).
3. Enumerate tools via `tools/list`.
4. For each tool, generate schema-aware payloads and fire them sequentially.
5. Classify each response as SAFE, FINDING, CRASH, or ERROR.
6. Aggregate results and emit a report.

All runs use the default `timeout` of 10 seconds per tool call. No retries or adaptive delays are applied in leaderboard runs.

### 4. Response Classification

| Class | Condition |
|-------|-----------|
| **SAFE** | Server returns `isError: true` — expected validation rejection |
| **FINDING** | Server returns `isError: false` — payload accepted without error |
| **FINDING** | Response text contains leaked internal info (traceback, exception, stack trace, password, secret, token) |
| **CRASH** | `ConnectionError` raised — server process exited or closed connection |
| **ERROR** | Unexpected exception during delivery |

### 5. Reproducibility

To reproduce leaderboard results:

```bash
# Clone and install
git clone https://github.com/ShovalBenjer/mcp-guard.git
cd mcp-guard
pip install -e ".[dev]"

# Run against a server
mcp-guard fuzz -- npx @modelcontextprotocol/server-memory
mcp-guard fuzz -- npx @modelcontextprotocol/server-filesystem /tmp
```

All output is deterministic given the same server version and input arguments.

### 6. Submitting New Entries

1. Run mcp-guard against your MCP server.
2. Capture the full CLI output.
3. Open a PR against this file with your results formatted as a new table row.
4. Include: server name, tool count, total payloads sent, crashes, findings, safe count, and a brief verdict.

New entries are reviewed for accuracy before merging.
