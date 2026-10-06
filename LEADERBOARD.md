# MCP Server Security Leaderboard

Results from running [mcp-guard](https://github.com/ShovalBenjer/mcp-guard) against popular MCP servers.

**Last updated: 2026-06-03**
**mcp-guard version: 0.2.1**
**Payload ruleset version: 1**
**Protocol version: 2024-11-05**
**Methodology (§1–§4) verified against code: 2026-10-06** (payload counts in §1 recomputed from `src/mcp_guard/payloads.py` and `src/mcp_guard/fuzzer.py` on this commit; `tests/test_leaderboard_methodology.py` fails CI if they drift)

## Rankings

| # | Server | Tools | Payloads | Crashes | Findings | Safe | Verdict |
|---|--------|-------|----------|---------|----------|------|---------|
| 1 | @modelcontextprotocol/server-filesystem | 14 | 490 | 0 | 24 | 466 | FINDINGS |
| 2 | @modelcontextprotocol/server-memory | 9 | 91 | 0 | 41 | 50 | FINDINGS |

> The ranked rows were produced 2026-06-03 with mcp-guard 0.1.0 — before the indirect-injection probes (4 per string parameter, added 2026-09-26) entered the payload ruleset. Their payload totals would be higher under the current ruleset; they have not been re-run. New submissions are benchmarked under the methodology below.

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

---

## Methodology

mcp-guard's leaderboard methodology is designed to be reproducible. Every measurement follows the same pipeline.

### 1. Payload Counting

Payloads are counted per tool call, not per parameter. Each payload is one tool call with a single parameter set to the payload value. The total payload count for a server is the sum of per-parameter payloads across all its tools.

| Tool Input Type | Payloads per Parameter |
|-----------------|------------------------|
| String parameter | 29 |
| URI-typed string parameter | 37 |
| Integer / number parameter | 9 |
| No input schema | 24 |

**Calculation example**: A server with 3 tools, each having one string parameter, produces `3 × 29 = 87` total payloads.

Payloads are schema-aware:
- String parameters receive shell injection (8), prompt injection (6), indirect-injection probes (4), overflow subset (3), and type confusion (8).
- URI parameters receive the above string payloads plus SSRF (8).
- No-schema tools receive shell injection (8), SSRF (8), overflow subset (2), and prompt injection (6).
- Integer parameters receive type confusion (8) plus max int64 overflow (1).

### 2. Severity Levels

Each payload carries a severity assigned at generation time:

| Severity | Weight | Description |
|----------|--------|-------------|
| CRITICAL | 4 | Direct code execution, cloud metadata exposure, local file read |
| HIGH | 3 | SSRF to internal services, prompt injection, SQL injection |
| MEDIUM | 2 | Resource exhaustion, type confusion |
| LOW | 1 | Minor validation gaps, negative numbers |
| INFO | 0 | No observable effect — payload produced no error, no reflection, no leak; documented for visibility, not a clean bill of health |

Weights are declared metadata on each payload. The leaderboard aggregates findings by raw count per severity, not by weighted score. A finding is counted once per payload-tool pair.

### 3. Benchmarking

Benchmarks are run against a live server instance:

1. Spawn the server via stdio transport (the only transport `mcp-guard fuzz` supports).
2. Perform MCP handshake (`initialize` + `notifications/initialized`).
3. Enumerate tools via `tools/list`.
4. For each tool, generate schema-aware payloads and fire them sequentially.
5. Classify each response as SAFE, FINDING, CRASH, or ERROR.
6. Aggregate results and emit a report.

Leaderboard runs use the defaults: **timeout 10 seconds per tool call** (`--timeout`), **delay 0 ms between payloads** (`--delay-ms`), **no retries** — a crashed call is recorded as CRASH and the fuzzer moves on. Deviations from these defaults must be disclosed in the submission.

Every report carries provenance so a row can be reproduced: scanner name and version (installed `mcp-guard`), payload ruleset version, run id, UTC timestamp, and the exact target server command. These are printed in the table and JSON reports (the JSON report's `_provenance` block).

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

Payload generation and classification are deterministic given the same server version and input arguments; each report carries a unique run id and UTC timestamp.

### 6. Submitting New Entries

Required artifacts (attach all five to the PR; a submission missing any of them is not reviewed):

1. **Server name and exact version** — package version, commit SHA, or container digest; "latest" is not a version.
2. **Exact server command** — the full command used after `--` (e.g. `npx @modelcontextprotocol/server-memory`), so a maintainer can re-run it verbatim.
3. **Toolchain versions** — `mcp-guard` version and payload ruleset version from the report's provenance block.
4. **Full report** — `--format json` output of the run; the table row is derived from it, never hand-written from memory.
5. **Environment** — OS and Python version the run executed on.

Process:

1. Run `mcp-guard fuzz --format json -- <server command>` with the defaults from §3. Note any flag deviations in the PR.
2. Open a PR that adds your row to the Rankings table and (if new) a Key Findings subsection following the format of the existing subsections above. Fill in `.github/pull_request_template.md` — every PR needs a linked issue (open one for the submission if none exists; `pr-link-check` CI fails without it).
3. **Review**: a maintainer re-runs the submitted command with the same mcp-guard and ruleset versions. The row merges when the reproduced payload/finding/crash counts match the submission. Mismatches are resolved on the PR, not post-merge.
