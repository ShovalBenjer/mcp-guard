# MCP Server Security Leaderboard

Results from running [mcp-guard](https://github.com/ShovalBenjer/mcp-guard) against popular MCP servers.

**Last updated: 2026-06-27**
**mcp-guard version: 0.2.1**

> **Reading the table:** a *finding* means a payload was accepted **and** the response showed concrete evidence of a leak. *Accepted* means the server returned a normal response with no evidence of harm — informational (missing input validation), not a confirmed vulnerability. *Rejected* means the server correctly errored. See [How to Read Results](README.md#how-to-read-results). The exit code is non-zero only on crashes.

## Rankings

| # | Server | Tools | Payloads | Crashes | Findings | Accepted | Rejected | Verdict |
|---|--------|-------|----------|---------|----------|----------|----------|---------|
| 1 | @modelcontextprotocol/server-filesystem | 14 | 490 | 0 | 0 | 24 | 466 | NO CONFIRMED VULNS |
| 2 | @modelcontextprotocol/server-memory | 9 | 91 | 0 | 0 | 41 | 50 | NO CONFIRMED VULNS |

Both official servers handled the full payload set without crashing and without leaking. The remaining `Accepted` results are inputs that passed through without an error — worth reviewing, but not exploits.

## Notes

### @modelcontextprotocol/server-memory (9 tools, 41 accepted)

- The 41 `Accepted` results are concentrated in **no-schema tools** (`read_graph`, `search_nodes`, `open_nodes`) that ignore parameters they don't use — they return their normal output regardless of the payload string.
- No payload was executed and nothing leaked. Sending `$(whoami)` to `read_graph` returns the same empty graph as any other input.
- **Takeaway:** the server accepts arbitrary strings without validation, but exposes no command-execution, SSRF, or file-read surface for these payloads to reach.

### @modelcontextprotocol/server-filesystem (14 tools, 24 accepted)

- 466 of 490 payloads (95%) were rejected with an error — strong input validation on the file-operation tools (`read_file`, `write_file`, `edit_file`).
- The 24 `Accepted` results are tools that **ignore irrelevant parameters** (e.g. `list_allowed_directories`).
- **Reproducibility:** this server's tools *write* during fuzzing, so the `Accepted` count drifts upward if the target directory already contains files. Run against a **fresh empty directory** for the numbers above.

## Methodology

Each server was:
1. Spawned via stdio transport
2. Enumerated for all tools
3. Fuzzed with schema-aware adversarial payloads (shell injection, SSRF, overflow, type confusion, prompt injection)
4. Responses classified:
   - **REJECTED** — server returned an error (expected, good)
   - **ACCEPTED** — normal response, no evidence of harm (informational)
   - **FINDING** — accepted *and* the response leaked sensitive data (stack trace, `/etc/passwd`, key, cloud metadata)
   - **CRASH** — server died after the payload

## Want your server tested?

```bash
pip install -e ".[dev]"  # from repo
mkdir -p /tmp/sandbox
mcp-guard fuzz -- npx -y @your-org/your-mcp-server
```

Open a PR with your results added to this file.
