# MCP Server Security Leaderboard

Results from running [mcp-guard](https://github.com/ShovalBenjer/mcp-guard) against popular MCP servers.

**Last updated: 2026-06-03**
**mcp-guard version: 0.2.1**

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

## Methodology

Each server was:
1. Spawned via stdio transport
2. Enumerated for all tools
3. Fuzzed with schema-aware adversarial payloads (shell injection, SSRF, overflow, type confusion, prompt injection)
4. Responses classified: SAFE (expected error), FINDING (accepted without error), CRASH (server died)

## Want your server tested?

```bash
pip install -e ".[dev]"  # from repo
mcp-guard fuzz -- npx @your-org/your-mcp-server
```

Open a PR with your results added to this file.
