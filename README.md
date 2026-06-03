# mcp-guard

**Adversarial fuzzer for MCP servers** — dynamically break Model Context Protocol endpoints before they reach production. Sends crafted payloads to exposed tools, detects crashes, information leakage, and unexpected behavior.

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-12%20passing-brightgreen.svg)]()

## Why This Exists

**microsoft/agent-governance-toolkit** does static policy checks — *"does this tool declaration look safe?"*

**mcp-guard** does dynamic adversarial testing — *"what happens when I ACTUALLY SEND this payload?"*

That's the difference between reading the label and eating the food. Static governance can't catch runtime vulnerabilities, crashes, or information leakage. mcp-guard sends real malicious inputs and watches what breaks.

## What It Does

1. Spawns an MCP server via stdio transport
2. Enumerates all exposed tools, resources, and prompts
3. Generates **schema-aware adversarial payloads** per tool parameter
4. Fires payloads and classifies responses: SAFE / FINDING / CRASH
5. Outputs a scored report with reproduction steps

### Fuzz Probes

| Probe | What It Sends | What It Catches |
|-------|--------------|-----------------|
| **Shell injection** | `; rm -rf /`, `$(whoami)`, backtick expressions | Command execution surface |
| **SSRF** | `http://169.254.169.254/`, `file:///etc/passwd` | Internal network access |
| **Overflow** | 100KB–1MB strings, 10K-key objects | Buffer overflows, memory leaks |
| **Type confusion** | Wrong types, null for required, arrays for scalars | Missing input validation |
| **Prompt injection** | DAN-style overrides, system prompt extractions | Instruction override, prompt leakage |

Payloads are **intelligent** — they read each tool's `inputSchema` and target specific parameter types. String params get injection + overflow. URI params get SSRF. No-schema tools get the full suite.

## Quick Start

```bash
# Install
pip install mcp-guard

# Fuzz an MCP server
mcp-guard fuzz -- npx @modelcontextprotocol/server-memory

# JSON output for CI pipelines
mcp-guard fuzz --format json -- npx @modelcontextprotocol/server-filesystem /tmp

# SARIF output for GitHub Security tab
mcp-guard fuzz --format sarif -- npx @modelcontextprotocol/server-github

# Static scan (schema analysis, no server needed)
mcp-guard scan -- npx @modelcontextprotocol/server-memory
```

## Example Output

```
$ mcp-guard fuzz -- npx @modelcontextprotocol/server-memory

========================================================================
  mcp-guard fuzz report: npx @modelcontextprotocol/server-memory
========================================================================

  Tools fuzzed:  5
  Payloads sent: 127
  Crashes:       1
  Findings:      18
  Safe:          108

  CRASHES
  --------------------------------------------------------------------
  [CRITICAL] create_entities :: overflow
         payload: AAAAAAAAAA... (100KB string)
         Server crashed or connection lost after payload

  FINDINGS
  --------------------------------------------------------------------
  [CRITICAL] search_nodes :: shell-injection
         payload: $(whoami)
         response: uid=1000(node) gid=1000(node)
  [HIGH] search_nodes :: ssrf
         payload: http://169.254.169.254/latest/meta-data/
         Payload accepted without error — potential vulnerability

========================================================================
  VERDICT: VULNERABLE — crashes detected
========================================================================
```

## Programmatic Usage

```python
from mcp_guard.fuzzer import FuzzEngine
from mcp_guard.payloads import generate_shell_injection

# Use with any transport (custom, mock, etc.)
engine = FuzzEngine(transport=my_transport)
results = engine.fuzz_tool({
    "name": "run_bash",
    "description": "Execute a bash command",
    "inputSchema": {
        "type": "object",
        "properties": {"command": {"type": "string"}},
        "required": ["command"],
    },
})

for r in results:
    if r.category != ResultCategory.SAFE:
        print(f"[{r.severity}] {r.tool_name}: {r.detail}")
```

## Architecture

```
src/mcp_guard/
  fuzzer.py      # Core fuzz engine — orchestrates payload delivery
  payloads.py    # Schema-aware adversarial payload generators
  transport.py   # MCP stdio transport (SSE/HTTP coming)
  scanner.py     # Static schema analysis (OWASP rules)
  report.py      # Output: table, JSON, SARIF
  cli.py         # CLI entry point
```

Zero external dependencies for core fuzzer. Python 3.11+ stdlib only.

## Tech Stack

- Python 3.11+ (stdlib only — no external deps for core)
- pytest for testing (12 tests, 0 failures)
- JSON-RPC over stdio for MCP transport
- Output: CLI table, JSON, SARIF

## CI Integration

```yaml
# GitHub Actions
- name: Fuzz MCP Server
  run: |
    pip install mcp-guard
    mcp-guard fuzz --format sarif -- npx @myorg/mcp-server > results.sarif
    # Upload to GitHub Security tab
```

Exit code 2 = crashes found. Exit code 0 = clean.

## Roadmap

- [ ] SSE + streamable HTTP transports
- [ ] MCP server leaderboard (community fuzzing results)
- [ ] Custom payload config via YAML
- [ ] GitHub Action for automated fuzzing on PR
- [ ] Diff mode: compare fuzz results between versions

## AEO / Structured Data

```html
<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "SoftwareSourceCode",
  "name": "mcp-guard",
  "description": "Adversarial fuzzer for MCP servers — dynamically test Model Context Protocol endpoints against crashes, SSRF, injection, and prompt leakage",
  "programmingLanguage": "Python",
  "license": "https://spdx.org/licenses/MIT",
  "author": {"@type": "Person", "name": "Shoval Benjer"},
  "keywords": ["mcp", "fuzzer", "security", "ai-agent", "owasp", "devsecops", "model-context-protocol", "adversarial-testing"]
}
</script>
```

## License

MIT
