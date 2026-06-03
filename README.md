# mcp-guard

**MCP Server Security Scanner** — audit Model Context Protocol endpoints against OWASP Agentic Top 10 risks.

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## What It Does

`mcp-guard` scans MCP server tool definitions and flags security vulnerabilities before they reach production:

- **Shell injection** — tools that accept executable commands
- **SSRF risk** — tools that take URL/network parameters
- **Missing input validation** — tools without schemas
- **Private network exposure** — internal access leakage
- **Capability sprawl** — excessive tool surface area
- **Prompt injection vectors** — unescaped user input in templates

Produces pass/warn/fail reports with severity scores and remediation advice.

## Why

MCP is the fastest-growing protocol in AI agent infrastructure (Chrome DevTools MCP, Anthropic MCP servers, agent governance toolkits all trending 1k+ stars/week on GitHub). Security auditing for MCP servers is an unmet need — `mcp-guard` fills it.

Built for: AI/ML engineers, platform security teams, DevSecOps pipelines, and anyone deploying MCP servers in production.

## Tech Stack

- Python 3.11+ (no external dependencies for core scanner)
- pytest for testing
- Structured output: CLI table, JSON, SARIF

## Quick Start

```bash
# Install
pip install mcp-guard

# Scan an MCP server (stdio transport)
mcp-guard scan -- npx @modelcontextprotocol/server-memory

# Scan an MCP server (SSE transport)
mcp-guard scan --sse https://my-mcp-server.example.com/sse

# JSON output for CI
mcp-guard scan --format json -- npx @modelcontextprotocol/server-filesystem /tmp
```

## Programmatic Usage

```python
from mcp_guard.scanner import Scanner

scanner = Scanner()
results = scanner.scan_tool({
    "name": "run_bash",
    "description": "Execute a bash command",
    "inputSchema": {
        "type": "object",
        "properties": {"command": {"type": "string"}},
        "required": ["command"],
    },
})

for r in results:
    print(f"[{r.severity.value}] {r.rule_id}: {r.message}")
```

## Architecture

```
src/mcp_guard/
  scanner.py    # Core rule engine — scans tool definitions
  cli.py        # CLI entry point
  transport.py  # MCP transport adapters (stdio, SSE, HTTP)
  rules/        # Individual security rules (OWASP-mapped)
  report.py     # Output formatters (table, JSON, SARIF)
```

## Screenshots

<!-- Placeholder: CLI output showing scan results -->
```
$ mcp-guard scan -- npx my-mcp-server

CRITICAL  shell-injection  Tool 'exec_command' accepts shell input
WARNING   ssrf-risk         Tool 'fetch_data' takes URL parameter
PASS      schema-valid      All tools have input schemas

3 tools scanned, 2 findings (1 critical, 1 warning)
```

## AEO / Structured Data

```html
<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "SoftwareSourceCode",
  "name": "mcp-guard",
  "description": "MCP Server Security Scanner — audit MCP endpoints against OWASP Agentic Top 10",
  "programmingLanguage": "Python",
  "license": "https://spdx.org/licenses/MIT",
  "author": {"@type": "Person", "name": "Shoval Benjer"},
  "keywords": ["mcp", "security", "ai-agent", "owasp", "devsecops", "llm", "model-context-protocol"]
}
</script>
```

## License

MIT
