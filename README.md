<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo.svg">
  <img src="docs/assets/logo.svg" alt="mcp-guard" width="120">
</picture>

# mcp-guard

**Adversarial fuzzer for MCP servers — send real payloads, classify every response.**

[![CI](https://img.shields.io/github/actions/workflow/status/ShovalBenjer/mcp-guard/ci.yml?branch=main&style=for-the-badge)](https://github.com/ShovalBenjer/mcp-guard/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-yellow?style=for-the-badge)](LICENSE)
[![Zero Deps](https://img.shields.io/badge/dependencies-0-green?style=for-the-badge)]()
[![Payloads](https://img.shields.io/badge/payloads-35-blueviolet?style=for-the-badge)](src/mcp_guard/payloads.py)

[What It Does](#what-it-does) · [How to Read Results](#how-to-read-results) · [Real Results](#real-results) · [Install](#install) · [Usage](#usage) · [Python API](#python-api) · [Leaderboard](LEADERBOARD.md)

</div>

---

## The Difference

| | Static Governance | mcp-guard |
|---|---|---|
| **What** | Checks tool declarations | Sends real adversarial payloads |
| **How** | "Does this look safe?" | "What happens when I actually send this?" |
| **Analogy** | Reading the nutrition label | Eating the food |
| **Tool** | microsoft/agent-governance-toolkit | This repo |

## What It Does

1. Spawns your MCP server via stdio transport
2. Enumerates all exposed tools
3. Reads each tool's `inputSchema` and generates **schema-aware adversarial payloads**
4. Fires the payloads at each parameter and classifies every response
5. Reports each result as `REJECTED` / `ACCEPTED` / `FINDING` / `CRASH`

35 distinct payloads span 5 probe types; **25–33 are fired per string parameter** depending on its type (URI parameters also get SSRF probes), and tools with no input schema receive a 24-payload mixed suite.

### 5 Probe Types

| Probe | Example Payloads | Catches |
|:------|:-----------------|:--------|
| **Shell injection** | `$(whoami)` `` `cat /etc/passwd` `` `; rm -rf /` | Command execution surface |
| **SSRF** | `http://169.254.169.254/` `file:///etc/passwd` `dict://` | Cloud metadata, internal network |
| **Overflow** | 10KB → 1MB strings, 10K-key objects | Buffer overflows, OOM |
| **Type confusion** | Wrong types, null for required, arrays for scalars | Missing input validation |
| **Prompt injection** | DAN override, system prompt extraction, XML injection | Instruction override, prompt leak |

Payloads are **schema-aware** — URI params get SSRF probes, string params get injection + overflow, no-schema tools get a mixed suite.

## How to Read Results

mcp-guard is a fuzzer, not an oracle. It tells you how a server *responded* to hostile input — it does **not** assert exploitability. Every response lands in one of four buckets:

| Category | Meaning | Is it a vulnerability? |
|:---------|:--------|:-----------------------|
| **REJECTED** | Server returned an error (`isError`) for the payload | No — this is the desired behavior |
| **ACCEPTED** | Server returned a normal response, no evidence of harm | **Not by itself.** Signals missing input validation. Worth a look, especially for tools that touch the shell, filesystem, or network. |
| **FINDING** | Accepted **and** the response contains concrete evidence of a leak (stack trace, `/etc/passwd` contents, a private key, cloud-metadata fields) | Likely — investigate |
| **CRASH** | Server died / dropped the connection after the payload | Yes — a denial-of-service bug |

> **Why this matters:** a tool like `read_graph` that takes no input will happily return its normal result no matter what string you hand it. That is an `ACCEPTED`, not a critical shell-injection. mcp-guard only escalates to `FINDING` when the response itself proves something leaked. The exit code is non-zero **only on crashes**.

## Real Results

Tested against **official Anthropic MCP servers** — real servers, real payloads. Results are reproducible with the commands shown ([full leaderboard →](LEADERBOARD.md)).

**Headline: 0 confirmed vulnerabilities. 0 crashes.** Both servers reject the majority of payloads. What's left is *accepted-without-validation* — informational, not exploits.

```
$ mcp-guard fuzz -- npx -y @modelcontextprotocol/server-memory

  Tools fuzzed:  9
  Payloads sent: 91
  Crashes:       0
  Findings:      0   (accepted + concrete evidence of harm)
  Accepted:      41   (no validation, no evidence of harm)
  Rejected:      50   (server returned an error)

  VERDICT: no confirmed vulnerabilities. 41 payload(s) accepted
           without validation — review input handling.
```

The 41 `ACCEPTED` results are no-schema tools (`read_graph`, `search_nodes`) returning their normal output when handed adversarial strings — they ignore input they don't use. No payload was executed, nothing leaked.

```
$ mkdir /tmp/sandbox
$ mcp-guard fuzz -- npx -y @modelcontextprotocol/server-filesystem /tmp/sandbox

  Tools fuzzed:  14
  Payloads sent: 490
  Crashes:       0
  Findings:      0
  Accepted:      24
  Rejected:      466

  VERDICT: no confirmed vulnerabilities. 24 payload(s) accepted
           without validation — review input handling.
```

> The filesystem server's `ACCEPTED` count depends on the contents of the target directory (its tools *write* during fuzzing). Run against a **fresh, empty directory** for the reproducible numbers above.

## Install

```bash
git clone https://github.com/ShovalBenjer/mcp-guard.git
cd mcp-guard
pip install -e ".[dev]"
```

## Usage

```bash
# Fuzz an MCP server (stdio transport)
mcp-guard fuzz -- npx -y @modelcontextprotocol/server-memory

# JSON output for CI pipelines (progress goes to stderr; stdout is pure JSON)
mcp-guard fuzz --format json -- npx -y @modelcontextprotocol/server-filesystem /tmp/sandbox

# SARIF for the GitHub Security tab
mcp-guard fuzz --format sarif -- npx -y @modelcontextprotocol/server-github

# Throttle payloads (ms between calls) for rate-limited servers
mcp-guard fuzz --delay-ms 50 -- npx -y @modelcontextprotocol/server-memory

# Static schema scan (no payloads sent)
mcp-guard scan -- npx -y @modelcontextprotocol/server-memory
```

Exit codes: `0` = no crashes, `1` = error talking to the server, `2` = crashes found.

## Python API

```python
from mcp_guard.fuzzer import FuzzEngine, ResultCategory
from mcp_guard.transport import StdioTransport

with StdioTransport(["npx", "-y", "@modelcontextprotocol/server-memory"]) as transport:
    engine = FuzzEngine(transport=transport)
    for tool in transport.list_tools():
        results = engine.fuzz_tool(tool)
        crashes = [r for r in results if r.category == ResultCategory.CRASH]
        leaks = [r for r in results if r.category == ResultCategory.FINDING]
        if crashes:
            print(f"DOS: {tool['name']} crashed on {len(crashes)} payloads")
        if leaks:
            print(f"LEAK: {tool['name']} leaked data on {len(leaks)} payloads")
```

## CI Integration

```yaml
- name: Security fuzz
  run: |
    pip install -e ".[dev]"
    mkdir -p /tmp/sandbox
    mcp-guard fuzz --format sarif -- npx -y @myorg/mcp-server > results.sarif
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

Crashes become SARIF `error`s, leaks become `warning`s, and accepted-without-validation results become `note`s.

## Architecture

```
src/mcp_guard/
  fuzzer.py      # Core fuzz engine — payload delivery + response classification
  payloads.py    # 35 adversarial payloads across 5 probe types
  transport.py   # MCP stdio transport (JSON-RPC handshake)
  scanner.py     # Static schema analysis (OWASP rules)
  report.py      # Output formatters: table, JSON, SARIF
  cli.py         # CLI: fuzz, scan subcommands
```

Zero external dependencies. Python 3.11+ stdlib only.

## Limitations

- **Stdio transport only.** SSE / streamable HTTP are on the roadmap.
- **Single-parameter payloads.** Each payload sets one parameter at a time; multi-field injection chains aren't generated.
- **Leak detection is heuristic.** `FINDING` matches known leak signatures (stack traces, `/etc/passwd`, private keys, cloud-metadata fields). A novel leak format can read as `ACCEPTED` — review `ACCEPTED` results on security-sensitive tools by hand.
- **Stateful servers drift.** Tools that write (filesystem, memory) change their own results across runs; fuzz against a fresh sandbox for reproducibility.

## Roadmap

- [ ] SSE + streamable HTTP transports
- [ ] MCP server security leaderboard (community submissions)
- [ ] Custom payloads via YAML config
- [ ] GitHub Action (fuzz on every PR)
- [ ] Diff mode: compare fuzz results between server versions

## License

[MIT](LICENSE) — Shoval Benjer
