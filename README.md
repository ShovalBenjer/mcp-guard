<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo.svg">
  <img src="docs/assets/logo.svg" alt="mcp-guard" width="120">
</picture>

# mcp-guard

**Adversarial fuzzer for MCP servers — send real payloads, classify every response.**

[![CI](https://img.shields.io/github/actions/workflow/status/ShovalBenjer/mcp-guard/ci.yml?branch=main&style=for-the-badge)](https://github.com/ShovalBenjer/mcp-guard/actions/workflows/ci.yml)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-CE422B?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-yellow?style=for-the-badge)](LICENSE)
[![unsafe](https://img.shields.io/badge/unsafe-forbidden-success?style=for-the-badge)]()
[![Payloads](https://img.shields.io/badge/payloads-35-blueviolet?style=for-the-badge)](src/payloads.rs)

[What It Does](#what-it-does) · [How to Read Results](#how-to-read-results) · [Real Results](#real-results) · [Install](#install) · [Usage](#usage) · [Rust API](#rust-api) · [Leaderboard](LEADERBOARD.md)

</div>

---

## The Difference

| | Static Governance | mcp-guard |
|---|---|---|
| **What** | Checks tool declarations | Sends real adversarial payloads |
| **How** | "Does this look safe?" | "What happens when I actually send this?" |
| **Analogy** | Reading the nutrition label | Eating the food |
| **Tool** | microsoft/agent-governance-toolkit | This repo |

Written in Rust: a single static binary, `#![forbid(unsafe_code)]`, clippy-pedantic clean.

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

Payloads are **schema-aware** — URI params get SSRF probes, string params get injection + overflow, no-schema tools get a mixed suite. Add your own with `--payloads custom.json` (see [Custom payloads](#custom-payloads)).

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

Requires Rust 1.85+ (edition 2024).

```bash
# Install the binary from source
cargo install --git https://github.com/ShovalBenjer/mcp-guard

# …or build from a clone
git clone https://github.com/ShovalBenjer/mcp-guard.git
cd mcp-guard
cargo build --release
./target/release/mcp-guard --help
```

The default build is lean (`serde`, `serde_json`, `clap`, `thiserror`). YAML config support is an opt-in feature: `cargo build --release --features yaml`.

## Usage

```bash
# Fuzz an MCP server (stdio transport)
mcp-guard fuzz -- npx -y @modelcontextprotocol/server-memory

# JSON output for CI pipelines (progress goes to stderr; stdout is pure JSON)
mcp-guard fuzz --format json -- npx -y @modelcontextprotocol/server-filesystem /tmp/sandbox

# SARIF for the GitHub Security tab
mcp-guard fuzz --format sarif -- npx -y @modelcontextprotocol/server-github

# Safe mode: cap destructive/oversized payloads
mcp-guard fuzz --safe -- npx -y @modelcontextprotocol/server-memory

# Gate CI on more than crashes: fail the run on any accepted-without-validation result
mcp-guard fuzz --fail-on accepted -- npx -y @modelcontextprotocol/server-memory

# Throttle payloads (ms between calls) for rate-limited servers
mcp-guard fuzz --delay-ms 50 -- npx -y @modelcontextprotocol/server-memory

# Static schema scan (no payloads sent)
mcp-guard scan -- npx -y @modelcontextprotocol/server-memory
```

### HTTP transport

Build with `--features http` to fuzz servers over streamable HTTP (JSON and SSE responses are both handled):

```bash
cargo build --release --features http

# Local server — no authorization needed
mcp-guard fuzz --url http://localhost:8080/mcp

# Authenticated server, with a header
mcp-guard fuzz --url http://localhost:8080/mcp --header "Authorization: Bearer $TOKEN"
```

**Authorization gate.** Any target that isn't loopback (`localhost`/`127.0.0.0/8`/`::1`) is refused unless you pass `--i-have-authorization`, and safe mode is forced on for remote targets (override with `--unsafe`). Only fuzz servers you are permitted to test.

**Exit codes.** `2` = crashes found, `1` = error talking to the server (or a soft failure under `--fail-on`), `0` = clean. `--fail-on {crash,finding,accepted,none}` (default `crash`) chooses which result category makes the run fail — e.g. `--fail-on finding` fails on evidence-backed leaks, `--fail-on none` never fails.

**Crash recovery.** If one tool crashes the server, mcp-guard restarts it and continues fuzzing the remaining tools rather than aborting the whole run.

### Custom payloads

Add your own payloads and toggle built-in probes with a JSON config (YAML with `--features yaml`):

```json
{
  "payloads": [
    { "value": "{{7*7}}", "rule_id": "template-injection", "severity": "high",
      "applies_to": ["string"], "evidence": { "contains": "49" } }
  ],
  "probes": { "disable": ["overflow"] }
}
```

```bash
mcp-guard fuzz --payloads custom.json -- npx -y @myorg/mcp-server
```

`applies_to` empty = all parameter types (and no-schema tools). An `evidence.contains` match promotes an accepted response to a `FINDING`.

## Rust API

```rust
use mcp_guard::fuzzer::{FuzzEngine, ResultCategory};
use mcp_guard::transport::StdioTransport;

let mut transport = StdioTransport::spawn(&[
    "npx".into(), "-y".into(), "@modelcontextprotocol/server-memory".into(),
])?;
let engine = FuzzEngine::new(0);
for tool in transport.list_tools()? {
    let results = engine.fuzz_tool(&mut transport, &tool);
    let crashes = results.iter().filter(|r| r.category == ResultCategory::Crash).count();
    let leaks   = results.iter().filter(|r| r.category == ResultCategory::Finding).count();
    if crashes > 0 { eprintln!("DOS: {} crashed on {crashes} payloads", tool["name"]); }
    if leaks  > 0 { eprintln!("LEAK: {} leaked on {leaks} payloads", tool["name"]); }
}
# Ok::<(), mcp_guard::fuzzer::TransportError>(())
```

## CI Integration

```yaml
- name: Security fuzz
  run: |
    cargo install --git https://github.com/ShovalBenjer/mcp-guard
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
src/
  fuzzer.rs      # Core fuzz engine — payload delivery + response classification
  payloads.rs    # 35 adversarial payloads across 5 probe types
  transport.rs   # MCP transports: stdio, and streamable HTTP (feature = "http")
  net.rs         # URL / SSE helpers + loopback detection for the authz gate
  scanner.rs     # Static schema analysis (OWASP-style heuristics)
  report.rs      # Output formatters: table, JSON, SARIF
  config.rs      # Custom payloads / probe toggles (JSON; YAML behind a feature)
  cli.rs         # CLI: fuzz, scan subcommands
  lib.rs / main.rs
```

`#![forbid(unsafe_code)]`, clippy `pedantic` + `nursery` clean, `cargo fmt` enforced in CI.

## Limitations

- **Single-parameter payloads.** Each payload sets one parameter at a time; multi-field injection chains aren't generated.
- **Leak detection is heuristic.** `FINDING` matches known leak signatures (stack traces, `/etc/passwd`, private keys, cloud-metadata fields). A novel leak format can read as `ACCEPTED` — review `ACCEPTED` results on security-sensitive tools by hand.
- **Stateful servers drift.** Tools that write (filesystem, memory) change their own results across runs; fuzz against a fresh sandbox for reproducibility.
- **Blocking reads.** A server that hangs (rather than crashing) is not yet bounded by a read timeout — on the roadmap.

## Roadmap

The full plan — requirements, milestones, and success metrics — lives in the [Product Requirements Document](docs/PRD.md). Near-term highlights:

- [x] Custom payloads via config (JSON in core, YAML behind a feature)
- [x] Crash recovery + `--fail-on` CI gating
- [x] Streamable HTTP transport (`--features http`) with SSE responses
- [x] Safe mode + authorization gate for third-party targets
- [ ] GitHub Action (fuzz on every PR)
- [ ] Diff mode: compare fuzz results between server versions
- [ ] MCP server security leaderboard (community submissions)

## License

[MIT](LICENSE) — Shoval Benjer
