# mcp-guard — Product Requirements Document

| | |
|---|---|
| **Product** | mcp-guard — adversarial fuzzer for MCP servers |
| **Status** | Draft for review |
| **Doc version** | 1.1 |
| **Last updated** | 2026-06-28 |
| **Owner** | Shoval Benjer |
| **Implementation** | Rust (edition 2024, MSRV 1.85) — ported from the Python prototype in v0.3.0 |
| **Current release** | v0.4.1 |
| **Target** | v1.0 (general availability) |

### Resolved decisions
- **Q3 (config dependency)** — *Resolved.* Custom payloads load from **JSON in the core build** (reuses `serde_json`, so the default install adds no parser dependency); **YAML is behind an opt-in `yaml` cargo feature**. Shipped in v0.3.0 (FR-P1).
- **Q5 (hosted/SaaS track)** — *Resolved: in scope* as a post-1.0 track. See §13a.

---

## 1. Summary

mcp-guard is a zero-dependency CLI and Python library that **dynamically fuzzes Model Context Protocol (MCP) servers** — it spawns a server, enumerates its tools, sends schema-aware adversarial payloads, and classifies every response as `REJECTED`, `ACCEPTED`, `FINDING`, or `CRASH`.

Static governance tools (e.g. microsoft/agent-governance-toolkit) inspect a tool's *declaration*. mcp-guard tests what the running server actually *does* with hostile input. The product's defining principle is **honest classification**: a response that merely doesn't error is reported as informational, never as a confirmed vulnerability. This PRD defines the path from the current credible prototype (v0.2.1) to a production-grade v1.0.

---

## 2. Problem & motivation

MCP is becoming the default integration layer between LLM agents and external tools. Every MCP server is reachable by an LLM, and LLMs are routinely prompt-injected via untrusted content (documents, web pages, emails). An attacker who controls model input can cause arbitrary tool calls with arbitrary arguments. That makes each MCP server an attack surface with effectively untrusted callers.

Today there is no widely-adopted way to answer the operational question: *"If a hostile string reaches this tool, what happens?"* Static checks can't answer it. Manual testing doesn't scale across dozens of tools and hundreds of payloads. The gap is a fast, reproducible, **trustworthy** dynamic tester — one whose findings teams will actually act on because it doesn't cry wolf.

### Why "trustworthy" is the moat
The v0.1–v0.2.0 prototype classified every non-error response as a CRITICAL finding, producing "65 findings" against official servers that were all false positives. A security tool that floods users with false criticals gets muted. v0.2.1 corrected this. **Low false-positive rate is the primary product differentiator and must be protected by every future feature.**

---

## 3. Goals & non-goals

### 3.1 Goals (v1.0)
- **G1** — Cover the transports real MCP servers use: stdio, SSE, and streamable HTTP.
- **G2** — Keep the false-positive rate near zero: confirmed findings are backed by concrete evidence, and "accepted-without-validation" stays a distinct, lower-severity signal.
- **G3** — Be CI-native: a first-class GitHub Action, deterministic exit codes, and clean machine-readable output (JSON, SARIF).
- **G4** — Be extensible: users can add custom payloads and probes without forking.
- **G5** — Be responsible by default: safe handling of destructive payloads, explicit consent for third-party targets, and rate-limit controls.
- **G6** — Stay zero-runtime-dependency and stdlib-only where feasible.

### 3.2 Non-goals (v1.0)
- **NG1** — Not a full DAST/web scanner; scope is the MCP surface (tools, resources, prompts), not arbitrary HTTP apps.
- **NG2** — Not an exploit framework; mcp-guard detects and evidences weaknesses, it does not weaponize them.
- **NG3** — Not a static analyzer of server source code (the `scan` subcommand does lightweight schema heuristics only).
- **NG4** — No hosted SaaS or multi-tenant dashboard in v1.0 (possible future track; see §13).
- **NG5** — Not a runtime guardrail / proxy that blocks live agent traffic.

---

## 4. Users & personas

| Persona | Need | How they use mcp-guard |
|---|---|---|
| **MCP server author** | Ship a server that resists hostile tool calls | Runs `fuzz` locally and in CI on every PR; gates merges on no-crash/no-leak |
| **Security engineer / pentester** | Assess third-party or internal MCP servers | Runs ad-hoc fuzz + scan, exports SARIF, triages `ACCEPTED` results on sensitive tools |
| **Platform / DevSecOps team** | Enforce a baseline across many servers | Wires the GitHub Action into shared pipelines; tracks results over time |
| **Researcher** | Survey the ecosystem | Maintains/extends the leaderboard with reproducible results |

---

## 5. Current state — v0.3.0 (Rust)

The product was ported from the Python prototype to **Rust** in v0.3.0 (single static binary,
`#![forbid(unsafe_code)]`, clippy `pedantic`+`nursery` clean, `cargo fmt` enforced). Verified
and reproducible today:

- **Transports:** stdio (subprocess + JSON-RPC handshake); streamable HTTP behind the `http` feature (JSON and SSE responses, `Mcp-Session-Id` handling, `--header` auth passthrough).
- **Authorization gate (FR-R3 — done):** non-loopback HTTP targets are refused without `--i-have-authorization`; safe mode is forced on for remote targets (override with `--unsafe`).
- **Subcommands:** `fuzz` (dynamic), `scan` (static schema heuristics).
- **Probes:** 5 types, 35 distinct payloads — shell injection (8), SSRF (8), overflow (5), type confusion (6+), prompt injection (6). 25 payloads fired per plain string param, 33 per URI string param, 24 for no-schema tools.
- **Custom payloads:** `--payloads <file>` merges user payloads and probe toggles (JSON in core, YAML behind the `yaml` feature). User `evidence.contains` matchers can promote an accepted response to a finding. *(FR-P1 — done.)*
- **Safe mode:** `--safe` caps oversized/destructive payloads (partial FR-R2; consent gate FR-R3 still pending).
- **Crash recovery (FR-R1 — done):** a tool that crashes the server triggers a transport respawn so the remaining tools are still fuzzed; the run only aborts if the server can't be restarted.
- **CI gating (FR-C2 — done):** `--fail-on {crash,finding,accepted,none}` selects which category makes the process exit non-zero.
- **Classification:** `REJECTED` / `ACCEPTED` / `FINDING` (evidence-backed) / `CRASH` / `ERROR`.
- **Output:** table, JSON, SARIF, Markdown; progress on stderr, data on stdout.
- **GitHub Action (FR-CI1 — done):** a composite `action.yml` installs mcp-guard and runs a fuzz with configurable transport, format, and `fail-on`, optionally writing to a file for SARIF upload or PR comments.
- **Exit codes:** 2 = crashes, 1 = transport error or soft failure (per `--fail-on`), 0 = clean.
- **Quality gates:** `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test` (unit + ignored live integration test) in CI.
- **Verified results:** server-memory (0 findings / 41 accepted / 50 rejected), server-filesystem (0 / 24 / 466), both 0 crashes — identical to the Python baseline.

### Known limitations (drive the roadmap)
1. Single-parameter payloads — no multi-field injection chains.
2. Heuristic leak detection — signature-based; novel leak formats read as `ACCEPTED`.
3. Stateful drift — write-capable servers change their own results across runs.
4. HTTP transport handles request/response (incl. SSE-framed replies); it does not yet consume a long-lived server-initiated SSE stream (GET channel).
5. stdio blocking reads — a hung (non-crashing) stdio server is not yet bounded by a read timeout (HTTP requests are timeout-bounded).

---

## 6. Product principles

1. **Honesty over headlines.** Never label "accepted" as "vulnerable." Findings require evidence; everything else is graded informational.
2. **Reproducibility.** Same server + same conditions ⇒ same result. Non-determinism is surfaced, not hidden.
3. **Zero/low dependencies.** Stdlib-first; new deps require justification and stay optional where possible.
4. **Safe by default.** The tool must not cause avoidable damage to targets, and must make third-party testing a conscious choice.
5. **CI-native.** Every capability is scriptable, machine-readable, and exit-code-correct.

---

## 7. Functional requirements

Priorities: **P0** = required for v1.0, **P1** = strongly desired, **P2** = nice-to-have / post-1.0. Each requirement lists acceptance criteria (AC).

### 7.1 Transports
- **FR-T2 (P0) — Streamable HTTP transport. ✅ Done (v0.4.0).** Support the streamable-HTTP transport per the current MCP spec.
  - AC: `fuzz --url <endpoint>` completes a handshake, enumerates tools, and fuzzes them; `application/json` and SSE-framed (`text/event-stream`) responses are both parsed; `Mcp-Session-Id` is captured and echoed. *(Met — verified by an integration test against an in-process stub covering both response types.)*
- **FR-T1 (P1) — Long-lived SSE stream.** Consume a server-initiated SSE (GET) channel in addition to request/response replies. *(Deferred — request/response SSE replies are handled; the persistent GET stream is not yet.)*
- **FR-T3 (P1) — Auth passthrough. ✅ Done (v0.4.0).** Custom headers via repeatable `--header "Name: Value"`.
  - AC: headers are attached to every request; secrets are never echoed into reports. *(Met.)*
- **FR-T4 (P1) — Transport auto-detect. ✅ Done (v0.4.0).** `--url` implies the HTTP transport; `--transport` overrides explicitly.

### 7.2 Probe & payload engine
- **FR-P1 (P0) — Custom payloads via config. ✅ Done (v0.3.0).** Load additional payloads/probes from a JSON file (YAML behind the `yaml` feature). Per Q3, JSON is core (no extra dependency); YAML is an opt-in extra.
  - AC: `fuzz --payloads custom.json` merges user payloads with built-ins; a payload entry specifies value, rule_id, severity, target param-type, and an optional `evidence.contains` matcher that promotes acceptance to a finding. *(Met.)*
- **FR-P2 (P1) — Multi-parameter payloads.** Populate all required params with benign values and inject the adversarial payload into one target at a time (and optionally combinations).
  - AC: tools with multiple required params are fuzzed without spurious "missing required field" rejections masking real behavior.
- **FR-P3 (P1) — Probe selection.** Enable/disable probe categories per run.
  - AC: `fuzz --probes shell,ssrf` runs only those categories; `--exclude-probes overflow` skips large-payload probes.
- **FR-P4 (P2) — Resources & prompts fuzzing.** Extend beyond tools to `resources/*` and `prompts/*` surfaces already enumerated by the transport.
- **FR-P5 (P2) — Encoding/mutation layer.** Apply URL/base64/unicode-escape mutations to evade naive denylists.

### 7.3 Classification & evidence
- **FR-C1 (P0) — Evidence-backed findings only.** A `FINDING` requires a concrete evidence match (leak signature, payload reflection proving execution, or a crash). Maintain the `ACCEPTED` (informational) tier.
  - AC: a regression test asserts a normal non-error response is never classified `FINDING`.
- **FR-C2 (P0) — Configurable failure policy. ✅ Done (v0.3.1).** `--fail-on {crash,finding,accepted,none}` controls the non-zero exit threshold (default `crash`).
  - AC: CI can choose to fail on findings without failing on accepted. *(Met; exit-code logic is unit-tested.)*
- **FR-C3 (P1) — Reflection detection.** Flag a finding when an injected marker payload is echoed back in a context indicating execution/interpolation (distinct from mere storage).
  - AC: a fixture server that interpolates input into a shell string is detected; one that merely stores and returns it is not.
- **FR-C4 (P1) — Extensible evidence matchers.** Leak/evidence signatures are data-driven and user-extendable alongside FR-P1.
- **FR-C5 (P2) — Confidence scoring.** Attach a confidence level to each result to aid triage.

### 7.4 Reliability & safety
- **FR-R1 (P0) — Crash recovery. ✅ Done (v0.3.1).** On lost transport, record the crash, respawn/reconnect, and continue with the remaining tools.
  - AC: a fixture server that exits on a specific payload still yields results for all other tools. *(Met — verified with a stub server: the crashing tool's results are recorded, the transport respawns, and subsequent tools are fuzzed. Recovery is at the tool boundary; payloads remaining within the crashing tool are not retried.)*
- **FR-R2 (P0) — Safe mode for destructive payloads.** `--safe` caps oversized payloads and is forced on for remote targets (override with `--unsafe`). *(Partial — size caps done; substituting inert sentinels for literally-destructive shell payloads is still pending.)*
- **FR-R3 (P0) — Third-party consent gate. ✅ Done (v0.4.0).** Fuzzing a non-loopback HTTP target requires explicit `--i-have-authorization` and prints a responsible-use notice.
  - AC: without the flag, non-local targets are refused with a clear message. *(Met; loopback detection is unit-tested.)*
- **FR-R4 (P1) — Rate limiting / adaptive throttle.** Beyond `--delay-ms`, support adaptive backoff on rising latency or error bursts.
- **FR-R5 (P1) — Per-tool timeout & overall budget.** Honor `--timeout` per call and a global `--max-duration`.

### 7.5 Reporting & output
- **FR-O1 (P0) — Stable JSON schema.** Versioned, documented JSON output with the `accepted` bucket; backward-compatible within a major version.
- **FR-O2 (P0) — SARIF correctness.** Valid SARIF 2.1.0: crash→`error`, finding→`warning`, accepted→`note`; uploads cleanly to the GitHub Security tab.
- **FR-O3 (P1) — Markdown report. ✅ Done (v0.4.1).** `--format markdown` renders a GitHub-flavored summary table + findings tables suitable for PR comments (table-cell pipes escaped). *(Met; unit-tested.)*
- **FR-O4 (P1) — Reproduction steps.** Each result includes a copy-pasteable repro (tool, param, exact payload, transport invocation).
- **FR-O5 (P2) — Severity normalization.** Map findings to a documented severity rubric (CVSS-like or qualitative) consistently across probes.

### 7.6 CI/CD integration
- **FR-CI1 (P0) — Official GitHub Action. ✅ Done (v0.4.1).** A `uses:`-able composite action (`action.yml`) that installs mcp-guard and runs `fuzz`.
  - AC: configurable transport (`command`/`url`), `format`, `fail-on`, `headers`, `safe`, `authorized`, and `output-file`; fails the job per `--fail-on` and can write SARIF for upload. *(Met — arg-building verified against the real binary.)*
- **FR-CI2 (P1) — PR annotations.** Post a concise summary (and optionally inline findings) as a PR comment.
- **FR-CI3 (P2) — Baseline / suppression file.** Allow known-accepted results to be baselined so CI only flags new deltas.

### 7.7 Diff mode
- **FR-D1 (P1) — Result diffing.** `diff <baseline.json> <current.json>` reports newly-introduced findings/crashes and resolved ones.
  - AC: a regression that turns a `REJECTED` into an `ACCEPTED`/`FINDING` is detected and exits non-zero under policy.
- **FR-D2 (P2) — Trend storage.** Optional append-only history to track a server's posture over versions.

### 7.8 Leaderboard
- **FR-L1 (P1) — Reproducible submissions.** A documented, scriptable process (and schema) for community leaderboard entries, including environment capture for reproducibility.
- **FR-L2 (P2) — Automated refresh.** A scheduled job re-runs the published set and flags drift.

### 7.9 Library / API
- **FR-A1 (P0) — Stable public API.** `FuzzEngine`, `StdioTransport`/transport protocol, `FuzzResult`, `ResultCategory`, and report types are documented and semver-stable.
- **FR-A2 (P1) — Programmatic config.** Everything exposed on the CLI (probe selection, payload injection, policies) is reachable from the library.

---

## 8. Non-functional requirements

- **NFR-1 Performance.** Fuzz a 15-tool server with the default suite in < 30 s on stdio (excluding server cold-start). Payload firing is I/O-bound; support optional concurrency where the transport allows.
- **NFR-2 Determinism.** With a fixed seed and a stateless target, results are byte-identical across runs. State-dependence is documented per target.
- **NFR-3 Compatibility.** Python 3.11–3.13; Linux/macOS/Windows. Track the current MCP protocol version with graceful failure on unknown message types.
- **NFR-4 Dependencies.** Lean, audited core: `serde`/`serde_json`/`clap`/`thiserror`. New formats and transports land behind **optional cargo features** (e.g. `--features yaml`, future `--features http`); the default build stays minimal. `#![forbid(unsafe_code)]` crate-wide.
- **NFR-5 Security & privacy.** Never log secrets; redact auth material in all outputs; no telemetry without explicit opt-in.
- **NFR-6 Reliability.** A single tool's failure never aborts the whole run (see FR-R1). Non-zero exit only per the configured policy.
- **NFR-7 Maintainability.** ruff + mypy clean; test coverage on the classifier, transports, and report formatters. Single source of truth for version (`__version__`), enforced by test.
- **NFR-8 Documentation.** Every flag, exit code, and output schema documented; README "How to Read Results" kept in sync with classifier behavior.
- **NFR-9 Observability.** `--verbose`/`--quiet` levels; progress to stderr only; machine output to stdout only.

---

## 9. Detailed specs for near-term priorities

### 9.1 Safe mode & consent (FR-R2, FR-R3) — *ship with, or before, networked transports*
Once SSE/HTTP land, mcp-guard can hit remote targets, which raises real blast-radius and authorization concerns. Required behavior:
- Targets resolving to loopback/private ranges: default `--safe` on, no consent flag required.
- Any other target: refuse unless `--i-have-authorization` is present; print a one-line responsible-use notice and the resolved target.
- In `--safe`, destructive shell payloads are replaced by inert sentinels that still exercise the parsing/validation path (e.g. `; echo MCPGUARD_MARKER_$(:)` style markers) without destructive intent. `--unsafe` opts back into raw payloads with a printed warning.
- Overflow caps: in safe mode, cap the largest payload (e.g. 100 KB instead of 1 MB) unless `--unsafe`.

### 9.2 Custom payloads (FR-P1) — config schema sketch
```yaml
# custom.yml
payloads:
  - value: "{{7*7}}"            # template injection
    rule_id: template-injection
    severity: high
    applies_to: [string]        # param types
    evidence:                   # optional: promotes ACCEPTED -> FINDING on match
      contains: "49"
probes:
  disable: [overflow]           # turn off built-in categories
```
- Merge semantics: user payloads are additive; `probes.disable` removes built-in categories. Validation errors in the file fail fast with line context.

### 9.3 GitHub Action (FR-CI1) — interface sketch
```yaml
- uses: ShovalBenjer/mcp-guard@v1
  with:
    command: "npx -y @myorg/mcp-server"   # or url + transport
    format: sarif
    fail-on: crash                         # crash | finding | accepted | none
    sandbox-dir: /tmp/sandbox              # for write-capable servers
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: results.sarif }
```

---

## 10. Architecture notes

Current Rust module layout:

```
src/
  fuzzer.rs      # engine: payload delivery + classification; Transport trait
  payloads.rs    # built-in payload generators
  transport.rs   # stdio transport implementing Transport
  scanner.rs     # static schema heuristics
  report.rs      # table / JSON / SARIF formatters
  config.rs      # custom payloads / probe toggles (JSON; YAML feature)
  cli.rs         # clap parsing + orchestration
  lib.rs, main.rs
```

Planned evolution:
- **Transport** becomes a module group (`transport/{stdio,sse,http}.rs`) behind the existing `Transport` trait so the engine stays transport-agnostic. HTTP/SSE crates live behind optional cargo features.
- **Policy** (fail-on, safe mode, consent) becomes a small config struct threaded from CLI/library into the engine — keeping `cli.rs` thin.
- **Report** gains markdown/HTML emitters alongside the existing formatters; the JSON schema is versioned and snapshot-tested.
- **Reliability** adds bounded reads (timeout via a reader thread/channel) and crash respawn (FR-R1).

---

## 11. Release plan

| Release | Theme | Scope (FR IDs) |
|---|---|---|
| **v0.3** ✅ | Rust port + extensibility + reliability | Rust rewrite, FR-C1✓, FR-P1✓, FR-A1✓, FR-R1✓, FR-C2✓, partial FR-R2 (`--safe`), NFR-4/-7 |
| **v0.4** ✅ | Networked transport + safety | FR-T2✓, FR-T3✓, FR-T4✓, FR-R3✓, partial FR-R2 (`--safe` for remote) |
| **v0.4.1** ✅ | Reporting & CI | FR-O3✓ (Markdown), FR-CI1✓ (GitHub Action) |
| **v0.5** | Trust & reliability | FR-C3, FR-C4, FR-P2, FR-P3, FR-O1, FR-T1 (SSE GET), FR-R4, read-timeout |
| **v0.6** | CI & reporting | FR-CI2, FR-O4, FR-D1 |
| **v1.0** | GA hardening | All P0 complete; docs, stable JSON/API, leaderboard process (FR-L1), responsible-use defaults |
| **post-1.0** | Reach | FR-P4, FR-P5, FR-C5, FR-CI3, FR-D2, FR-L2, hosted track (§13) |

✓ = already delivered in v0.2.1.

---

## 12. Success metrics

- **M1 — False-positive rate.** On a curated corpus of known-hardened servers, confirmed `FINDING`s that are false ≈ 0. *(Primary metric.)*
- **M2 — True-positive recall.** On a corpus of intentionally-vulnerable fixture servers (shell-out, SSRF, crash-on-overflow, leak), mcp-guard detects ≥ 95% as `FINDING`/`CRASH`.
- **M3 — Coverage.** % of MCP transports supported (target 3/3 by v1.0).
- **M4 — Adoption.** GitHub Action installs; repos with mcp-guard in CI; leaderboard submissions.
- **M5 — Reproducibility.** % of published leaderboard rows that re-run to the same numbers on a clean environment (target 100% for stateless targets).
- **M6 — Performance.** P50 run time for a 15-tool stdio server under target (NFR-1).

---

## 13. Risks & mitigations

| # | Risk | Mitigation |
|---|---|---|
| R1 | Re-introducing false positives as probes grow | FR-C1 regression tests; evidence-required findings; M1 tracked per release |
| R2 | Destructive payloads damage a target | FR-R2 safe mode default; FR-R3 consent gate; overflow caps |
| R3 | Authorization/abuse (fuzzing servers without permission) | Consent gate, responsible-use notice, docs; refuse non-local without opt-in |
| R4 | MCP protocol drift breaks the handshake | Version-pin constants, graceful unknown-message handling, conformance tests per spec rev |
| R5 | Dependency creep erodes "zero-dep" positioning | Optional extras only; core stays stdlib; CI asserts default install pulls nothing |
| R6 | Non-determinism from stateful servers confuses users | Document per-target; sandbox guidance; seed control; diff mode baselines |
| R7 | Secret leakage via reports/logs | NFR-5 redaction; tests asserting auth material never appears in output |

---

## 13a. Hosted / SaaS track (Q5 — in scope, post-1.0)

A managed offering on top of the open-source CLI. The CLI/library remains the engine and stays
fully usable standalone; the hosted product adds continuity and collaboration. Requires its own
detailed PRD before build; this section sets the intent and guardrails.

- **HS-1 — Continuous monitoring.** Scheduled fuzz runs against registered MCP servers (stdio via a customer-side runner, or networked transports once shipped), with alerting on new findings/crashes.
- **HS-2 — Trend dashboard.** Per-server posture over time, built on diff mode (FR-D1/FR-D2): new vs resolved findings, accepted-without-validation deltas.
- **HS-3 — Team workflows.** Triage state, suppressions/baselines (FR-CI3), and shareable reports (FR-O3).
- **HS-4 — Org policy.** Centralized `--fail-on` and probe policies enforced across a fleet of pipelines.
- **HS-5 — Authorization & isolation.** Hosted runs must honor the same consent model (FR-R3) and run fuzzing in isolated, customer-scoped runners; never store secrets (NFR-5).
- **Boundary.** Open-source parity is preserved — no engine capability is gated behind the SaaS. The hosted product sells *continuity, history, and collaboration*, not the fuzzer itself.

## 14. Open questions

- **Q1** — Concurrency model for networked transports: per-tool parallelism vs strict sequential for determinism? (Lean sequential by default, opt-in concurrency.)
- **Q2** — Should `scan` (static heuristics) remain in scope, or be deprecated in favor of pure dynamic fuzzing?
- **Q4** — Severity rubric: adopt a CVSS-like score or keep qualitative critical/high/medium?

> Q3 (config dependency) and Q5 (hosted track) are resolved — see the header and §13a.

---

## 15. Out of scope (v1.0)

Full web DAST; exploit/weaponization; source-level SAST; runtime guardrail/proxy; hosted multi-tenant dashboard; auto-remediation/patching of target servers.

---

## 16. Appendix — glossary

- **MCP** — Model Context Protocol; the agent↔tool integration protocol.
- **Tool** — a callable an MCP server exposes, with a JSON-Schema `inputSchema`.
- **Probe** — a category of adversarial payloads (shell, SSRF, overflow, type-confusion, prompt-injection).
- **REJECTED** — server returned an error for the payload (desired behavior).
- **ACCEPTED** — normal response, no evidence of harm (informational: missing validation).
- **FINDING** — accepted *and* concrete evidence of a problem (leak/reflection).
- **CRASH** — server died or dropped the connection after a payload (DoS).
- **Safe mode** — substitutes inert markers for destructive payloads to bound blast radius.
