# mcp-guard — Product Requirements Document

| | |
|---|---|
| **Product** | mcp-guard — adversarial fuzzer for MCP servers |
| **Status** | Draft for review |
| **Doc version** | 1.0 |
| **Last updated** | 2026-06-28 |
| **Owner** | Shoval Benjer |
| **Current release** | v0.2.1 |
| **Target** | v1.0 (general availability) |

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

## 5. Current state — v0.2.1 (baseline)

Verified and reproducible today:

- **Transport:** stdio (subprocess + JSON-RPC handshake).
- **Subcommands:** `fuzz` (dynamic), `scan` (static schema heuristics).
- **Probes:** 5 types, 35 distinct payloads — shell injection (8), SSRF (8), overflow (5), type confusion (6+), prompt injection (6). 25 payloads fired per plain string param, 33 per URI string param, 24 for no-schema tools.
- **Classification:** `REJECTED` / `ACCEPTED` / `FINDING` (evidence-backed) / `CRASH` / `ERROR`.
- **Output:** table, JSON, SARIF; progress on stderr, data on stdout.
- **Exit codes:** 0 = no crashes, 1 = transport error, 2 = crash found.
- **Quality gates:** ruff + mypy + pytest in CI across Python 3.11–3.13.
- **Verified results:** server-memory (0 findings / 41 accepted / 50 rejected), server-filesystem (0 / 24 / 466), both 0 crashes.

### Known limitations (drive the roadmap)
1. stdio only — no SSE / HTTP.
2. Single-parameter payloads — no multi-field injection chains.
3. Heuristic leak detection — signature-based; novel leak formats read as `ACCEPTED`.
4. Stateful drift — write-capable servers change their own results across runs.
5. No custom-payload mechanism — probes are hard-coded.
6. No consent/safety gating for destructive payloads or third-party targets.
7. No retry/respawn after a crash — fuzzing stops at first lost transport.

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
- **FR-T1 (P0) — SSE transport.** Connect to MCP servers over Server-Sent Events.
  - AC: `fuzz --transport sse --url <endpoint>` completes a handshake, enumerates tools, and fuzzes them; covered by an integration test against a local SSE fixture.
- **FR-T2 (P0) — Streamable HTTP transport.** Support the streamable-HTTP transport per current MCP spec.
  - AC: same flow as FR-T1 over HTTP; honors auth headers via `--header`.
- **FR-T3 (P1) — Auth passthrough.** Allow bearer tokens / custom headers / env-based secrets for authenticated servers.
  - AC: secrets are never echoed to stdout/stderr or written into reports.
- **FR-T4 (P1) — Transport auto-detect.** Infer transport from the argument shape (command vs URL) with an explicit `--transport` override.

### 7.2 Probe & payload engine
- **FR-P1 (P0) — Custom payloads via config.** Load additional payloads/probes from a YAML (or JSON) file.
  - AC: `fuzz --payloads custom.yml` merges user payloads with built-ins; a payload entry specifies value, rule_id, severity, target param-type, and an optional expected-evidence matcher.
- **FR-P2 (P1) — Multi-parameter payloads.** Populate all required params with benign values and inject the adversarial payload into one target at a time (and optionally combinations).
  - AC: tools with multiple required params are fuzzed without spurious "missing required field" rejections masking real behavior.
- **FR-P3 (P1) — Probe selection.** Enable/disable probe categories per run.
  - AC: `fuzz --probes shell,ssrf` runs only those categories; `--exclude-probes overflow` skips large-payload probes.
- **FR-P4 (P2) — Resources & prompts fuzzing.** Extend beyond tools to `resources/*` and `prompts/*` surfaces already enumerated by the transport.
- **FR-P5 (P2) — Encoding/mutation layer.** Apply URL/base64/unicode-escape mutations to evade naive denylists.

### 7.3 Classification & evidence
- **FR-C1 (P0) — Evidence-backed findings only.** A `FINDING` requires a concrete evidence match (leak signature, payload reflection proving execution, or a crash). Maintain the `ACCEPTED` (informational) tier.
  - AC: a regression test asserts a normal non-error response is never classified `FINDING`.
- **FR-C2 (P0) — Configurable failure policy.** `--fail-on {crash,finding,accepted,none}` controls the non-zero exit threshold (default `crash`).
  - AC: CI can choose to fail on findings without failing on accepted.
- **FR-C3 (P1) — Reflection detection.** Flag a finding when an injected marker payload is echoed back in a context indicating execution/interpolation (distinct from mere storage).
  - AC: a fixture server that interpolates input into a shell string is detected; one that merely stores and returns it is not.
- **FR-C4 (P1) — Extensible evidence matchers.** Leak/evidence signatures are data-driven and user-extendable alongside FR-P1.
- **FR-C5 (P2) — Confidence scoring.** Attach a confidence level to each result to aid triage.

### 7.4 Reliability & safety
- **FR-R1 (P0) — Crash recovery.** On lost transport, record the crash-causing payload, respawn/reconnect, and continue remaining probes.
  - AC: a fixture server that exits on a specific payload still yields results for all other tools.
- **FR-R2 (P0) — Safe mode for destructive payloads.** A `--safe` mode (default on for non-localhost / third-party targets) substitutes inert markers for destructive payloads (`; rm -rf /` → tagged sentinel) so mcp-guard never induces real data loss it can avoid.
  - AC: in safe mode no payload contains a literally destructive command; `--unsafe` is required to send raw destructive payloads and prints a warning.
- **FR-R3 (P0) — Third-party consent gate.** Fuzzing a target that isn't localhost/loopback requires explicit `--i-have-authorization` (or config equivalent) and prints a responsible-use notice.
  - AC: without the flag, non-local targets are refused with a clear message.
- **FR-R4 (P1) — Rate limiting / adaptive throttle.** Beyond `--delay-ms`, support adaptive backoff on rising latency or error bursts.
- **FR-R5 (P1) — Per-tool timeout & overall budget.** Honor `--timeout` per call and a global `--max-duration`.

### 7.5 Reporting & output
- **FR-O1 (P0) — Stable JSON schema.** Versioned, documented JSON output with the `accepted` bucket; backward-compatible within a major version.
- **FR-O2 (P0) — SARIF correctness.** Valid SARIF 2.1.0: crash→`error`, finding→`warning`, accepted→`note`; uploads cleanly to the GitHub Security tab.
- **FR-O3 (P1) — Markdown/HTML report.** Human-readable report artifact suitable for PR comments and sharing.
- **FR-O4 (P1) — Reproduction steps.** Each result includes a copy-pasteable repro (tool, param, exact payload, transport invocation).
- **FR-O5 (P2) — Severity normalization.** Map findings to a documented severity rubric (CVSS-like or qualitative) consistently across probes.

### 7.6 CI/CD integration
- **FR-CI1 (P0) — Official GitHub Action.** A `uses:`-able action that installs, runs `fuzz`, and surfaces results.
  - AC: documented action runs against a sample server, fails the job per `--fail-on`, and can upload SARIF.
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
- **NFR-4 Dependencies.** Core stays stdlib-only. SSE/HTTP/YAML may introduce **optional** extras (`pip install mcp-guard[http]`); the default install remains zero-dependency.
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

Current module layout is sound and should be preserved:

```
src/mcp_guard/
  fuzzer.py      # engine: payload delivery + classification
  payloads.py    # built-in payload generators
  transport.py   # stdio transport (Transport protocol)
  scanner.py     # static schema heuristics
  report.py      # table / JSON / SARIF formatters
  cli.py         # argument parsing + orchestration
```

Planned evolution:
- **Transport** becomes a package (`transport/{stdio,sse,http}.py`) behind the existing `Transport` Protocol so the engine is transport-agnostic. New deps stay isolated to the HTTP/SSE modules and optional extras.
- **Payloads/probes** become data-driven (built-in YAML + user YAML) loaded into the same `Payload` dataclass, so FR-P1/FR-C4 share one path.
- **Policy** (fail-on, safe mode, consent) lives in a small config object threaded from CLI/library into the engine — not scattered through `cli.py`.
- **Report** gains markdown/HTML emitters alongside the existing formatters; the JSON schema is versioned and snapshot-tested.

---

## 11. Release plan

| Release | Theme | Scope (FR IDs) |
|---|---|---|
| **v0.3** | Trust & policy hardening | FR-C1✓, FR-C2, FR-R1, FR-O1, FR-A1, NFR-2/-7 |
| **v0.4** | Networked transports + safety | FR-T1, FR-T2, FR-T3, FR-R2, FR-R3, FR-R4 |
| **v0.5** | Extensibility | FR-P1, FR-P2, FR-P3, FR-C4 |
| **v0.6** | CI & reporting | FR-CI1, FR-CI2, FR-O2✓, FR-O3, FR-O4, FR-D1 |
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

## 14. Open questions

- **Q1** — Concurrency model for networked transports: per-tool parallelism vs strict sequential for determinism? (Lean sequential by default, opt-in concurrency.)
- **Q2** — Should `scan` (static heuristics) remain in scope, or be deprecated in favor of pure dynamic fuzzing?
- **Q3** — YAML config implies a parser dependency; is a JSON-only config acceptable to preserve zero-dep core, with YAML as an extra?
- **Q4** — Severity rubric: adopt a CVSS-like score or keep qualitative critical/high/medium?
- **Q5** — Is a hosted/SaaS track (continuous monitoring, dashboards) worth a separate PRD, or explicitly out of scope long-term?

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
