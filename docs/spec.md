# mcp-guard Technical Spec

**Version:** 0.2.1
**Status:** Stable
**Last Updated:** 2026-08-24

This document covers API surface details and design rationale not included in the README.

## API Surface

### Transport Layer (`transport.py`)

```python
class StdioTransport:
    def __init__(self, command: list[str], timeout: float = 10.0)
    def start() -> None
    def stop() -> None
    def __enter__() -> StdioTransport
    def __exit__(*args) -> None
    @property
    def is_alive -> bool
    def list_tools() -> list[dict]
    def list_resources() -> list[dict]
    def list_prompts() -> list[dict]
    def call_tool(tool_name: str, arguments: dict) -> dict
```

The transport implements the MCP JSON-RPC 2.0 protocol over stdio. It handles the handshake (`initialize` + `notifications/initialized`) and provides typed accessors for all MCP resource types.

### Fuzz Engine (`fuzzer.py`)

```python
class FuzzEngine:
    def __init__(self, transport: Transport, delay_ms: int = 0)
    def fuzz_tool(tool: dict) -> list[FuzzResult]

class ResultCategory(Enum):
    SAFE = "safe"       # Expected error response
    FINDING = "finding" # Accepted without error
    CRASH = "crash"     # Server died
    ERROR = "error"     # Unexpected exception

@dataclass
class FuzzResult:
    tool_name: str
    probe_name: str
    payload_value: object
    category: ResultCategory
    rule_id: str
    severity: str
    detail: str
    response_preview: str
```

### Payload Generators (`payloads.py`)

```python
def generate_shell_injection() -> list[Payload]   # 8 payloads
def generate_ssrf() -> list[Payload]               # 8 payloads
def generate_overflow() -> list[Payload]           # 5 payloads
def generate_type_confusion(param_type: str) -> list[Payload]  # 6-8 payloads
def generate_prompt_injection() -> list[Payload]   # 6 payloads
def generate_all_for_param(param_name: str, param_schema: dict) -> list[Payload]
```

`generate_all_for_param` dispatches based on schema type:
- URI params: SSRF only (8 payloads)
- String params: shell + prompt + overflow + type_confusion (25 payloads)
- Integer/number params: type_confusion + overflow (9 payloads)
- Other types: type_confusion (6-8 payloads)
- No-schema tools: full suite (24 payloads)

### Scanner (`scanner.py`)

Static schema analysis without server execution. Checks:
- `shell-injection`: Tool name/description matches shell keywords
- `ssrf-risk`: URL parameters (downgrades to WARNING if enum-constrained)
- `missing-schema`: Tools without inputSchema

### Report Formats (`report.py`)

```python
class FuzzReport:
    def to_table(out: TextIO | None = None) -> None
    def to_json(out: TextIO | None = None) -> None
    def to_sarif(out: TextIO | None = None) -> None
```

## PREMORTEM — 5 Failure Modes

1. **Server crashes kill the fuzzer**: A payload crashes the MCP server process, fuzzer loses transport. Mitigation: detect process exit, respawn server between probe groups, track crash-causing payloads.

2. **Rate limiting / server throttling**: Aggressive fuzzing triggers rate limits or intentional slowdowns. Mitigation: configurable delay between payloads (`--delay-ms`), adaptive throttling based on response times.

3. **False positives from expected errors**: A tool correctly rejects bad input with a 400 error — fuzzer flags it as a finding. Mitigation: classify responses: expected errors (safe) vs. unexpected errors (finding) vs. crashes (critical). Only flag the latter two.

4. **Non-deterministic results**: Same payload, different results across runs (server has state). Mitigation: seed-based payload ordering, state reset between probe groups, document non-determinism in report.

5. **MCP protocol version drift**: Protocol spec evolves, handshake changes. Mitigation: implement against current spec, version-pin the protocol constants, fail gracefully on unknown message types.
