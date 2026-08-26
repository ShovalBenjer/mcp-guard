# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1] - 2026-08-24

### Added
- Static schema scanner with OWASP-based rules (shell injection, SSRF, missing schema detection)
- SARIF output format for GitHub Security tab integration
- JSON output format for CI pipeline integration
- `scan` subcommand for static analysis without server spawn
- `list_resources` and `list_prompts` transport methods

### Changed
- Schema-aware payload generation: targeted payloads per parameter type
- Response classification: SAFE / FINDING / CRASH / ERROR categories

## [0.2.0] - 2026-06-03

### Added
- Initial public release
- Stdio transport for MCP server communication
- 5 probe types: shell injection, SSRF, overflow, type confusion, prompt injection
- Schema-aware payload generation
- Table and JSON output formats
- CLI with `fuzz` subcommand
- Leaderboard with results against official Anthropic MCP servers

## [0.1.0] - 2026-06-03

### Added
- Initial release of mcp-guard
- Stdio transport with JSON-RPC 2.0 handshake
- Schema-aware adversarial payload generation (5 probe types)
- Dynamic fuzzing engine with SAFE / FINDING / CRASH classification
- Static schema scanner with shell injection, SSRF, and missing-schema rules
- CLI with `fuzz` and `scan` subcommands
- Output formats: table, JSON, SARIF
- Zero runtime dependencies (Python 3.11+ stdlib only)

[0.2.1]: https://github.com/ShovalBenjer/mcp-guard/releases/tag/v0.2.1
[0.2.0]: https://github.com/ShovalBenjer/mcp-guard/releases/tag/v0.2.0
[0.1.0]: https://github.com/ShovalBenjer/mcp-guard/releases/tag/v0.1.0
