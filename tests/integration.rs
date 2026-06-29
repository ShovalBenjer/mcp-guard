//! End-to-end test against a real MCP server.
//!
//! Ignored by default because it requires `npx` and network access. Run with:
//! `cargo test --test integration -- --ignored`.

use mcp_guard::fuzzer::{FuzzEngine, ResultCategory};
use mcp_guard::transport::StdioTransport;

#[test]
#[ignore = "requires npx + network"]
fn fuzzes_official_memory_server_without_findings() {
    let cmd: Vec<String> = ["npx", "-y", "@modelcontextprotocol/server-memory"]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();

    let mut transport = StdioTransport::spawn(&cmd).expect("server should start");
    let tools = transport.list_tools().expect("should list tools");
    assert!(!tools.is_empty(), "memory server exposes tools");

    let engine = FuzzEngine::new(0);
    let mut crashes = 0;
    let mut findings = 0;
    let mut accepted = 0;
    for tool in &tools {
        for r in engine.fuzz_tool(&mut transport, tool) {
            match r.category {
                ResultCategory::Crash => crashes += 1,
                ResultCategory::Finding => findings += 1,
                ResultCategory::Accepted => accepted += 1,
                _ => {}
            }
        }
    }

    // The honest expectation: a well-hardened server has no crashes and no evidence-backed
    // findings, but does accept some unvalidated input.
    assert_eq!(crashes, 0, "memory server should not crash");
    assert_eq!(
        findings, 0,
        "no payload should yield an evidence-backed finding"
    );
    assert!(
        accepted > 0,
        "no-schema tools accept input without validation"
    );
}
