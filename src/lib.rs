//! mcp-guard — an adversarial fuzzer for [Model Context Protocol](https://modelcontextprotocol.io)
//! servers.
//!
//! mcp-guard spawns an MCP server, enumerates its tools, fires schema-aware adversarial
//! payloads at each parameter, and classifies every response. Its defining principle is
//! **honest classification**: a response that merely does not error is reported as
//! informational ([`ResultCategory::Accepted`]), never as a confirmed vulnerability. A
//! [`ResultCategory::Finding`] requires concrete evidence (a leak signature or a crash).
//!
//! ```no_run
//! use mcp_guard::fuzzer::{FuzzEngine, ResultCategory};
//! use mcp_guard::transport::StdioTransport;
//!
//! let mut transport = StdioTransport::spawn(&[
//!     "npx".into(), "-y".into(), "@modelcontextprotocol/server-memory".into(),
//! ])?;
//! let engine = FuzzEngine::new(0);
//! for tool in transport.list_tools()? {
//!     let results = engine.fuzz_tool(&mut transport, &tool);
//!     let crashes = results.iter().filter(|r| r.category == ResultCategory::Crash).count();
//!     if crashes > 0 {
//!         eprintln!("DOS: {crashes} crash(es)");
//!     }
//! }
//! # Ok::<(), mcp_guard::fuzzer::TransportError>(())
//! ```
//!
//! [`ResultCategory::Accepted`]: fuzzer::ResultCategory::Accepted
//! [`ResultCategory::Finding`]: fuzzer::ResultCategory::Finding
//! [`ResultCategory::Crash`]: fuzzer::ResultCategory::Crash

pub mod cli;
pub mod config;
pub mod fuzzer;
pub mod payloads;
pub mod report;
pub mod scanner;
pub mod transport;

/// The crate version, taken from `Cargo.toml` at build time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
