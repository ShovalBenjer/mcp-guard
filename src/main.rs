//! Binary entry point for the `mcp-guard` CLI.

use std::process::ExitCode;

fn main() -> ExitCode {
    mcp_guard::cli::run()
}
