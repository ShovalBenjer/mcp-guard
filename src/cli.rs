//! Command-line interface: `fuzz` and `scan` subcommands.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};

use crate::config::PayloadConfig;
use crate::fuzzer::{FuzzEngine, Transport};
use crate::net;
use crate::report::FuzzReport;
use crate::scanner;
use crate::transport::StdioTransport;

/// Adversarial fuzzer for MCP servers — break them before they break you.
#[derive(Parser)]
#[command(name = "mcp-guard", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Fuzz an MCP server via stdio transport.
    Fuzz(FuzzArgs),
    /// Static security scan of MCP tool schemas (no payloads sent).
    Scan(ScanArgs),
}

#[derive(Parser)]
struct FuzzArgs {
    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Table)]
    format: Format,
    /// Transport to reach the server (`http` requires the `http` build feature).
    #[arg(long, value_enum, default_value_t = TransportKind::Stdio)]
    transport: TransportKind,
    /// Endpoint URL for the HTTP transport (implies `--transport http`).
    #[arg(long, value_name = "URL")]
    url: Option<String>,
    /// Extra request header for the HTTP transport, `Name: Value` (repeatable).
    #[arg(long = "header", value_name = "NAME: VALUE")]
    headers: Vec<String>,
    /// Confirm you are authorized to fuzz a non-local target (required for remote hosts).
    #[arg(long = "i-have-authorization", default_value_t = false)]
    i_have_authorization: bool,
    /// Delay between payloads, in milliseconds.
    #[arg(long = "delay-ms", default_value_t = 0)]
    delay_ms: u64,
    /// Safe mode: cap destructive/oversized payloads (forced on for remote targets).
    #[arg(long, default_value_t = false)]
    safe: bool,
    /// Send raw destructive/oversized payloads even against remote targets.
    #[arg(long = "unsafe", default_value_t = false)]
    unsafe_mode: bool,
    /// Which result category should cause a non-zero exit (for CI gating).
    #[arg(long = "fail-on", value_enum, default_value_t = FailOn::Crash)]
    fail_on: FailOn,
    /// Load custom payloads/probe toggles from a config file (.json, or .yml with `--features yaml`).
    #[arg(long, value_name = "FILE")]
    payloads: Option<PathBuf>,
    /// The MCP server command (stdio transport), after `--`, e.g. `-- npx -y @modelcontextprotocol/server-memory`.
    #[arg(last = true, value_name = "SERVER_COMMAND")]
    server_command: Vec<String>,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum TransportKind {
    Stdio,
    Http,
}

#[derive(Parser)]
struct ScanArgs {
    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Table)]
    format: Format,
    /// The MCP server command, after `--`.
    #[arg(last = true, num_args = 1.., value_name = "SERVER_COMMAND")]
    server_command: Vec<String>,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum Format {
    Table,
    Json,
    Sarif,
    Markdown,
}

/// Which result category should make the process exit non-zero.
#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum FailOn {
    /// Only crashes fail the run (default).
    Crash,
    /// Crashes or evidence-backed findings fail the run.
    Finding,
    /// Crashes, findings, or any accepted-without-validation result fail the run.
    Accepted,
    /// Never fail (always exit 0).
    None,
}

/// Compute the process exit code: `2` for crashes, `1` for the softer failure categories, `0`
/// otherwise. Kept pure for testing.
fn exit_code_for(crashes: usize, findings: usize, accepted: usize, fail_on: FailOn) -> u8 {
    if fail_on == FailOn::None {
        return 0;
    }
    if crashes > 0 {
        return 2;
    }
    match fail_on {
        FailOn::Finding => u8::from(findings > 0),
        FailOn::Accepted => u8::from(findings > 0 || accepted > 0),
        FailOn::Crash | FailOn::None => 0,
    }
}

/// Parse arguments and run. Returns the process exit code: `0` = clean (per `--fail-on`),
/// `1` = error talking to the server or a soft failure, `2` = crashes found.
#[must_use]
pub fn run() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Some(Command::Fuzz(args)) => run_fuzz(&args),
        Some(Command::Scan(args)) => run_scan(&args),
        None => {
            eprintln!(
                "mcp-guard {}: specify a subcommand (fuzz or scan). Try --help.",
                crate::VERSION
            );
            ExitCode::from(1)
        }
    }
}

fn server_command(raw: &[String]) -> Vec<String> {
    raw.iter().filter(|a| *a != "--").cloned().collect()
}

/// Determine whether the run targets HTTP, and the effective safe-mode setting.
fn use_http(args: &FuzzArgs) -> bool {
    args.url.is_some() || args.transport == TransportKind::Http
}

/// Parse `Name: Value` header strings, ignoring malformed entries.
fn parse_headers(raw: &[String]) -> Vec<(String, String)> {
    raw.iter()
        .filter_map(|h| h.split_once(':'))
        .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        .collect()
}

/// Open the target transport, applying the authorization gate for remote HTTP targets.
/// Returns the transport, a human-readable label, and the effective safe-mode flag.
fn open_target(args: &FuzzArgs) -> Result<(Box<dyn Transport>, String, bool), ExitCode> {
    if use_http(args) {
        let Some(url) = args.url.clone() else {
            eprintln!("[!] --transport http requires --url <URL>");
            return Err(ExitCode::from(1));
        };
        let host = net::host_of(&url).unwrap_or_default();
        let loopback = net::is_loopback_host(&host);
        if !loopback && !args.i_have_authorization {
            eprintln!("[!] Refusing to fuzz non-local target '{host}' without authorization.");
            eprintln!("    Pass --i-have-authorization to confirm you are permitted to test it.");
            return Err(ExitCode::from(1));
        }
        if !loopback {
            eprintln!(
                "[*] Authorized remote fuzz of '{host}'. Only test servers you are permitted to."
            );
        }
        let safe = (args.safe || !loopback) && !args.unsafe_mode;
        let headers = parse_headers(&args.headers);
        eprintln!("[*] Connecting to {url} (HTTP)...");
        let transport = open_http(url, headers)?;
        return Ok((transport, "http endpoint".to_owned(), safe));
    }

    let cmd = server_command(&args.server_command);
    if cmd.is_empty() {
        eprintln!("Error: specify the MCP server command after --");
        eprintln!("Usage: mcp-guard fuzz -- npx -y @modelcontextprotocol/server-memory");
        return Err(ExitCode::from(1));
    }
    eprintln!("[*] Starting MCP server: {}", cmd.join(" "));
    match StdioTransport::spawn(&cmd) {
        Ok(t) => Ok((Box::new(t), cmd.join(" "), args.safe && !args.unsafe_mode)),
        Err(e) => {
            eprintln!("[!] Failed to start server: {e}");
            Err(ExitCode::from(1))
        }
    }
}

#[cfg(feature = "http")]
fn open_http(url: String, headers: Vec<(String, String)>) -> Result<Box<dyn Transport>, ExitCode> {
    use std::time::Duration;
    match crate::transport::HttpTransport::connect(url, headers, Duration::from_secs(30)) {
        Ok(t) => Ok(Box::new(t)),
        Err(e) => {
            eprintln!("[!] Failed to connect: {e}");
            Err(ExitCode::from(1))
        }
    }
}

#[cfg(not(feature = "http"))]
#[allow(clippy::needless_pass_by_value)]
fn open_http(
    _url: String,
    _headers: Vec<(String, String)>,
) -> Result<Box<dyn Transport>, ExitCode> {
    eprintln!("[!] This build has no HTTP transport. Rebuild with: cargo build --features http");
    Err(ExitCode::from(1))
}

fn run_fuzz(args: &FuzzArgs) -> ExitCode {
    let (mut transport, label, safe) = match open_target(args) {
        Ok(t) => t,
        Err(code) => return code,
    };

    let mut engine = FuzzEngine::new(args.delay_ms).with_safe_mode(safe);
    if let Some(path) = &args.payloads {
        match PayloadConfig::load(path) {
            Ok(config) => engine = engine.with_config(config),
            Err(e) => {
                eprintln!("[!] {e}");
                return ExitCode::from(1);
            }
        }
    }

    eprintln!("[*] Connected. Enumerating tools...");
    let tools = match transport.list_tools() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("[!] Could not list tools: {e}");
            return ExitCode::from(1);
        }
    };
    if tools.is_empty() {
        eprintln!("[!] No tools found on this server.");
        return ExitCode::from(0);
    }

    eprintln!("[*] Found {} tools. Generating payloads...", tools.len());
    let outcome = engine.fuzz_server(transport.as_mut(), &tools, |name| {
        eprintln!("[*] Fuzzing: {name}...");
    });
    if outcome.aborted {
        eprintln!(
            "[!] Server crashed and could not be restarted — stopped after {} of {} tools.",
            outcome.tools_fuzzed,
            tools.len()
        );
    }

    let report = FuzzReport {
        server_command: label,
        tools_fuzzed: outcome.tools_fuzzed,
        total_payloads: outcome.results.len(),
        results: outcome.results,
    };

    let mut stdout = std::io::stdout().lock();
    let rendered = match args.format {
        Format::Table => report.to_table(&mut stdout),
        Format::Json => report.to_json(&mut stdout),
        Format::Sarif => report.to_sarif(&mut stdout),
        Format::Markdown => report.to_markdown(&mut stdout),
    };
    if let Err(e) = rendered {
        eprintln!("[!] Failed to write report: {e}");
        return ExitCode::from(1);
    }

    ExitCode::from(exit_code_for(
        report.crashes(),
        report.findings(),
        report.accepted(),
        args.fail_on,
    ))
}

fn run_scan(args: &ScanArgs) -> ExitCode {
    let cmd = server_command(&args.server_command);
    if cmd.is_empty() {
        eprintln!("Error: specify the MCP server command after --");
        return ExitCode::from(1);
    }

    let mut transport = match StdioTransport::spawn(&cmd) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("[!] Failed to start server: {e}");
            return ExitCode::from(1);
        }
    };
    let tools = match transport.list_tools() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("[!] Could not list tools: {e}");
            return ExitCode::from(1);
        }
    };

    if matches!(args.format, Format::Json) {
        let findings: Vec<_> = tools
            .iter()
            .flat_map(scanner::scan_tool)
            .map(|r| {
                serde_json::json!({
                    "rule_id": r.rule_id, "severity": r.severity.label(),
                    "tool": r.tool_name, "message": r.message, "remediation": r.remediation,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!(findings)).unwrap_or_default()
        );
        return ExitCode::from(0);
    }

    println!("\nStatic scan of {} tools:\n", tools.len());
    for tool in &tools {
        let name = tool
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let findings = scanner::scan_tool(tool);
        if findings.is_empty() {
            println!("  [PASS] {name}");
        } else {
            for f in findings {
                println!("  [{}] {name}: {}", f.severity.label(), f.message);
            }
        }
    }
    println!();
    ExitCode::from(0)
}

#[cfg(test)]
mod tests {
    use super::{FailOn, exit_code_for};

    #[test]
    fn crash_dominates_and_yields_two() {
        for policy in [FailOn::Crash, FailOn::Finding, FailOn::Accepted] {
            assert_eq!(exit_code_for(1, 0, 5, policy), 2);
        }
    }

    #[test]
    fn fail_on_crash_ignores_softer_categories() {
        assert_eq!(exit_code_for(0, 3, 9, FailOn::Crash), 0);
    }

    #[test]
    fn fail_on_finding_flags_findings_only() {
        assert_eq!(exit_code_for(0, 1, 0, FailOn::Finding), 1);
        assert_eq!(exit_code_for(0, 0, 9, FailOn::Finding), 0);
    }

    #[test]
    fn fail_on_accepted_flags_findings_or_accepted() {
        assert_eq!(exit_code_for(0, 0, 1, FailOn::Accepted), 1);
        assert_eq!(exit_code_for(0, 0, 0, FailOn::Accepted), 0);
    }

    #[test]
    fn fail_on_none_never_fails() {
        assert_eq!(exit_code_for(9, 9, 9, FailOn::None), 0);
    }
}
