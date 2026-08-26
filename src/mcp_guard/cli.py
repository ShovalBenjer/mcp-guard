"""CLI entry point for mcp-guard adversarial fuzzer."""
from __future__ import annotations

import argparse
import logging
import sys

from .fuzzer import FuzzEngine
from .report import FuzzReport
from .scanner import Scanner
from .transport import StdioTransport


def _setup_logging(verbose: bool, quiet: bool) -> None:
    if quiet:
        level = logging.ERROR
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO

    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stderr,
    )


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="mcp-guard",
        description="Adversarial fuzzer for MCP servers — break before they break you.",
    )
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--quiet", action="store_true", help="Suppress all non-error output")
    sub = parser.add_subparsers(dest="command")

    # fuzz subcommand
    fuzz_parser = sub.add_parser("fuzz", help="Fuzz an MCP server via stdio transport")
    fuzz_parser.add_argument("--format", choices=["table", "json", "sarif"], default="table")
    fuzz_parser.add_argument("--delay-ms", type=int, default=0, help="Delay between payloads (ms)")
    fuzz_parser.add_argument("--timeout", type=float, default=10.0, help="Per-tool-call timeout (seconds)")
    fuzz_parser.add_argument("server_command", nargs=argparse.REMAINDER)

    # scan subcommand (static analysis)
    scan_parser = sub.add_parser("scan", help="Static security scan of MCP tool schemas")
    scan_parser.add_argument("--format", choices=["table", "json"], default="table")
    scan_parser.add_argument("server_command", nargs=argparse.REMAINDER)

    args = parser.parse_args(argv)
    _setup_logging(args.verbose, args.quiet)

    if args.command == "fuzz":
        _run_fuzz(args)
    elif args.command == "scan":
        _run_scan(args)
    else:
        parser.print_help()


def _run_fuzz(args: argparse.Namespace) -> None:
    cmd = [a for a in args.server_command if a != "--"]
    if not cmd:
        logging.error("Error: specify MCP server command after --")
        logging.info("Usage: mcp-guard fuzz -- npx @modelcontextprotocol/server-memory")
        sys.exit(1)

    logging.info("Starting MCP server: %s", " ".join(cmd))
    try:
        with StdioTransport(cmd, timeout=args.timeout) as transport:
            logging.info("Connected. Enumerating tools...")
            tools = transport.list_tools()
            if not tools:
                logging.warning("No tools found on this server.")
                return

            logging.info("Found %d tools. Generating payloads...", len(tools))
            all_results = []
            engine = FuzzEngine(transport=transport, delay_ms=args.delay_ms)
            for tool in tools:
                name = tool.get("name", "unknown")
                logging.info("Fuzzing: %s...", name)
                results = engine.fuzz_tool(tool)
                all_results.extend(results)

            report = FuzzReport(
                server_command=" ".join(cmd),
                tools_fuzzed=len(tools),
                total_payloads=len(all_results),
                results=all_results,
            )

            if args.format == "json":
                report.to_json()
            elif args.format == "sarif":
                report.to_sarif()
            else:
                report.to_table()

            crashes = len(report.crashes)
            if crashes:
                logging.warning("VERDICT: VULNERABLE — %d crashes detected", crashes)
                sys.exit(2)
            elif report.findings:
                logging.warning("VERDICT: %d findings require investigation", len(report.findings))
            else:
                logging.info("VERDICT: CLEAN — all payloads handled safely")
    except ConnectionError as e:
        logging.error("Connection error: %s", e)
        sys.exit(1)
    except Exception as e:  # noqa: BLE001
        logging.error("Error: %s", e)
        sys.exit(1)


def _run_scan(args: argparse.Namespace) -> None:
    cmd = [a for a in args.server_command if a != "--"]
    if not cmd:
        logging.error("Error: specify MCP server command after --")
        sys.exit(1)

    try:
        with StdioTransport(cmd) as transport:
            tools = transport.list_tools()
            if not tools:
                logging.warning("No tools found.")
                return

            scanner = Scanner()
            logging.info("Static scan of %d tools:", len(tools))
            for tool in tools:
                name = tool.get("name", "unknown")
                results = scanner.scan_tool(tool)
                if results:
                    for r in results:
                        logging.info("  [%s] %s: %s", r.severity.value.upper(), name, r.message)
                else:
                    logging.info("  [PASS] %s", name)
    except Exception as e:  # noqa: BLE001
        logging.error("Error: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
