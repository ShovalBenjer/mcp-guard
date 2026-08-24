"""CLI entry point for mcp-guard adversarial fuzzer."""
from __future__ import annotations

import argparse
import logging
import sys

from .fuzzer import FuzzEngine
from .report import FuzzReport
from .scanner import Scanner
from .transport import StdioTransport

logger = logging.getLogger(__name__)


def _setup_logging(verbose: bool, quiet: bool) -> None:
    """Configure structured logging based on verbosity flags.

    Args:
        verbose: Enable verbose (DEBUG) logging.
        quiet: Suppress all non-error output.
    """
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
    parser.add_argument("--output-file", help="Write output to a file instead of stdout")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logger")
    parser.add_argument("--quiet", action="store_true", help="Suppress all non-error output")
    sub = parser.add_subparsers(dest="command")

    fuzz_parser = sub.add_parser("fuzz", help="Fuzz an MCP server via stdio transport")
    fuzz_parser.add_argument("--format", choices=["table", "json", "sarif"], default="table")
    fuzz_parser.add_argument("--delay-ms", type=int, default=0, help="Delay between payloads (ms)")
    fuzz_parser.add_argument("--timeout", type=float, default=30.0, help="Per-tool-call timeout (seconds)")
    fuzz_parser.add_argument("server_command", nargs=argparse.REMAINDER)

    scan_parser = sub.add_parser("scan", help="Static security scan of MCP tool schemas")
    scan_parser.add_argument("--format", choices=["table", "json"], default="table")
    scan_parser.add_argument("--timeout", type=float, default=30.0, help="Per-tool-call timeout (seconds)")
    scan_parser.add_argument("server_command", nargs=argparse.REMAINDER)

    args = parser.parse_args(argv)
    _setup_logging(args.verbose, args.quiet)

    if args.command == "fuzz":
        _run_fuzz(args)
    elif args.command == "scan":
        _run_scan(args)
    else:
        parser.print_help()


def _open_output(path: str | None):
    """Open an output file or return sys.stdout.

    Args:
        path: Optional file path for output.

    Returns:
        A writable file-like object.
    """
    if path:
        return open(path, "w", encoding="utf-8")
    return sys.stdout


def _run_fuzz(args: argparse.Namespace) -> None:
    out = _open_output(args.output_file)
    cmd = [a for a in args.server_command if a != "--"]
    if not cmd:
        logger.error("No MCP server command specified after --")
        logger.info("Usage: mcp-guard fuzz -- npx @modelcontextprotocol/server-memory")
        sys.exit(1)

    logger.info("Starting MCP server: %s", " ".join(cmd))
    try:
        with StdioTransport(cmd, timeout=args.timeout) as transport:
            logger.info("Connected. Enumerating tools...")
            tools = transport.list_tools()
            if not tools:
                logger.warning("No tools found on this server.")
                return

            logger.info("Found %d tools. Generating payloads...", len(tools))
            all_results: list = []
            engine = FuzzEngine(transport=transport, delay_ms=args.delay_ms)
            total_tools = len(tools)
            for idx, tool in enumerate(tools, 1):
                name = tool.get("name", "unknown")
                if total_tools > 5:
                    logger.info("Fuzzing tool %d/%d: %s", idx, total_tools, name)
                else:
                    logger.info("Fuzzing: %s", name)
                results = engine.fuzz_tool(tool)
                all_results.extend(results)

            report = FuzzReport(
                server_command=" ".join(cmd),
                tools_fuzzed=len(tools),
                total_payloads=len(all_results),
                results=all_results,
            )

            if args.format == "json":
                report.to_json(out=out)
            elif args.format == "sarif":
                report.to_sarif(out=out)
            else:
                report.to_table(out=out)

            if out is not sys.stdout:
                out.close()

            crashes = len(report.crashes)
            if crashes:
                logger.warning("VERDICT: VULNERABLE — %d crashes detected", crashes)
                sys.exit(2)
            elif report.findings:
                logger.warning("VERDICT: %d findings require investigation", len(report.findings))
            else:
                logger.info("VERDICT: CLEAN — all payloads handled safely")
    except ConnectionError as e:
        logger.error("Connection error: %s", e)
        sys.exit(1)
    except OSError as e:
        logger.error("OS error: %s", e)
        sys.exit(1)
    except Exception as e:  # noqa: BLE001
        logger.error("Unexpected error: %s", e)
        sys.exit(1)


def _run_scan(args: argparse.Namespace) -> None:
    out = _open_output(args.output_file)
    cmd = [a for a in args.server_command if a != "--"]
    if not cmd:
        logger.error("No MCP server command specified after --")
        logger.info("Usage: mcp-guard scan -- npx @modelcontextprotocol/server-memory")
        sys.exit(1)

    try:
        with StdioTransport(cmd, timeout=args.timeout) as transport:
            tools = transport.list_tools()
            if not tools:
                logger.warning("No tools found.")
                return

            logger.info("Static scan of %d tools:\n", len(tools))
            if out is sys.stdout:
                print(f"\nStatic scan of {len(tools)} tools:\n")
            for tool in tools:
                name = tool.get("name", "unknown")
                results = Scanner().scan_tool(tool)
                if results:
                    for r in results:
                        msg = f"  [{r.severity.value.upper()}] {name}: {r.message}"
                        if out is sys.stdout:
                            print(msg)
                        else:
                            out.write(msg + "\n")
                else:
                    msg = f"  [PASS] {name}"
                    if out is sys.stdout:
                        print(msg)
                    else:
                        out.write(msg + "\n")
            if out is sys.stdout:
                print()
        if out is not sys.stdout:
            out.close()
    except ConnectionError as e:
        logger.error("Connection error: %s", e)
        sys.exit(1)
    except OSError as e:
        logger.error("OS error: %s", e)
        sys.exit(1)
    except Exception as e:  # noqa: BLE001
        logger.error("Unexpected error: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
