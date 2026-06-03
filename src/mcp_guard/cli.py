"""CLI entry point for mcp-guard adversarial fuzzer."""
from __future__ import annotations

import argparse
import sys

from .fuzzer import FuzzEngine, ResultCategory
from .report import FuzzReport
from .scanner import Scanner
from .transport import StdioTransport


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="mcp-guard",
        description="Adversarial fuzzer for MCP servers — break before they break you.",
    )
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

    if args.command == "fuzz":
        _run_fuzz(args)
    elif args.command == "scan":
        _run_scan(args)
    else:
        parser.print_help()


def _run_fuzz(args: argparse.Namespace) -> None:
    cmd = [a for a in args.server_command if a != "--"]
    if not cmd:
        print("Error: specify MCP server command after --", file=sys.stderr)
        print("Usage: mcp-guard fuzz -- npx @modelcontextprotocol/server-memory", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Starting MCP server: {' '.join(cmd)}")
    try:
        with StdioTransport(cmd, timeout=args.timeout) as transport:
            print("[*] Connected. Enumerating tools...")
            tools = transport.list_tools()
            if not tools:
                print("[!] No tools found on this server.")
                return

            print(f"[*] Found {len(tools)} tools. Generating payloads...")
            all_results = []
            engine = FuzzEngine(transport=transport, delay_ms=args.delay_ms)
            for tool in tools:
                name = tool.get("name", "unknown")
                print(f"[*] Fuzzing: {name}...")
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
                sys.exit(2)
    except ConnectionError as e:
        print(f"[!] Connection error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        sys.exit(1)


def _run_scan(args: argparse.Namespace) -> None:
    cmd = [a for a in args.server_command if a != "--"]
    if not cmd:
        print("Error: specify MCP server command after --", file=sys.stderr)
        sys.exit(1)

    try:
        with StdioTransport(cmd) as transport:
            tools = transport.list_tools()
            if not tools:
                print("[!] No tools found.")
                return

            scanner = Scanner()
            print(f"\nStatic scan of {len(tools)} tools:\n")
            for tool in tools:
                name = tool.get("name", "unknown")
                results = scanner.scan_tool(tool)
                if results:
                    for r in results:
                        print(f"  [{r.severity.value.upper()}] {name}: {r.message}")
                else:
                    print(f"  [PASS] {name}")
            print()
    except Exception as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
