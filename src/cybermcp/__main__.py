"""Vajra MCP entry point for configurable MCP transports."""

import argparse
import sys

from cybermcp.config import get_config


def _requires_http_auth(transport: str, host: str, allow_localhost: bool) -> bool:
    if transport == "stdio":
        return False
    if allow_localhost and host in {"127.0.0.1", "localhost"}:
        return False
    return True


def main() -> None:
    cfg = get_config()
    
    import sys as py_sys
    if len(py_sys.argv) > 1 and py_sys.argv[1].lower() == "doctor":
        import asyncio
        from cybermcp.tools.health import diagnostics
        from rich.console import Console
        from rich.table import Table

        console = Console()
        console.print("[bold blue]Vajra MCP Diagnostics Tool (Doctor)[/bold blue]\n")
        console.print("Running health checks for priority security tools...\n")

        results = asyncio.run(diagnostics())

        table = Table(title="Vajra MCP Tool Health Diagnostics")
        table.add_column("Tool", style="cyan")
        table.add_column("Installed", style="bold")
        table.add_column("Version", style="green")
        table.add_column("Path", style="yellow")
        table.add_column("API Keys Configured", style="magenta")

        for r in results:
            inst = "[green]YES[/green]" if r["installed"] else "[red]NO[/red]"
            keys_str = "N/A"
            if r["api_keys"]:
                keys_str = ", ".join(f"{k}: {'[green]OK[/green]' if v else '[red]MISSING[/red]'}" for k, v in r["api_keys"].items())
            
            table.add_row(
                r["tool"],
                inst,
                r["version"],
                r["path"] if r["path"] else "-",
                keys_str
            )

        console.print(table)

        missing = [r for r in results if not r["installed"]]
        if missing:
            console.print("\n[bold yellow]Suggested Installation Fixes for Missing Tools:[/bold yellow]")
            for m in missing:
                console.print(f"• [bold cyan]{m['tool']}[/bold cyan]: {m['install_command']}")
        else:
            console.print("\n[bold green]All priority tools are installed and ready to use![/bold green]")
        
        py_ver = f"{py_sys.version_info.major}.{py_sys.version_info.minor}.{py_sys.version_info.micro}"
        console.print(f"\n[bold blue]System Information:[/bold blue]")
        console.print(f"• Python version: {py_ver}")
        console.print(f"• Database Path: {cfg.db_path}")
        console.print(f"• Sessions Directory: {cfg.sessions_dir}")
        console.print(f"• Reports Directory: {cfg.reports_dir}")
        return

    parser = argparse.ArgumentParser(
        prog="vajra-mcp",
        description="Vajra MCP - MCP execution backend for Claude Code security workflows",
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse", "streamable-http"],
        default=cfg.transport,
        help="MCP transport layer (default: stdio)",
    )
    parser.add_argument(
        "--host",
        default=cfg.host,
        help="Host to bind HTTP/SSE transport (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=cfg.port,
        help="Port for HTTP/SSE transport (default: 8394)",
    )
    args = parser.parse_args()

    if _requires_http_auth(args.transport, args.host, cfg.allow_localhost_no_auth):
        if not cfg.http_api_key:
            print("ERROR: HTTP/SSE transport requires CYBERMCP_HTTP_API_KEY to be set.", file=sys.stderr)
            sys.exit(2)

    from cybermcp.server import create_server

    server = create_server()

    if args.transport == "stdio":
        server.run(transport="stdio")
    else:
        server.run(transport=args.transport, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
