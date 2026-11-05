"""Vajra MCP entry point for configurable MCP transports."""

import argparse
from pathlib import Path
import sys

from cybermcp.config import get_config


def _requires_http_auth(transport: str, host: str, allow_localhost: bool) -> bool:
    if transport == "stdio":
        return False
    if allow_localhost and host in {"127.0.0.1", "localhost", "::1"}:
        return False
    return True


def main() -> None:
    cfg = get_config()
    
    if len(sys.argv) > 1 and sys.argv[1].lower() == "doctor":
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
        
        py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        console.print("\n[bold blue]System Information:[/bold blue]")
        console.print(f"• Python version: {py_ver}")
        console.print(f"• Database Path: {cfg.db_path}")
        console.print(f"• Sessions Directory: {cfg.sessions_dir}")
        console.print(f"• Reports Directory: {cfg.reports_dir}")
        return

    if len(sys.argv) > 1 and sys.argv[1].lower() == "config":
        subcmd = sys.argv[2].lower() if len(sys.argv) > 2 else "list"
        env_path = Path(".env")
        if subcmd == "set-key":
            if len(sys.argv) < 5:
                print("Usage: vajra-mcp config set-key <KEY_NAME> <VALUE>")
                print("Example: vajra-mcp config set-key shodan_api_key abc123xyz")
                sys.exit(1)
            raw_key = sys.argv[3].strip()
            val = sys.argv[4].strip()
            env_key = raw_key.upper()
            if not env_key.startswith("CYBERMCP_"):
                env_key = f"CYBERMCP_{env_key}"

            lines = []
            if env_path.exists():
                lines = env_path.read_text(encoding="utf-8").splitlines()

            updated = False
            new_lines = []
            for line in lines:
                if line.strip().startswith(f"{env_key}="):
                    new_lines.append(f"{env_key}={val}")
                    updated = True
                else:
                    new_lines.append(line)
            if not updated:
                new_lines.append(f"{env_key}={val}")

            env_path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
            print(f"[+] Successfully saved {env_key} to {env_path.resolve()}")
            return
        elif subcmd in ("get-keys", "list"):
            from rich.console import Console
            from rich.table import Table

            console = Console()
            table = Table(title="Vajra MCP Configured API Keys")
            table.add_column("Key Name", style="cyan")
            table.add_column("Environment Variable", style="yellow")
            table.add_column("Status", style="bold")
            table.add_column("Masked Value", style="green")

            keys_to_check = [
                ("shodan_api_key", "CYBERMCP_SHODAN_API_KEY", cfg.shodan_api_key),
                ("censys_api_id", "CYBERMCP_CENSYS_API_ID", cfg.censys_api_id),
                ("censys_api_secret", "CYBERMCP_CENSYS_API_SECRET", cfg.censys_api_secret),
                ("virustotal_api_key", "CYBERMCP_VIRUSTOTAL_API_KEY", cfg.virustotal_api_key),
                ("hunter_api_key", "CYBERMCP_HUNTER_API_KEY", cfg.hunter_api_key),
                ("wpscan_api_token", "CYBERMCP_WPSCAN_API_TOKEN", getattr(cfg, "wpscan_api_token", "")),
                ("http_api_key", "CYBERMCP_HTTP_API_KEY", cfg.http_api_key),
            ]
            for name, env_var, val in keys_to_check:
                status = "[green]CONFIGURED[/green]" if val else "[red]NOT SET[/red]"
                masked = (val[:3] + "*" * (len(val) - 6) + val[-3:]) if len(val) > 6 else ("*" * len(val) if val else "-")
                table.add_row(name, env_var, status, masked)
            console.print(table)
            console.print("\nTo set an API key: [bold]vajra-mcp config set-key <KEY_NAME> <VALUE>[/bold]")
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
            import secrets
            generated_key = secrets.token_hex(16)
            cfg.http_api_key = generated_key
            print(f"[!] Warning: No CYBERMCP_HTTP_API_KEY was configured for network transport on {args.host}.", file=sys.stderr)
            print(f"[+] Auto-generated one-time session API key: {generated_key}", file=sys.stderr)
            print(f"[+] Pass header 'Authorization: Bearer {generated_key}' in your client requests.\n", file=sys.stderr)

    from cybermcp.server import create_server

    server = create_server()

    if args.transport == "stdio":
        server.run(transport="stdio")
    else:
        server.run(transport=args.transport, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
