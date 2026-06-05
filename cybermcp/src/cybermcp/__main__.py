"""CyberMCP entry point — launch the MCP server with configurable transport."""

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
    parser = argparse.ArgumentParser(
        prog="cybermcp",
        description="CyberMCP — AI Cybersecurity Platform MCP Server",
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
