import os

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from mcp import ClientSession
from mcp.client.sse import sse_client

from api.core.config import settings

# httpx respects system HTTP proxy on macOS; bypass local MCP hosts.
for _proxy_key in ("NO_PROXY", "no_proxy"):
    _current = os.environ.get(_proxy_key, "")
    for _host in ("127.0.0.1", "localhost"):
        if _host not in _current.split(","):
            _current = f"{_current},{_host}".strip(",")
    if _current:
        os.environ[_proxy_key] = _current


@asynccontextmanager
async def mcp_sse_client(
    mcp_host: str = "mcp",
) -> AsyncGenerator[ClientSession]:
    """
    Creates and initializes an MCP client session over SSE.

    Establishes an SSE connection to the MCP server and yields an initialized
    `ClientSession` for communication.

    Yields:
        ClientSession: An initialized MCP client session.
    """
    async with sse_client(
        f"http://{mcp_host}:{settings.mcp_server_port}/sse"
    ) as (
        read_stream,
        write_stream,
    ):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            yield session
