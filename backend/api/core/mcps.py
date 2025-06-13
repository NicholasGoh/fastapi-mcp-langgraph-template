from contextlib import asynccontextmanager
from typing import AsyncGenerator

from mcp import ClientSession
from mcp.client.sse import sse_client

from api.core.config import settings


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
