from contextlib import AsyncExitStack, asynccontextmanager
from typing import AsyncGenerator

from langchain_mcp_adapters.tools import load_mcp_tools

from api.core.agent.persistence import create_checkpoint_pool, init_checkpointer
from api.core.config import settings
from api.core.mcps import mcp_sse_client
from api.core.models import Resource


@asynccontextmanager
async def app_resources_context() -> AsyncGenerator[Resource]:
    pool = await create_checkpoint_pool(settings.checkpoint_conn_str)
    try:
        checkpointer = await init_checkpointer(pool)
        tools = []
        sessions = []
        async with AsyncExitStack() as stack:
            for hostname in settings.mcp_hostnames:
                session = await stack.enter_async_context(
                    mcp_sse_client(hostname)
                )
                tools += await load_mcp_tools(session)
                sessions.append(session)
            yield Resource(
                checkpointer=checkpointer,
                tools=tools,
                sessions=sessions,
            )
    finally:
        await pool.close()
