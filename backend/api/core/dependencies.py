from contextlib import asynccontextmanager
from typing import Annotated, AsyncGenerator

from fastapi import Depends
from langchain_mcp_adapters.tools import load_mcp_tools
from langchain_openai import ChatOpenAI
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
import asyncio

from api.core.agent.persistence import checkpointer_context
from api.core.config import settings
from api.core.mcps import mcp_sse_client
from api.core.models import Resource


def get_llm() -> ChatOpenAI:
    return ChatOpenAI(
        streaming=True,
        model=settings.model,
        temperature=0,
        api_key=settings.openai_api_key,
        stream_usage=True,
    )


LLMDep = Annotated[ChatOpenAI, Depends(get_llm)]


engine: AsyncEngine = create_async_engine(settings.orm_conn_str)


def get_engine() -> AsyncEngine:
    return engine


EngineDep = Annotated[AsyncEngine, Depends(get_engine)]


@asynccontextmanager
async def setup_graph() -> AsyncGenerator[Resource]:
    # Define MCP server URLs based on compose file service names and ports
    # Assuming the port for the 'mcp' service is in settings
    mcp_base_url = f"http://mcp:{settings.mcp_server_port}/sse"
    gmail_mcp_url = "http://gmail-mcp:3000/mcp"

    async with checkpointer_context(
        settings.checkpoint_conn_str
    ) as checkpointer:
        # Connect to both MCP servers simultaneously
        async with mcp_sse_client(mcp_base_url) as session_base, \
                   mcp_sse_client(gmail_mcp_url) as session_gmail:
            # Load tools from both sessions concurrently
            tools_base_task = asyncio.create_task(load_mcp_tools(session_base))
            tools_gmail_task = asyncio.create_task(load_mcp_tools(session_gmail))

            tools_base = await tools_base_task
            tools_gmail = await tools_gmail_task

            # Combine the tool lists
            all_tools = tools_base + tools_gmail

            # Yield the resource with combined tools
            # Note: Removed 'session=session' as its meaning is ambiguous with multiple sessions.
            # Adjust if the session object itself is needed downstream.
            yield Resource(
                checkpointer=checkpointer,
                tools=all_tools,
            )
