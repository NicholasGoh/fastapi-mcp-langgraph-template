from contextlib import AsyncExitStack, asynccontextmanager
from typing import Annotated, AsyncGenerator

from fastapi import Depends
from langchain_mcp_adapters.tools import load_mcp_tools
from langchain_openai import ChatOpenAI
from langfuse.callback import CallbackHandler
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

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
    async with checkpointer_context(
        settings.checkpoint_conn_str
    ) as checkpointer:
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


def get_langfuse_handler() -> CallbackHandler:

    return CallbackHandler(
        public_key=settings.langfuse_public_key,
        secret_key=settings.langfuse_secret_key,
        host=settings.langfuse_host,
        session_id=settings.environment,
        environment=settings.environment,
    )


LangfuseHandlerDep = Annotated[CallbackHandler, Depends(get_langfuse_handler)]
