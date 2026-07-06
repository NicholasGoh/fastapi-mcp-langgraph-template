from typing import Annotated

from fastapi import Depends, Request
from langchain_openai import ChatOpenAI
from langfuse.callback import CallbackHandler
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from api.core.config import settings
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


engine: AsyncEngine = create_async_engine(
    settings.orm_conn_str,
    pool_size=settings.db_pool_size,
    max_overflow=settings.db_max_overflow,
    pool_pre_ping=settings.db_pool_pre_ping,
    pool_recycle=settings.db_pool_recycle,
)


def get_engine() -> AsyncEngine:
    return engine


EngineDep = Annotated[AsyncEngine, Depends(get_engine)]


def get_app_resource(request: Request) -> Resource:
    return request.app.state.resource


ResourceDep = Annotated[Resource, Depends(get_app_resource)]


def get_langfuse_handler() -> CallbackHandler:

    return CallbackHandler(
        public_key=settings.langfuse_public_key,
        secret_key=settings.langfuse_secret_key,
        host=settings.langfuse_host,
        session_id=settings.environment,
        environment=settings.environment,
    )


LangfuseHandlerDep = Annotated[CallbackHandler, Depends(get_langfuse_handler)]
