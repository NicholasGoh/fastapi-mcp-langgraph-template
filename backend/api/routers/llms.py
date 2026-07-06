from typing import AsyncGenerator
from uuid import uuid4

from fastapi import APIRouter
from langchain_core.messages import HumanMessage
from sse_starlette.sse import EventSourceResponse
from starlette.responses import Response

from api.core.agent.orchestration import get_config, get_graph
from api.core.dependencies import LangfuseHandlerDep, LLMDep, ResourceDep
from api.core.logs import print

router = APIRouter(tags=["chat"])


@router.get("/chat/completions")
async def completions(query: str, llm: LLMDep) -> Response:
    """
    Stream model completions as Server-Sent Events (SSE).

    This endpoint sends the model's responses in real-time as they are generated,
    allowing for a continuous stream of data to the client.
    """
    return EventSourceResponse(stream_completions(query, llm))


@router.get("/chat/agent")
async def agent(
    query: str,
    llm: LLMDep,
    langfuse_handler: LangfuseHandlerDep,
    resource: ResourceDep,
    thread_id: str | None = None,
) -> Response:
    """Stream LangGraph completions as Server-Sent Events (SSE).

    This endpoint streams LangGraph-generated events in real-time, allowing the client
    to receive responses as they are processed, useful for agent-based workflows.
    """
    session_thread_id = thread_id or str(uuid4())
    return EventSourceResponse(
        stream_graph(query, llm, langfuse_handler, resource, session_thread_id)
    )


async def stream_completions(
    query: str, llm: LLMDep
) -> AsyncGenerator[dict[str, str], None]:
    async for chunk in llm.astream_events(query):
        yield dict(data=chunk)


async def stream_graph(
    query: str,
    llm: LLMDep,
    langfuse_handler: LangfuseHandlerDep,
    resource: ResourceDep,
    thread_id: str,
) -> AsyncGenerator[dict[str, str], None]:
    graph = get_graph(
        llm,
        tools=resource.tools,
        checkpointer=resource.checkpointer,
        name="math_agent",
    )
    config = get_config(langfuse_handler, thread_id)
    events = dict(messages=[HumanMessage(content=query)])

    async for event in graph.astream_events(
        events,
        config,
        version="v2",
        stream_mode="updates",
    ):
        yield dict(data=event)
    print(event)
