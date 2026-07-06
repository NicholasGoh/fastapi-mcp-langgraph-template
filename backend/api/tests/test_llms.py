from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver

from api.core.models import Resource
from api.main import app


@pytest.fixture
def mock_resource():
    return Resource(
        checkpointer=MagicMock(spec=AsyncPostgresSaver),
        tools=[],
        sessions=[],
    )


@pytest.mark.asyncio
async def test_health_docs(mock_resource):
    app.state.resource = mock_resource

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.get("/docs")

    assert response.status_code == 200


@pytest.mark.asyncio
async def test_agent_accepts_thread_id(mock_resource):
    app.state.resource = mock_resource

    async def fake_stream(*args, **kwargs):
        yield dict(data={"event": "done"})

    with patch("api.routers.llms.stream_graph", side_effect=fake_stream):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            response = await client.get(
                "/v1/chat/agent",
                params={"query": "hello", "thread_id": "user-123"},
            )

    assert response.status_code == 200
