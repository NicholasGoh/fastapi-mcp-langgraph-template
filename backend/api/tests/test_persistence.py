from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from api.core.agent.persistence import init_checkpointer
from api.core.config import Settings


def test_settings_pool_defaults():
    settings = Settings(
        _env_file=None,
        openai_api_key="test",
        postgres_dsn="postgresql://postgres:password@localhost:5432/postgres",
    )
    assert settings.db_pool_size == 5
    assert settings.checkpoint_pool_min_size == 2
    assert settings.checkpoint_pool_max_size == 10


def test_checkpoint_conn_str_uses_psycopg_driver_for_orm():
    settings = Settings(
        _env_file=None,
        postgres_dsn="postgresql://postgres:password@localhost:5432/postgres",
    )
    assert settings.orm_conn_str.startswith("postgresql+psycopg://")
    assert settings.checkpoint_conn_str.startswith("postgresql://")


@pytest.mark.asyncio
async def test_init_checkpointer_skips_duplicate_setup():
    pool = MagicMock()
    checkpointer = AsyncMock()
    checkpointer.setup = AsyncMock(
        side_effect=__import__("psycopg.errors").errors.DuplicateColumn("dup")
    )

    with patch(
        "api.core.agent.persistence.AsyncPostgresSaver",
        return_value=checkpointer,
    ):
        result = await init_checkpointer(pool)

    assert result is checkpointer
    checkpointer.setup.assert_awaited_once()


def test_get_config_uses_thread_id():
    from api.core.agent.orchestration import get_config

    handler = MagicMock()
    config = get_config(handler, "session-abc")

    assert config["configurable"]["thread_id"] == "session-abc"
    assert config["callbacks"] == [handler]
