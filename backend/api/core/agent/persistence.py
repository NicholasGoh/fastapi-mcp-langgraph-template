from contextlib import asynccontextmanager
from typing import AsyncGenerator

import psycopg
import psycopg.errors
import uvicorn
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from psycopg_pool import AsyncConnectionPool

from api.core.logs import uvicorn


@asynccontextmanager
async def checkpointer_context(
    conn_str: str,
) -> AsyncGenerator[AsyncPostgresSaver]:
    """
    Async context manager that sets up and yields a LangGraph checkpointer.

    Uses a psycopg async connection pool to initialize AsyncPostgresSaver.
    Skips setup if checkpointer is already configured.

    Args:
        conn_str (str): PostgreSQL connection string.

    Yields:
        AsyncPostgresSaver: The initialized checkpointer.
    """
    # NOTE: LangGraph AsyncPostgresSaver does not support SQLAlchemy ORM Connections.
    # A compatible psycopg connection is created via the connection pool to connect to the checkpointer.
    async with AsyncConnectionPool(
        conninfo=conn_str,
        kwargs=dict(prepare_threshold=None, autocommit=True),
    ) as pool:
        checkpointer = AsyncPostgresSaver(pool)
        try:
            await checkpointer.setup()
        except (
            psycopg.errors.DuplicateColumn,
            psycopg.errors.ActiveSqlTransaction,
        ):
            uvicorn.warning("Skipping checkpointer setup — already configured.")
        yield checkpointer
