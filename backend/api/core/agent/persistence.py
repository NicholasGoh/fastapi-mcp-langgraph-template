import psycopg.errors
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from psycopg_pool import AsyncConnectionPool

from api.core.config import settings
from api.core.logs import uvicorn


async def create_checkpoint_pool(conn_str: str) -> AsyncConnectionPool:
    pool = AsyncConnectionPool(
        conninfo=conn_str,
        min_size=settings.checkpoint_pool_min_size,
        max_size=settings.checkpoint_pool_max_size,
        max_idle=settings.checkpoint_pool_max_idle,
        timeout=settings.checkpoint_pool_timeout,
        kwargs=dict(prepare_threshold=None, autocommit=True),
        open=False,
    )
    await pool.open()
    return pool


async def init_checkpointer(pool: AsyncConnectionPool) -> AsyncPostgresSaver:
    """
    Initialize LangGraph AsyncPostgresSaver with a shared connection pool.

    Skips setup if checkpointer tables are already configured.
    """
    # NOTE: LangGraph AsyncPostgresSaver does not support SQLAlchemy ORM Connections.
    # A compatible psycopg connection is created via the connection pool.
    checkpointer = AsyncPostgresSaver(pool)
    try:
        await checkpointer.setup()
    except (
        psycopg.errors.DuplicateColumn,
        psycopg.errors.ActiveSqlTransaction,
    ):
        uvicorn.warning("Skipping checkpointer setup — already configured.")
    return checkpointer
