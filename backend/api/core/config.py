from pathlib import Path

from pydantic import PostgresDsn, computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict

_PROJECT_ROOT = Path(__file__).resolve().parents[3]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(
            str(_PROJECT_ROOT / ".env"),
            "/opt/.env",
        ),
        env_ignore_empty=True,
        extra="ignore",
    )

    model: str = "gpt-4o-mini-2024-07-18"
    openai_api_key: str = ""
    mcp_server_port: int = 8050

    postgres_dsn: PostgresDsn = (
        "postgresql://postgres:password@example.supabase.com:6543/postgres"
    )

    db_pool_size: int = 5
    db_max_overflow: int = 10
    db_pool_pre_ping: bool = True
    db_pool_recycle: int = 3600

    checkpoint_pool_min_size: int = 2
    checkpoint_pool_max_size: int = 10
    checkpoint_pool_max_idle: float = 300.0
    checkpoint_pool_timeout: float = 30.0

    @computed_field
    @property
    def orm_conn_str(self) -> str:
        # NOTE: Explicitly follow LangGraph AsyncPostgresSaver
        # and use psycopg driver for ORM
        return self.postgres_dsn.encoded_string().replace(
            "postgresql://", "postgresql+psycopg://"
        )

    @computed_field
    @property
    def checkpoint_conn_str(self) -> str:
        # NOTE: LangGraph AsyncPostgresSaver has some issues
        # with specifying psycopg driver explicitly
        return self.postgres_dsn.encoded_string()

    langfuse_public_key: str = ""
    langfuse_secret_key: str = ""
    langfuse_host: str = "https://cloud.langfuse.com"

    environment: str = "development"
    mcp_hostnames_csv: str = "mcp"

    @computed_field
    @property
    def mcp_hostnames(self) -> list[str]:
        return [
            h.strip() for h in self.mcp_hostnames_csv.split(",") if h.strip()
        ]


settings = Settings()
