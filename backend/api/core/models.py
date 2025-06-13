from langchain_core.tools import StructuredTool
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from mcp import ClientSession
from pydantic import BaseModel


class Resource(BaseModel):
    checkpointer: AsyncPostgresSaver
    tools: list[StructuredTool]
    sessions: list[ClientSession]

    class Config:
        arbitrary_types_allowed = True
