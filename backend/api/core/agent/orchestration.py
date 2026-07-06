import functools

from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.runnables.base import RunnableSequence
from langchain_core.tools import StructuredTool
from langchain_openai import ChatOpenAI
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from langgraph.graph import MessagesState, StateGraph
from langgraph.graph.state import CompiledStateGraph
from langgraph.prebuilt import ToolNode, tools_condition
from langfuse.callback import CallbackHandler

from api.core.agent.prompts import SYSTEM_PROMPT


class State(MessagesState):
    next: str


def agent_factory(
    llm: ChatOpenAI, tools: list[StructuredTool], system_prompt: str
) -> RunnableSequence:
    prompt = ChatPromptTemplate.from_messages(
        [
            ("system", system_prompt),
            MessagesPlaceholder(variable_name="messages"),
        ]
    )
    if tools:
        agent = prompt | llm.bind_tools(tools)
    else:
        agent = prompt | llm
    return agent


async def agent_node_factory(
    state: State,
    agent: RunnableSequence,
) -> State:
    result = await agent.ainvoke(state)
    return dict(messages=[result])


def graph_factory(
    agent_node: functools.partial,
    tools: list[StructuredTool],
    checkpointer: AsyncPostgresSaver | None = None,
    name: str = "agent_node",
) -> CompiledStateGraph:
    graph_builder = StateGraph(State)
    graph_builder.add_node(name, agent_node)
    graph_builder.add_node("tools", ToolNode(tools))

    graph_builder.add_conditional_edges(name, tools_condition)
    graph_builder.add_edge("tools", name)

    graph_builder.set_entry_point(name)
    graph = graph_builder.compile(checkpointer=checkpointer)
    return graph


def get_graph(
    llm: ChatOpenAI,
    tools: list[StructuredTool] = [],
    system_prompt: str = SYSTEM_PROMPT,
    name: str = "agent_node",
    checkpointer: AsyncPostgresSaver | None = None,
) -> CompiledStateGraph:
    agent = agent_factory(llm, tools, system_prompt)
    worker_node = functools.partial(agent_node_factory, agent=agent)
    return graph_factory(worker_node, tools, checkpointer, name)


def get_config(langfuse_handler: CallbackHandler, thread_id: str):
    return dict(
        configurable=dict(thread_id=thread_id),
        callbacks=[langfuse_handler],
    )
