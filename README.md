[![MseeP.ai Security Assessment Badge](https://mseep.net/pr/nicholasgoh-fastapi-mcp-langgraph-template-badge.png)](https://mseep.ai/app/nicholasgoh-fastapi-mcp-langgraph-template)

# FastAPI MCP LangGraph Template

A modern template for agentic orchestration — built for rapid iteration and scalable deployment using highly customizable, community-supported tools like MCP, LangGraph, and more.

Visit the Github: [![FastAPI MCP LangGraph Template](https://img.shields.io/github/stars/nicholasgoh/fastapi-mcp-langgraph-template?label=FastAPI%20MCP%20LangGraph%20Template)](https://github.com/NicholasGoh/fastapi-mcp-langgraph-template) [![FastAPI MCP LangGraph Template](https://img.shields.io/github/v/tag/nicholasgoh/fastapi-mcp-langgraph-template?style=flat)](https://github.com/NicholasGoh/fastapi-mcp-langgraph-template)

> [!NOTE]
> Read the docs with demo videos [here](https://nicholas-goh.com/docs/intro?ref=fastapi-mcp-langgraph-template). This repo will not contain demo videos.

<!--toc:start-->
- [FastAPI MCP LangGraph Template](#fastapi-mcp-langgraph-template)
  - [Core Features](#core-features)
    - [Technology Stack and Features](#technology-stack-and-features)
    - [Planned Features](#planned-features)
  - [Architecture](#architecture)
    - [Inspector](#inspector)
    - [Template Setup](#template-setup)
    - [Reverse Proxy](#reverse-proxy)
    - [Planned Features Diagrams](#planned-features-diagrams)
      - [Monitoring and Observability](#monitoring-and-observability)
      - [Authentication and Authorization](#authentication-and-authorization)
  - [Quick Start](#quick-start)
  - [Development](#development)
    - [VSCode Devcontainer](#vscode-devcontainer)
    - [Without VSCode Devcontainer](#without-vscode-devcontainer)
  - [Debugging](#debugging)
  - [Refactored Markdown Files](#refactored-markdown-files)
    - [MCP](#mcp)
    - [LangGraph](#langgraph)
    - [Supabase](#supabase)
    - [Langfuse](#langfuse)
    - [Grafana Stack](#grafana-stack)
<!--toc:end-->

## Core Features

[![MCP Client](https://img.shields.io/github/stars/modelcontextprotocol/python-sdk?logo=modelcontextprotocol&label=MCP-Client)](https://github.com/modelcontextprotocol/python-sdk) is an open protocol that standardizes how apps provide context to LLMs.
  - Seamlessly integrates LLM with growing list of community integrations found here [![MCP Server](https://img.shields.io/github/stars/modelcontextprotocol/servers?logo=modelcontextprotocol&label=MCP-Servers)](https://github.com/modelcontextprotocol/servers)
  - No LLM provider lock in

[![LangGraph](https://img.shields.io/github/stars/langchain-ai/langgraph?logo=langgraph&label=LangGraph)](https://github.com/langchain-ai/langgraph) for Customizable Agentic Orchestration
- Native streaming for UX in complex Agentic Workflows
- Native persisted chat history and state management

### Technology Stack and Features

- [![FastAPI](https://img.shields.io/github/stars/fastapi/fastapi?logo=fastapi&label=fastapi)](https://github.com/fastapi/fastapi) for Python backend API
- [![SQLModel](https://img.shields.io/github/stars/fastapi/sqlmodel?logo=sqlmodel&label=SQLModel)](https://github.com/fastapi/sqlmodel) for Python SQL database interactions (ORM + Validation).
  - Wrapper of [![SQLAlchemy](https://img.shields.io/github/stars/sqlalchemy/sqlalchemy?logo=sqlalchemy&label=SQLAlchemy)](https://github.com/sqlalchemy/sqlalchemy)
- [![LangFuse](https://img.shields.io/github/stars/langfuse/langfuse?logo=langfuse&label=LangFuse)](https://github.com/langfuse/langfuse) for LLM Observability and LLM Metrics
- [![Pydantic](https://img.shields.io/github/stars/pydantic/pydantic?logo=pydantic&label=Pydantic)](https://github.com/pydantic/pydantic) for Data Validation and Settings Management.
- [![Supabase](https://img.shields.io/github/stars/supabase/supabase?logo=supabase&label=Supabase)](https://github.com/supabase/supabase) for DB RBAC
  - [![PostgreSQL](https://img.shields.io/github/stars/postgres/postgres?logo=postgresql&label=Postgres)](https://github.com/postgres/postgres) Relational DB
  - [![PGVector](https://img.shields.io/github/stars/pgvector/pgvector?logo=postgresql&label=PGVector)](https://github.com/pgvector/pgvector) Vector Store
- [![Nginx](https://img.shields.io/github/stars/nginx/nginx?logo=nginx&label=Nginx)](https://github.com/nginx/nginx) Reverse Proxy
- [![Compose](https://img.shields.io/github/stars/docker/compose?logo=docker&label=Compose)](https://github.com/docker/compose) for development and production.

### Planned Features

- [![Prometheus](https://img.shields.io/github/stars/prometheus/prometheus?logo=prometheus&label=Prometheus)](https://github.com/prometheus/prometheus) for scraping Metrics
- [![Grafana](https://img.shields.io/github/stars/prometheus/prometheus?logo=grafana&label=Grafana)](https://github.com/grafana/grafana) for visualizing Metrics
- [![Auth0](https://img.shields.io/badge/Auth0-white?logo=auth0)](https://auth0.com/docs) SaaS for Authentication and Authorization with OIDC & JWT via OAuth 2.0
- CI/CD via Github Actions
  - :dollar: Deploy live demo to [![Fargate](https://img.shields.io/badge/Fargate-white.svg?logo=awsfargate)](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/AWS_Fargate.html)
  - Provision with [![Terraform](https://img.shields.io/github/stars/hashicorp/terraform?logo=terraform&label=Terraform)](https://github.com/hashicorp/terraform) IaC
  - Push built images to ECR and Dockerhub

## Architecture

This section outlines the architecture of the services, their interactions, and planned features.

### Inspector

Inspector communicates via SSE protocol with each MCP Server, while each server adheres to MCP specification.

```mermaid
graph LR

  subgraph localhost
    A[Inspector]
    B[DBHub Server]
    C[Youtube Server]
    D[Custom Server]
  end

  subgraph Supabase Cloud
    E[Supabase DB]
  end

  subgraph Google Cloud
    F[Youtube API]
  end

  A<-->|Protocol|B
  A<-->|Protocol|C
  A<-->|Protocol|D
  B<-->E
  C<-->F
```

### Template Setup

The current template does not connect to all MCP servers. Additionally, the API server communicates with the database using a SQL ORM.

```mermaid
graph LR

  subgraph localhost
    A[API Server]
    B[DBHub Server]
    C[Youtube Server]
    D[Custom Server]
  end

  subgraph Supabase Cloud
    E[Supabase DB]
  end

  A<-->|Protocol|D
  A<-->E
```

### Reverse Proxy

Can be extended for other services like Frontend and/or certain backend services self-hosted instead of on cloud (e.g., Langfuse).

```mermaid
graph LR
  A[Web Browser]

  subgraph localhost
    B[Nginx Reverse Proxy]
    C[API Server]
  end

  A-->B
  B-->C
```

### Planned Features Diagrams

#### Monitoring and Observability

```mermaid
graph LR

  subgraph localhost
    A[API Server]
  end

  subgraph Grafana Cloud
    B[Grafana]
  end

  subgraph Langfuse Cloud
    C[Langfuse]
  end

  A -->|Metrics & Logs| B
  A -->|Traces & Events| C
```

#### Authentication and Authorization

![Auth0 Diagram](https://images.ctfassets.net/cdy7uua7fh8z/7mWk9No612EefC8uBidCqr/821eb60b0aa953b0d8e4afe897228844/Auth-code-flow-diagram.png)

[Auth0 Source](https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow)

## Quick Start

Setup to run the repository in both production and development environments.

Build community youtube MCP image with:

```bash
./community/youtube/build.sh
```

:::tip

Instead of cloning or submoduling the repository locally, then building the image, this script builds the Docker image inside a temporary Docker-in-Docker container. This approach avoids polluting your local environment with throwaway files by cleaning up everything once the container exits.

:::

Then build the other images with:

```bash
docker compose -f compose-dev.yaml build
```

Copy environment file:

```bash
cp .env.sample .env
```

Add your following API keys and value to the respective file: `./envs/backend.env`, `./envs/youtube.env` and `.env`.

```bash
OPENAI_API_KEY=sk-proj-...
POSTGRES_DSN=postgresql://postgres...

LANGFUSE_PUBLIC_KEY=pk-lf-...
LANGFUSE_SECRET_KEY=sk-lf-...
LANGFUSE_HOST=https://cloud.langfuse.com

ENVIRONMENT=production

YOUTUBE_API_KEY=...
```

Set environment variables in shell: (compatible with `bash` and `zsh`)

```bash
set -a; for env_file in ./envs/*; do source $env_file; done; set +a
```

Start production containers:

```bash
docker compose up -d
```

<ReactPlayer playing controls url='/vid/fastapi-mcp-langgraph-template/api.mp4' />

## Development

First, set environment variables as per above.

### VSCode Devcontainer

<ReactPlayer playing controls url='/vid/fastapi-mcp-langgraph-template/vscode.mp4' />

<br/>

:::warning

Only replace the following if you plan to start debugger for FastAPI server in VSCode.

:::

Replace `./compose-dev.yaml` entrypoint to allow debugging FastAPI server:

```yaml title="./compose-dev.yaml"
  api:
    image: api:prod
    build:
      dockerfile: ./backend/api/Dockerfile
    # highlight-next-line
    entrypoint: bash -c "sleep infinity"
    env_file:
      - ./envs/backend.env
```

Then:

```bash
code --no-sandbox .
```

Press `F1` and type `Dev Containers: Rebuild and Reopen in Container` to open containerized environment with IntelliSense and Debugger for FastAPI.

### Without VSCode Devcontainer

Run development environment with:

```bash
docker compose -f compose-dev.yaml up -d
```

## Debugging

Sometimes in development, nginx reverse proxy needs to reload its config to route services properly.

```bash
docker compose -f compose-dev.yaml exec nginx sh -c "nginx -s reload"
```

## Refactored Markdown Files

The following markdown files provide additional details on other features:

### MCP

[`./docs/mcp.md`](./docs/mcp.md)

### LangGraph

[`./docs/langgraph.md`](./docs/langgraph.md)

### Supabase

[`./docs/supabase.md`](./docs/supabase.md)

### Langfuse

[`./docs/langfuse.md`](./docs/langfuse.md)

### Grafana Stack

[`./docs/grafana-stack.md`](./docs/grafana-stack.md)

[![Star History Chart](https://api.star-history.com/svg?repos=nicholasgoh/fastapi-mcp-langgraph-template&type=Date)](https://www.star-history.com/#nicholasgoh/fastapi-mcp-langgraph-template&Date)

> [!NOTE]
> Click above to view live update on star history as per their [article](https://www.star-history.com/blog/a-message-to-github-star-history-users):
> Ongoing Broken Live Chart
> you can still use this website to view and download charts (though you may need to provide your own token).
