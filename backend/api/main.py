from contextlib import asynccontextmanager

from fastapi import FastAPI

from api.core.resources import app_resources_context
from api.routers import checkpoints, llms, mcps


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with app_resources_context() as resource:
        app.state.resource = resource
        yield


app = FastAPI(
    lifespan=lifespan,
    swagger_ui_parameters={"tryItOutEnabled": True},
)
app.include_router(llms.router, prefix="/v1")
app.include_router(mcps.router, prefix="/v1")
app.include_router(checkpoints.router, prefix="/v1")
