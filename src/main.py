import asyncio
from contextlib import asynccontextmanager
from typing import AsyncIterator

import uvicorn
from fastapi import APIRouter, FastAPI
from tools_openverse import setup_logger
from tools_openverse.common.config import get_redis, settings

from openverse_applaunch import ApplicationManager, JaegerService

from src.delivery.route.jwt import JwtTokenRoute
from src.infra.repository.db.base import init_db

logger = setup_logger()


@asynccontextmanager
async def lifespan(fast_app: FastAPI) -> AsyncIterator[None]:
    logger.info("Starting application lifespan for %s", settings.PROJECT_NAME)

    logger.info("Initializing database connection")
    db_task = asyncio.create_task(init_db())
    # redis_client = get_redis()
    asyncio.gather(db_task)
    logger.info("Database, redis initialized successfully")

    router = APIRouter(tags=["Authorization"])
    JwtTokenRoute(router)
    fast_app.include_router(router)
    logger.info("JWT token routes registered successfully")

    # logger.info("Connecting to Redis")
    # logger.info("Redis connection established")

    logger.info("Application startup completed successfully")
    yield


app = ApplicationManager.create(
    service_name=settings.PROJECT_NAME,
    lifespan=lifespan
)


async def _run_application() -> None:
    jaeger_service = JaegerService()
    await jaeger_service.init(service_name=settings.PROJECT_NAME)
    app.add_service(jaeger_service)
    await app.initialize_application(config=settings.to_dict(), with_tracers=True,
                                     with_metrics=False, health_check=True)


if __name__ == "__main__":
    asyncio.run(_run_application())
    uvicorn.run(app=app.get_app,
                host=settings.BASE_URL,
                port=int(settings.PORT_SERVICE_AUTH
                         if settings.PORT_SERVICE_AUTH else 8080))

