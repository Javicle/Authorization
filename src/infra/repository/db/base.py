from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase
from tools_openverse import setup_logger
from tools_openverse.common.config import settings

logger = setup_logger(__name__)

if settings.database_url:
    logger.info("Creating database engine with URL: %s", settings.database_url)
    engine = create_async_engine(settings.database_url)
    SessionLocal = async_sessionmaker(bind=engine, expire_on_commit=False)
    logger.info("Database engine and session factory created successfully")
else:
    logger.error("Database URL not provided in settings")
    raise ValueError("Database URL is required")


class Base(DeclarativeBase):
    __abstract__ = True


async def init_db() -> None:
    logger.info("Initializing database tables")
    try:
        async with engine.begin() as conn:
            # Атрибут для чистки базы данных
            # await conn.run_sync(Base.metadata.drop_all)
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Database tables initialized successfully")
    except Exception as e:
        logger.error("Failed to initialize database: %s", str(e), exc_info=True)
        raise


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    logger.debug("Creating database session")
    async with SessionLocal() as session:
        try:
            yield session
            logger.debug("Database session created successfully")
        except Exception as e:
            logger.error("Database session error: %s", str(e), exc_info=True)
            raise
        finally:
            logger.debug("Database session closed")
