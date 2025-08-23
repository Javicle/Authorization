import datetime
from typing import Annotated, Optional

from fastapi import Depends
from sqlalchemy import delete, insert, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from tools_openverse import setup_logger

from src.entity.jwt.dto import (
    CreateRefreshTokenDTO,
    RefreshTokenResponseDTO,
    RefreshTokenUpdateDTO,
)
from src.entity.jwt.ent import RefreshToken
from src.infra.repository.db.base import get_db
from src.infra.repository.db.models.refresh_token import RefreshTokenDBModel

logger = setup_logger(__name__)


class JwtRepository:
    def __init__(self, db_session: AsyncSession):
        logger.debug("Initializing JwtRepository")
        self.session = db_session

    async def create(
        self, refresh_token: CreateRefreshTokenDTO
    ) -> CreateRefreshTokenDTO:
        logger.info("Creating refresh token for user_id: %s", refresh_token.user_id)
        try:
            stmt = insert(RefreshTokenDBModel).values(
                refresh_token=refresh_token.refresh_token,
                user_id=refresh_token.user_id,
                expiration=refresh_token.expires_at,
            )
            await self.session.execute(stmt)
            await self.session.commit()
            logger.info(
                "Refresh token created successfully for user_id: %s",
                refresh_token.user_id,
            )
            return CreateRefreshTokenDTO.model_validate(refresh_token)
        except Exception as e:
            logger.error(
                "Failed to create refresh token for user_id %s: %s",
                refresh_token.user_id,
                str(e),
                exc_info=True,
            )
            await self.session.rollback()
            raise

    async def get_exists_refresh_token(
        self, refresh_token: RefreshToken
    ) -> Optional[RefreshToken]:
        logger.debug("Searching for existing refresh token")
        try:
            stmt = select(RefreshTokenDBModel).filter(
                or_(
                    RefreshTokenDBModel.refresh_token == refresh_token.refresh_token,
                    RefreshTokenDBModel.expires_at >= datetime.datetime.now(),
                )
            )

            _result = await self.session.execute(stmt)
            db_refresh_token = _result.first()

            if db_refresh_token is None:
                logger.debug("No existing refresh token found")
                return None

            logger.debug("Found existing refresh token")
            return RefreshToken.model_validate(db_refresh_token)
        except Exception as e:
            logger.error("Error searching for refresh token: %s", str(e), exc_info=True)
            raise

    async def update(
        self, refresh_token: RefreshTokenUpdateDTO
    ) -> Optional[RefreshTokenResponseDTO]:
        logger.info("Updating refresh token with id: %s", refresh_token.id)
        try:
            stmt = (
                update(RefreshTokenDBModel)
                .where(
                    RefreshTokenDBModel.id == refresh_token.id,
                )
                .values(
                    refresh_token=refresh_token.refresh_token,
                    expires_at=refresh_token.expires_at,
                    updated_at=datetime.datetime.now(),
                )
                .returning(RefreshTokenDBModel)
            )

            result = await self.session.execute(stmt)
            token = result.scalar_one_or_none()

            if not token:
                logger.error("Token not found for update with id: %s", refresh_token.id)
                raise ValueError(
                    f"Not found token with {
                        refresh_token.id
                    } and {refresh_token.refresh_token} in the database"
                )

            await self.session.commit()
            logger.info(
                "Refresh token updated successfully with id: %s", refresh_token.id
            )
            return RefreshTokenResponseDTO.model_validate(token)
        except Exception as e:
            logger.error(
                "Failed to update refresh token with id %s: %s",
                refresh_token.id,
                str(e),
                exc_info=True,
            )
            await self.session.rollback()
            raise

    async def delete(self, refresh_token: RefreshToken) -> None:
        logger.info("Deleting refresh token for user_id: %s", refresh_token.user_id)
        try:
            stmt = delete(RefreshTokenDBModel).where(
                or_(
                    RefreshTokenDBModel.refresh_token == refresh_token.refresh_token,
                    RefreshTokenDBModel.expires_at >= datetime.datetime.now(),
                )
            )
            result = await self.session.execute(stmt)
            await self.session.commit()
            logger.info(
                "Refresh token deleted successfully. Rows affected: %s", result.rowcount
            )
        except Exception as e:
            logger.error("Failed to delete refresh token: %s", str(e), exc_info=True)
            await self.session.rollback()
            raise


async def get_repository(session: AsyncSession = Depends(get_db)) -> JwtRepository:
    logger.debug("Creating JwtRepository instance")
    return JwtRepository(db_session=session)


get_jwt_repository_dep = Annotated[JwtRepository, Depends(get_repository)]