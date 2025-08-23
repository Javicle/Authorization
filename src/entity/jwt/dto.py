import datetime
from uuid import UUID

from pydantic import BaseModel, field_validator
from tools_openverse import setup_logger
from tools_openverse.common.types import RefreshTokenType

logger = setup_logger()


class CreateRefreshTokenDTO(BaseModel):
    user_id: UUID | str
    refresh_token: RefreshTokenType
    expires_at: datetime.datetime


class RefreshTokenUpdateDTO(BaseModel):
    id: UUID | str
    refresh_token: RefreshTokenType
    expires_at: datetime.datetime

    @field_validator("expires_at")
    @classmethod
    def validate_expires_at(cls, value: datetime.datetime) -> datetime.datetime:
        logger.debug("Validating expires_at in RefreshTokenUpdateDTO: %s", value)
        if value < datetime.datetime.now():
            logger.error("Invalid expires_at value: %s (less than current time)", value)
            raise ValueError("Time of expiration cannot be less than datetime now")
        logger.debug("expires_at validation passed: %s", value)
        return value


class RefreshTokenResponseDTO(BaseModel):
    user_id: UUID | str
    refresh_token: RefreshTokenType
    expires_at: datetime.datetime
    created_at: datetime.datetime

    class Config:
        orm_mode = True


class BlacklistRefreshTokenDTO(BaseModel):
    id: UUID | str
    refresh_token: RefreshTokenType
