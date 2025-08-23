from datetime import datetime, timedelta
from typing import Self

from fastapi import Form
from pydantic import BaseModel, Field, field_validator
from tools_openverse import setup_logger
from tools_openverse.common.types import (
    AccessTokenType,
    ExpiresAtType,
    ExpiresType,
    IdType,
    JwtAlgorithmType,
    JwtSecretKeyType,
    RefreshTokenType,
    ScopesType,
    SubType,
    TokenType,
)

from .exc import DateTimeHTTPException

logger = setup_logger()

_LOGIN_FORM = Form(..., description="User Login")
_PASSWORD_FORM = Form(..., description="User Password")


class CreateAccessTokenData(BaseModel):
    sub: SubType
    expires_delta: ExpiresAtType = Field(
        default_factory=lambda: datetime.now() + timedelta(minutes=15)
    )
    

class DecodedToken(BaseModel):
    token: AccessTokenType
    jwt_algoritm: JwtAlgorithmType
    jwt_secret_key: JwtSecretKeyType


class TokenPayload(BaseModel):
    sub: SubType
    scopes: ScopesType
    exp: ExpiresType


class RefreshToken(BaseModel):
    user_id: IdType
    refresh_token: RefreshTokenType
    expires_at: ExpiresAtType
    created_at: datetime
    updated_at: datetime

    @field_validator("expires_at")
    def validate_expires_at(cls, value: ExpiresAtType) -> ExpiresAtType:
        logger.debug("Validating expires_at value: %s", value)
        date = datetime.now()

        if value < date:
            logger.error("Invalid expiration time: %s", value)
            raise DateTimeHTTPException(
                detail="Время окончание не может быть меньше чем нынешнее время.",
                datetime=value,
            )
        logger.debug("expires_at validation passed: %s", value)
        return value


class JwtToken(BaseModel):
    access_token: AccessTokenType
    refresh_token: RefreshToken
    token_type: TokenType


class LoginOAuth2PasswordRequestForm(BaseModel):
    """
    Кастомная форма для входа через OAuth2 Password flow,
    но с полями login/password вместо username/password.
    """

    login: str
    password: str

    @classmethod
    def as_form(
        cls,
        login: str = _LOGIN_FORM,
        password: str = _PASSWORD_FORM,
    ) -> Self:
        logger.debug("Creating LoginOAuth2PasswordRequestForm for login: %s", login)
        return cls(login=login, password=password)
