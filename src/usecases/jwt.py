from datetime import datetime, timedelta
from typing import Annotated, Optional

from fastapi import Depends, Header, Request, status
from jose import jwt
from pydantic import BaseModel
from tools_openverse import setup_logger
from tools_openverse.common.config import settings
from tools_openverse.common.types import AccessTokenType, ExpiresType, RefreshTokenType

from src.entity.jwt.ent import (
    CreateAccessTokenData,
    DecodedToken,
    JwtToken,
    RefreshToken,
)
from tools_openverse.common.dep import authorization
from src.entity.jwt.exc import NotTransferredException
from src.infra.repository.db.user import JwtRepository, get_jwt_repository_dep
from src.usecases.exc import CredintialsException, ErrorResponseException, JwtException
from src.usecases.request import JwtRequest, get_jwt_request_dep

logger = setup_logger()


async def access_token_in_header(authorization: authorization) -> AccessTokenType:
    """Method for getting access token from header

    Args:
        authorization (str, optional): Authorization header. Defaults to Header(...).

    Raises:
        NotTransferredException: If authorization header is not valid.
    """
    if not authorization.startswith("Bearer "):
        logger.warning("Invalid authorization header format")
        raise NotTransferredException(
            detail="Invalid authorization header format."
        )
    token = authorization.replace("Bearer ", "")
    logger.debug("Access token extracted from header")
    return token


access_token_in_header_dep = Annotated[AccessTokenType, Depends(access_token_in_header)]


async def refresh_token_in_request(request: Request) -> Optional[RefreshTokenType]:
    """Method for getting refresh token from request

    Args:
        request (Request): Request object

    Returns:
        Optional[RefreshTokenType]: Refresh token
    """
    logger.debug("Getting refresh token from request")

    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        logger.debug("No refresh token found in request")
        return None
    logger.debug("Refresh token found in request")
    return refresh_token


async def decode_token(
    access_token_from_header: access_token_in_header_dep,
    access_token: Optional[AccessTokenType] = None,
    token: Optional[JwtToken] = None,
) -> DecodedToken:
    """Method for decoding token

    Args:
        access_token (Optional[AccessTokenType], optional): Access token.
        Defaults to None.
        token (Optional[JwtToken], optional): Jwt token. Defaults to None.
        access_token_from_header (str, optional): Access token from header.
        Defaults to Depends(access_token_in_header)

    Raises:
        NotTransferredException: If token is not found in database.

    Returns:
        DecodedToken: Decoded token.
    """

    logger.debug("Attempting to decode token")

    token_to_decode = (
        access_token_from_header or access_token or (
            token.access_token if token else None
        )
    )

    if token_to_decode:
        try:
            to_decode = jwt.decode(
                token=token_to_decode,
                algorithms=settings.JWT_ALGORITHM,
                key=settings.JWT_SECRET_KEY,
            )
            logger.debug("Token decoded successfully")
            return DecodedToken(**to_decode)
        except Exception as e:
            logger.error("Failed to decode token: %s", str(e))
            raise NotTransferredException(detail="Ошибка при декодировании токена.")

    logger.warning("No token provided for decoding")
    raise NotTransferredException(
        detail="Не переданы данные для декодирования токена."
    )


class JwtService:
    def __init__(self, repository: JwtRepository, jwt_request: JwtRequest) -> None:
        self.repository = repository
        self.request = jwt_request
        logger.debug("JwtService initialized")

    async def create_access_token(        
        self, data: CreateAccessTokenData,
        expires_delta: Optional[ExpiresType] = None,
    ) -> AccessTokenType:
        """Create access token for user

        Args:
            data (CreateAccessTokenData): BaseModel which need to create access token
            expires_delta (Optional[ExpiresType], optional): Time to expire access token

        Raises:
            ErrorResponseException: raises if not correct response

        Returns:
            AccessTokenType: string access token 
        """
        logger.info("Creating access token for user: %s", data)
        to_encode = data

        user_db = await self.request.get_user(
            user_login=data.sub if isinstance(data.sub, str) else str(data.sub)
        )

        if not user_db:
            logger.error("User not found when creating access token: %s", data.sub)
            raise ErrorResponseException(
                detail="User not found. Cannot create access token.",
                status_code=status.HTTP_404_NOT_FOUND,
            )

        expire = (
            datetime.now() + expires_delta
            if expires_delta
            else datetime.now() + timedelta(minutes=15)
        )

        claims = to_encode.model_dump()
        claims["expires_delta"] = claims["expires_delta"].isoformat()

        to_encode.expires_delta = expire
        encoded_jwt: str = jwt.encode(
            claims=claims,
            key=settings.JWT_SECRET_KEY,
            algorithm=settings.JWT_ALGORITHM,
        )
        logger.info("Access token created successfully for user: %s", data.sub)
        return encoded_jwt

    async def refresh_access_token(
        self, refresh_token: RefreshToken
    ) -> AccessTokenType:
        logger.info("Refreshing access token")
        token = await self.repository.get_exists_refresh_token(
            refresh_token=refresh_token
        )
        if not token:
            logger.warning("Refresh token not found in database")
            raise NotTransferredException(
                detail="Токен с указанным refresh_token не найден."
            )

        user_db = await self.request.get_user(user_id=token.user_id)
        if not user_db:
            logger.error("User not found for refresh token: %s", token.user_id)
            raise NotTransferredException(detail="Пользователь не найден.")

        login = getattr(user_db, "login", None)

        access_token = await self.create_access_token(
            data=CreateAccessTokenData(
                sub=login if login else "",
                expires_delta=datetime.now() + timedelta(minutes=15),
            ),
        )

        logger.info("Access token refreshed successfully for user: %s", login)
        return access_token

    async def get_current_user_by_token(self, request: Request) -> BaseModel:
        """
        Method to get user by token
        """
        logger.debug("Getting current user by token")
        token = request.cookies.get("access_token")
        logger.debug("Token from cookies: %s", "***" if token else "None")

        if not token:
            logger.warning("Token not found in cookies")
            raise CredintialsException(detail="Token not found in cookies.")

        if token.startswith("Bearer "):
            token = token[len("Bearer ") :]

        try:
            logger.debug("Decoding token with algorithm: %s", settings.JWT_ALGORITHM)
            payload = jwt.decode(
                token=token,
                key=settings.JWT_SECRET_KEY,
                algorithms=[settings.JWT_ALGORITHM],
            )
            login: str | None = payload.get("sub")

            if not login:
                logger.warning("No login found in token payload")
                raise CredintialsException(detail="Could not validate credentials.")

            logger.debug("Token decoded successfully for user: %s", login)

        except Exception as e:
            logger.error("JWT decoding error: %s", str(e))
            raise JwtException(detail="Could not validate credentials.")

        user = await self.request.get_user(user_login=login)
        if user is None:
            logger.error("User not found in database: %s", login)
            raise ErrorResponseException(
                detail="User not found in database.",
                status_code=status.HTTP_404_NOT_FOUND,
            )

        logger.info("Current user retrieved successfully: %s", login)
        return user

    async def get_current_user_by_raw_token(self, raw_token: str) -> BaseModel:
        try:
            logger.debug("Decoding token with algorithm: %s", settings.JWT_ALGORITHM)
            payload = jwt.decode(
                token=raw_token,
                key=settings.JWT_SECRET_KEY,
                algorithms=[settings.JWT_ALGORITHM],
            )
            login: Optional[str] = payload.get("sub")

            if not login:
                logger.warning("No login found in raw token payload")
                raise CredintialsException(detail="Could not validate credentials.")

            logger.debug("Token decoded successfully for user: %s", login)
        
        except Exception as exc:
            logger.error("JWT decoding error: %s", str(exc))
            raise JwtException(detail="Could not validate credentials.")
        
        user = await self.request.get_user(user_login=login)
        if user is None:
            logger.error("User not found in database: %s", login)
            raise ErrorResponseException(
                detail="User not found in database.",
                status_code=status.HTTP_404_NOT_FOUND,
            )

        logger.info("Current user retrieved successfully: %s", login)
        return user


async def get_jwt_service(
    repository: get_jwt_repository_dep,
    request: get_jwt_request_dep,
) -> JwtService:
    return JwtService(repository, request)


get_jwt_service_dep = Annotated[JwtService, Depends(get_jwt_service)]
