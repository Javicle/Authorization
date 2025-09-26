# use_cases/jwt.py
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, Literal, Optional

from fastapi import Depends, Request, status
from fastapi.responses import JSONResponse
from jose import jwt, JWTError
from pydantic import BaseModel
from tools_openverse import setup_logger
from tools_openverse.common.config import settings
from tools_openverse.common.types import AccessTokenType, RefreshTokenType

from src.entity.jwt.dto import CreateRefreshTokenDTO
from src.entity.jwt.ent import (
    CreateAccessTokenData,
    CreateRefreshTokenData,
    DecodedToken,
    JwtToken,
    RefreshToken,
    TokenPayload,
)
from tools_openverse.common.dep import authorization
from src.entity.jwt.exc import NotTransferredException
from src.infra.repository.db.user import JwtRepository, get_jwt_repository_dep
from src.usecases.exc import CredintialsException, ErrorResponseException, JwtException
from src.usecases.request import JwtRequest, get_jwt_request_dep

logger = setup_logger()

# constsant for tokens time
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 7


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


async def refresh_token_in_request(request: Request) -> str | None:
    """Method for getting refresh token from request

    Args:
        request (Request): Request object

    Returns:
        str | None: Refresh token without Bearer prefix
    """
    logger.debug("Getting refresh token from request")
    
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        logger.debug("No refresh token found in request")
        return None
    
    if refresh_token.startswith("Bearer "):
        refresh_token = refresh_token[7:]
    
    logger.debug("Refresh token found in request")
    return refresh_token


refresh_token_in_request_dep = Annotated[str | None, Depends(refresh_token_in_request)]


class JwtService:
    def __init__(self, repository: JwtRepository, jwt_request: JwtRequest) -> None:
        self.repository = repository
        self.request = jwt_request
        logger.debug("JwtService initialized")

    def _encode(self, data: CreateAccessTokenData | CreateRefreshTokenData) -> str:
        """Encode JWT token"""
        claims = data.model_dump()
        exp: datetime = claims["exp"]
        claims["exp"] = int(exp.timestamp())
        return jwt.encode(
            claims=claims,
            algorithm=settings.JWT_ALGORITHM,
            key=settings.JWT_SECRET_KEY,
        )
    
    async def _decode_and_validate_token(self, token: str) -> DecodedToken:
        """Internal method for decoding and validating token
        
        Args:
            token (str): JWT token to decode
            
        Raises:
            JwtException: If token is invalid or expired
            
        Returns:
            DecodedToken: Decoded token data
        """
        try:
            payload = jwt.decode(
                token=token,
                key=settings.JWT_SECRET_KEY,
                algorithms=[settings.JWT_ALGORITHM],
            )
            decoded = TokenPayload(**payload)

            if decoded.exp < datetime.now(timezone.utc):
                logger.warning("Token has expired")
                raise JwtException(detail="Token has expired")
                
            logger.debug("Token decoded and validated successfully")
            return decoded
            
        except JWTError as exc:
            logger.error("JWT decoding error: %s", str(exc))
            raise JwtException(detail="Could not validate credentials.")
        
    def set_cookies(
        self, 
        response: JSONResponse, 
        token: str, 
        expires: datetime,
        key: Literal["access_token", "refresh_token"]
    ) -> JSONResponse:
        """Set cookie with token
        
        Args:
            response: JSONResponse object
            token: Token value
            expires: Expiration datetime
            key: Cookie key name
            
        Returns:
            JSONResponse with cookie set
        """
        response.set_cookie(
            key=key,
            httponly=True,
            secure=True,  
            samesite="lax", 
            value=f"Bearer {token}",
            expires=expires.astimezone(timezone.utc)
        )
        return response

    async def create_access_token(self, data: CreateAccessTokenData) -> AccessTokenType:
        """Create access token for user

        Args:
            data (CreateAccessTokenData): BaseModel which need to create access token
            
        Raises:
            ErrorResponseException: raises if not correct response

        Returns:
            AccessTokenType: string access token 
        """
        logger.info("Creating access token for user: %s", data.sub)

        user_db = await self.request.get_user(
            user_login=data.sub if isinstance(data.sub, str) else str(data.sub)
        )

        if not user_db:
            logger.error("User not found when creating access token: %s", data.sub)
            raise ErrorResponseException(
                detail="User not found. Cannot create access token.",
                status_code=status.HTTP_404_NOT_FOUND,
            )

        encoded_jwt = self._encode(data=data)
        logger.info("Access token created successfully for user: %s", data.sub)
        return encoded_jwt

    async def create_refresh_token(self, data: CreateRefreshTokenData) -> RefreshToken:
        """Create refresh token and save to database
        
        Args:
            data: Refresh token creation data
            
        Returns:
            RefreshToken model
        """
        encoded_refresh_token = self._encode(data=data)
        logger.info("Creating refresh token for user: %s", data.sub)
        
        # model refresh token
        refresh_model = RefreshToken(
            user_id=data.sub,
            refresh_token_hash=encoded_refresh_token,
            expires_at=data.exp,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        # save database
        await self.repository.create(refresh_token=CreateRefreshTokenDTO(
            user_id=data.sub,
            refresh_token=encoded_refresh_token,
            expires_at=data.exp,
        ))
        
        return refresh_model

    async def refresh_access_token(self, request: Request) -> tuple[AccessTokenType, RefreshTokenType]:
        """Refresh access token using refresh token from cookies
        
        Args:
            request: FastAPI Request object
            
        Returns:
            Tuple of (access_token, refresh_token)
        """
        refresh_token_raw = await refresh_token_in_request(request=request)
        if not refresh_token_raw:
            logger.warning("Refresh token not in cookies")
            raise NotTransferredException("Refresh token not found in cookies")
        
        logger.info("Refreshing access token")
        
        # get token from database
        token = await self.repository.get_exists_refresh_token(
            refresh_token=refresh_token_raw
        )
        if not token:
            logger.warning("Refresh token not found in database")
            raise NotTransferredException(
                detail="Токен с указанным refresh_token не найден."
            )
        
        # delete olded token
        await self.repository.delete(refresh_token=refresh_token_raw)

        # get user
        user_db = await self.request.get_user(user_id=token.user_id)
        if not user_db:
            logger.error("User not found for refresh token: %s", token.user_id)
            raise NotTransferredException(detail="User not found")

        user_login = user_db.login if hasattr(user_db, 'login') else str(user_db.id)

        # Создаем новые токены
        now = datetime.now(timezone.utc)
        
        # new access token
        access_token = await self.create_access_token(
            data=CreateAccessTokenData(
                sub=user_login,
                exp=now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
            ),
        )
        
        # new refresh token
        refresh_token_model = await self.create_refresh_token(
            data=CreateRefreshTokenData(
                sub=user_login,
                exp=now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
            )
        )

        logger.info("Tokens refreshed successfully for user: %s", user_login)
        return access_token, refresh_token_model.refresh_token_hash

    async def get_current_user_by_token(self, request: Request) -> BaseModel:
        """
        Method to get user by token from cookies
        """
        logger.debug("Getting current user by token")
        token = request.cookies.get("access_token")
        logger.debug("Token from cookies: %s", "***" if token else "None")

        if not token:
            logger.warning("Token not found in cookies")
            raise CredintialsException(detail="Token not found in cookies.")

        if token.startswith("Bearer "):
            token = token[7:]

        
        decoded_token = await self._decode_and_validate_token(token)
        
        login = decoded_token.sub
        if not login:
            logger.warning("No login found in token payload")
            raise CredintialsException(detail="Could not validate credentials.")

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
        """Get user by raw token string
        
        Args:
            raw_token: JWT token string
            
        Returns:
            User model
        """
        
        decoded_token = await self._decode_and_validate_token(raw_token)
        
        login = decoded_token.sub
        if not login:
            logger.warning("No login found in raw token payload")
            raise CredintialsException(detail="Could not validate credentials.")
        
        user = await self.request.get_user(user_login=login)
        if user is None:
            logger.error("User not found in database: %s", login)
            raise ErrorResponseException(
                detail="User not found in database.",
                status_code=status.HTTP_404_NOT_FOUND,
            )

        logger.info("Current user retrieved successfully: %s", login)
        return user

    async def decode_token(
        self,
        access_token_from_header: Optional[str] = None,
        access_token: Optional[AccessTokenType] = None,
        token: Optional[JwtToken] = None,
    ) -> DecodedToken:
        """Method for decoding token

        Args:
            access_token_from_header: Access token from header
            access_token: Access token
            token: Jwt token object

        Raises:
            NotTransferredException: If token is not provided.

        Returns:
            DecodedToken: Decoded token.
        """
        logger.debug("Attempting to decode token")

        token_to_decode = (
            access_token_from_header or 
            access_token or 
            (token.access_token if token else None)
        )

        if not token_to_decode:
            logger.warning("No token provided for decoding")
            raise NotTransferredException(
                detail="Не переданы данные для декодирования токена."
            )

        return await self._decode_and_validate_token(token_to_decode)


async def get_jwt_service(
    repository: get_jwt_repository_dep,
    request: get_jwt_request_dep,
) -> JwtService:
    return JwtService(repository, request)


get_jwt_service_dep = Annotated[JwtService, Depends(get_jwt_service)]