# routes/jwt_token.py
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from tools_openverse import setup_logger
from tools_openverse.common.types import AccessTokenType

from src.entity.jwt.ent import (
    CreateAccessTokenData, 
    CreateRefreshTokenData, 
    LoginOAuth2PasswordRequestForm,
)
from src.usecases.jwt import (
    get_jwt_service_dep,
    ACCESS_TOKEN_EXPIRE_MINUTES,
    REFRESH_TOKEN_EXPIRE_DAYS
)

logger = setup_logger(__name__)

LoginAuthPasswordR = Annotated[LoginOAuth2PasswordRequestForm, Depends()]


class JwtTokenRoute:
    def __init__(self, router: APIRouter):
        logger.info("Initializing JwtTokenRoute")
        self.router = router
        self.router.add_api_route("/auth/user/log_in", self.log_in, methods=["POST"])
        self.router.add_api_route("/auth/user/info", self.read_me, methods=["GET"])
        self.router.add_api_route(
            "/auth/user/raw_token", self.get_current_user_by_raw_token, methods=["GET"]
        )
        self.router.add_api_route(
            "/auth/user/refresh", self.refresh_access_token, methods=["POST"]
        )
        self.router.add_api_route("/auth/user/logout", self.logout, methods=["POST"])

    async def log_in(
        self,
        form_data: LoginAuthPasswordR,
        service: get_jwt_service_dep,
    ) -> JSONResponse:
        """Login endpoint - creates access and refresh tokens
        
        Args:
            form_data: Login form data
            service: JWT service
            
        Returns:
            JSONResponse with cookies set
        """
        logger.info("Login attempt for user: %s", form_data.login)

        try:
            # Проверяем учетные данные пользователя
            # TODO: Здесь должна быть проверка пароля
            user = await service.request.get_user(user_login=form_data.login)
            if not user:
                logger.warning("Failed login attempt for user: %s", form_data.login)
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Incorrect username or password"
                )
            
            now = datetime.now(timezone.utc)
            
            # Создаем access token
            access_token_data = CreateAccessTokenData(
                sub=form_data.login,
                exp=now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
            )
            access_token = await service.create_access_token(data=access_token_data)
            
            # Создаем refresh token
            refresh_token_data = CreateRefreshTokenData(
                sub=form_data.login,
                exp=now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
            )
            refresh_token = await service.create_refresh_token(data=refresh_token_data)
            
            # Подготавливаем ответ
            response = JSONResponse(
                content={
                    "message": "Login successful",
                    "user": {
                        "login": form_data.login,
                        "id": str(user.id) if hasattr(user, 'id') else None
                    }
                }
            )
            
            # Устанавливаем cookies
            response = service.set_cookies(
                response=response,
                token=access_token,
                key="access_token",
                expires=access_token_data.exp
            )
            
            response = service.set_cookies(
                response=response,
                token=refresh_token.refresh_token_hash,  # Исправлено - теперь передаем строку
                key="refresh_token",
                expires=refresh_token_data.exp
            )
            
            logger.info("User logged in successfully: %s", form_data.login)
            return response

        except HTTPException:
            raise
        except Exception as exc:
            logger.error(
                "Login failed for user %s: %s", 
                form_data.login, 
                str(exc), 
                exc_info=True
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
                detail="Internal server error"
            ) from exc

    async def read_me(
        self, 
        request: Request, 
        service: get_jwt_service_dep, 
    ) -> dict[str, Any]:
        """Get current user information
        
        Args:
            request: FastAPI Request
            service: JWT service
            
        Returns:
            User information dict
        """
        logger.info("ReadMe endpoint called")
        logger.debug(
            "Processing ReadMe request from IP: %s",
            request.client.host if request.client else "unknown",
        )

        try:
            user = await service.get_current_user_by_token(request)
            
            logger.info("User data retrieved successfully in ReadMe endpoint")
            return {"user": user.model_dump()}

        except HTTPException:
            raise
        except Exception as exc:
            logger.error("Error in ReadMe endpoint: %s", str(exc), exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
                detail="Internal server error"
            ) from exc

    async def get_current_user_by_raw_token(
        self, 
        raw_token: str, 
        service: get_jwt_service_dep
    ) -> dict[str, Any]:
        """Get user by raw token (for API usage)
        
        Args:
            raw_token: JWT token string
            service: JWT service
            
        Returns:
            User information dict
        """
        logger.info("GET_CURRENT_USER_BY_RAW_TOKEN endpoint called")
        
        try:
            user = await service.get_current_user_by_raw_token(raw_token=raw_token)
            
            logger.info("User data retrieved successfully")
            return {"user": user.model_dump()}
            
        except HTTPException:
            raise
        except Exception as exc:
            logger.error(
                "Error in GET_CURRENT_USER_BY_RAW_TOKEN endpoint: %s", 
                str(exc), 
                exc_info=True
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
                detail="Internal server error"
            ) from exc
    
    async def refresh_access_token(
        self, 
        request: Request, 
        service: get_jwt_service_dep
    ) -> JSONResponse:
        """Refresh access token using refresh token
        
        Args:
            request: FastAPI Request
            service: JWT service
            
        Returns:
            JSONResponse with new tokens in cookies
        """
        logger.info("Refresh token endpoint called")
        
        try:
            # Получаем новые токены
            access_token, refresh_token = await service.refresh_access_token(request=request)
            
            now = datetime.now(timezone.utc)
            
            # Подготавливаем ответ
            response = JSONResponse(
                content={"message": "Access token refreshed successfully"}
            )
            
            # Устанавливаем новые cookies
            response = service.set_cookies(
                response=response, 
                token=access_token, 
                key="access_token",
                expires=now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
            )
            
            response = service.set_cookies(
                response=response, 
                token=refresh_token, 
                key="refresh_token",
                expires=now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
            )
            
            logger.info("Tokens refreshed successfully")
            return response
            
        except HTTPException:
            raise
        except Exception as exc:
            logger.error("Error refreshing tokens: %s", str(exc), exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to refresh token"
            ) from exc
    
    async def logout(self, request: Request) -> JSONResponse:
        """Logout endpoint - clears tokens from cookies
        
        Args:
            request: FastAPI Request
            
        Returns:
            JSONResponse with cleared cookies
        """
        logger.info("Logout endpoint called")
        
        response = JSONResponse(
            content={"message": "Logged out successfully"}
        )
        
        # Очищаем cookies
        response.delete_cookie(key="access_token")
        response.delete_cookie(key="refresh_token")
        
        logger.info("User logged out successfully")
        return response