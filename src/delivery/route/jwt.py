from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from tools_openverse import setup_logger

from src.entity.jwt.ent import CreateAccessTokenData, LoginOAuth2PasswordRequestForm
from src.usecases.jwt import get_jwt_service_dep

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

    async def log_in(
        self,
        form_data: LoginAuthPasswordR,
        service: get_jwt_service_dep,
    ) -> JSONResponse:

        logger.info("Login attempt for user: %s", form_data.login)

        try:
            logger.debug("Creating access token for user: %s", form_data.login)
            token = await service.create_access_token(
                data=CreateAccessTokenData(sub=form_data.login)
            )
            logger.info(
                "Access token created successfully for user: %s", form_data.login
            )

            response = JSONResponse(content={"message": "Login successful"})

            expires_time = datetime.now() + timedelta(minutes=15)
            logger.debug("Setting cookie expiration time: %s", expires_time)

            response.set_cookie(
                key="access_token",
                value=f"Bearer {token}",
                httponly=True,
                expires=expires_time.astimezone(timezone.utc),
            )

            logger.info("Cookie set successfully for user: %s", form_data.login)
            return response

        except Exception as exc:
            logger.error(
                "Login failed for user %s: %s", form_data.login, str(exc), exc_info=True
            )
            raise HTTPException(
                status_code=500, detail="Internal server error"
            ) from exc

    async def read_me(
        self, request: Request, service: get_jwt_service_dep, 
    ) -> dict[str, Any]:
        logger.info("ReadMe endpoint called")
        logger.debug(
            "Processing ReadMe request from IP: %s",
            request.client.host if request.client else "unknown",
        )

        try:
            logger.debug("Attempting to get current user from token")
            user = await service.get_current_user_by_token(request)
            if not user:
                logger.warning(
                    "Unauthorized access attempt in ReadMe endpoint from IP: %s",
                    request.client.host if request.client else "unknown",
                )
                raise HTTPException(status_code=401, detail="Unauthorized")

            logger.info("User data retrieved successfully in ReadMe endpoint")
            logger.debug("User data: %s", user.model_dump())
            return {"user": user.model_dump()}

        except HTTPException as exc:
            logger.warning("HTTP exception in ReadMe endpoint: %s", exc.detail)
            raise
        except Exception as exc:
            logger.error("Error in ReadMe endpoint: %s", str(exc), exc_info=True)
            raise HTTPException(
                status_code=500, detail="Internal server error"
            ) from exc


    async def get_current_user_by_raw_token(
        self, raw_token: str, service: get_jwt_service_dep
    ) -> dict[str, Any]:
        logger.info("GET_CURRENT_USER_BY_RAW_TOKEN endpoint called")
        try:
            logger.debug("Attempting to get current user from token")
            user = await service.get_current_user_by_raw_token(raw_token=raw_token)
            if not user:
                logger.warning(
                    "Unauthorized access attempt in GET_CURRENT_USER_BY_RAW_TOKEN endpoint from IP: %s",
                    raw_token
                )
                raise HTTPException(status_code=401, detail="Unauthorized")

        except HTTPException as exc:
            logger.warning("HTTP exception in GET_CURRENT_USER_BY_RAW_TOKEN endpoint: %s", exc.detail)
            raise
        except Exception as exc:
            logger.error("Error in GET_CURRENT_USER_BY_RAW_TOKEN endpoint: %s", str(exc), exc_info=True)
            raise HTTPException(
                status_code=500, detail=f"Internal server error {str(exc)}"
        ) from exc

        logger.info("User data retrieved successfully in GET_CURRENT_USER_BY_RAW_TOKEN endpoint")
        logger.debug("User data: %s", user.model_dump())
        return {"user": user.model_dump()}