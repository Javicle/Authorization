from typing import Optional

from fastapi import HTTPException, status
from tools_openverse import setup_logger

logger = setup_logger(__name__)


class ErrorResponseException(HTTPException):
    def __init__(self, detail: Optional[str], status_code: Optional[int]) -> None:
        logger.error("ErrorResponseException: %s (status: %s)", detail, status_code)
        super().__init__(
            detail=detail if detail else "An error was found",
            status_code=status_code if status_code else status.HTTP_400_BAD_REQUEST,
        )


class CredintialsException(HTTPException):
    def __init__(
        self, detail: Optional[str], status_code: Optional[int] = None
    ) -> None:
        logger.warning("CredentialsException: %s", detail)
        super().__init__(
            detail=detail if detail else "Invalid credentials on checking user data",
            status_code=status_code if status_code else status.HTTP_401_UNAUTHORIZED,
        )


class JwtException(HTTPException):
    def __init__(
        self, detail: Optional[str], status_code: Optional[int] = None
    ) -> None:
        logger.warning("JwtException: %s", detail)
        super().__init__(
            detail=detail if detail else "Invalid JWT token",
            status_code=status_code if status_code else status.HTTP_401_UNAUTHORIZED,
        )
