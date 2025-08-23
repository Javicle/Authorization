from datetime import datetime, timedelta
from typing import Any, Optional

from fastapi import HTTPException, status


class InvalidExpireJWTTokenException(HTTPException):
    def __init__(
        self,
        expires: timedelta,
        detail: Optional[str] = None,
        status_code: Optional[int] = None,
    ):
        super().__init__(
            status_code=status_code if status_code else status.HTTP_408_REQUEST_TIMEOUT,
            detail=detail if detail else f"Неверное время жизни JWTToken {expires}",
        )


class NotFoundException(HTTPException):
    def __init__(
        self, status_code: int, object: Any, detail: Optional[str] = None
    ) -> None:
        super().__init__(
            status_code if status_code else status.HTTP_404_NOT_FOUND,
            detail if detail else f"object was not found: {object}",
        )


class NotTransferredException(HTTPException):
    def __init__(self, detail: Optional[str] = None, status_code: Optional[int] = None):
        super().__init__(
            status_code=status_code if status_code else status.HTTP_400_BAD_REQUEST,
            detail=detail if detail else "Не переданы данные для использования!",
        )


class DateTimeHTTPException(HTTPException):
    def __init__(
        self,
        datetime: datetime | float | int,
        detail: Optional[str] = None,
        status_code: Optional[int] = None,
    ):
        super().__init__(
            status_code=status_code if status_code else status.HTTP_400_BAD_REQUEST,
            detail=(
                f"{detail} : {datetime}"
                if detail
                else f"Неверная дата и время: {datetime}"
            ),
        )
