from typing import Annotated, Any, Union
from uuid import UUID

from fastapi import Depends
from pydantic import BaseModel, create_model
from tools_openverse import setup_logger
from tools_openverse.common.request import (
    HttpMethods,
    ServiceName,
    SetRequest,
    UsersRoutes,
)
from tools_openverse.common.types import JSONResponseTypes, Sentinal, SuccessResponse

from .exc import ErrorResponseException

TYPE_MAPPING: dict[Union[Any, str], Any] = {
    str: str,
    int: int,
    float: float,
    bool: bool,
    dict: dict,
    list: list,
    type(None): Any,
}

logger = setup_logger()


class GetUserRequest(BaseModel):
    id: str | None = None
    user_login: str | None = None


async def _get_set_request() -> SetRequest:
    # its for dependency
    return SetRequest()


get_set_request_dep = Annotated[SetRequest, Depends(_get_set_request)]


async def repack_response(response: JSONResponseTypes) -> BaseModel:
    """
    Repack response to BaseModel

    Args:
        response (JSONResponseTypes): response from service

    Raises:
        ErrorResponseException: if response is not SuccessResponse

    Returns:
        BaseModel: response in BaseModel
    """
    if isinstance(response, SuccessResponse):
        response_detail = response.detail

        fields: dict[str, tuple[type, Any]] = {
            key: (TYPE_MAPPING.get(type(value), Any), ...)
            for key, value in response_detail.items()  # type: ignore
        }

        DynamicModel = create_model("DynamicModel", **fields)  # type: ignore
        logger.debug(f"dynamic model : {DynamicModel(**response_detail)}")

        return DynamicModel(**response_detail)  # type: ignore

    else:
        raise ErrorResponseException(
            detail="Не удалось получить данные пользователя", status_code=404
        )


class JwtRequest:
    """
    JwtRequest class for making requests to the users service

    Args:
        set_request (SetRequest): set_request
    """

    def __init__(self, set_request: SetRequest) -> None:
        self.set_request = set_request

    async def get_user(
        self, user_id: UUID | str = Sentinal, user_login: str = Sentinal
    ) -> BaseModel:
        response_user = await self.set_request.send_request(
            service_name=ServiceName.USERS,
            route_method=HttpMethods.GET,
            route_name=(
                UsersRoutes.GET_USER_BY_LOGIN
                if user_login
                else UsersRoutes.GET_USER_BY_ID
            ),
            request_data=GetUserRequest(id=str(user_id), user_login=user_login),
        )

        if not response_user:
            raise ValueError("Не удалось получить пользователь")

        user = await repack_response(response_user)
        return user


async def get_jwt_request(
    set_request: get_set_request_dep,
) -> JwtRequest:
    return JwtRequest(set_request)


get_jwt_request_dep = Annotated[JwtRequest, Depends(get_jwt_request)]