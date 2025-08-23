# TODO: restore and adapt under new system app-starter


# from redis.asyncio import Redis
# from sqlalchemy import text
# from sqlalchemy.ext.asyncio import AsyncSession
# from tools_openverse import setup_logger
# from tools_openverse.common.heath import ServiceCheck, ServiceStatusResponse

# logger = setup_logger(__name__)


# class DatabaseHealthService(ServiceCheck):
#     def __init__(self, service_name: str, session: AsyncSession) -> None:
#         logger.debug("Initializing DatabaseHealthService for service: %s", service_name)
#         self.service_name = service_name
#         self.session = session

#     async def check(self) -> ServiceStatusResponse:
#         logger.debug("Checking database health for service: %s", self.service_name)
#         try:
#             result = await self.session.execute(text("SELECT 1"))
#             if result:
#                 logger.info(
#                     "Database health check passed for service: %s", self.service_name
#                 )
#                 return ServiceStatusResponse(
#                     service_name=self.service_name,
#                     success=True,
#                     message="Database is healthy",
#                 )
#             logger.warning(
#                 "Database health check failed for service: %s", self.service_name
#             )
#             return ServiceStatusResponse(
#                 service_name=self.service_name,
#                 success=False,
#                 message="Database is unhealthy",
#             )
#         except Exception as e:
#             logger.error(
#                 "Database health check error for service %s: %s",
#                 self.service_name,
#                 str(e),
#                 exc_info=True,
#             )
#             return ServiceStatusResponse(
#                 service_name=self.service_name,
#                 success=False,
#                 message=f"Database is unhealthy: {str(e)}",
#             )


# class RedisHealthCheck(ServiceCheck):
#     def __init__(self, service_name: str, redis_client: Redis) -> None:
#         logger.debug("Initializing RedisHealthCheck for service: %s", service_name)
#         self.service_name = service_name
#         self.redis_client = redis_client

#     async def check(self) -> ServiceStatusResponse:
#         logger.debug("Checking Redis health for service: %s", self.service_name)
#         try:
#             await self.redis_client.ping()  # type: ignore[PylancereportUnknownMemberType]
#             logger.info("Redis health check passed for service: %s", self.service_name)
#             return ServiceStatusResponse(
#                 service_name=self.service_name, success=True, message="Redis is healthy"
#             )
#         except Exception as e:
#             logger.error(
#                 "Redis health check error for service %s: %s",
#                 self.service_name,
#                 str(e),
#                 exc_info=True,
#             )
#             return ServiceStatusResponse(
#                 service_name=self.service_name,
#                 success=False,
#                 message=f"Redis is unhealthy: {str(e)}",
#             )
