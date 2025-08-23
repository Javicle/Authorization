import datetime

from sqlalchemy import Column, DateTime, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column
from tools_openverse import setup_logger

from src.infra.repository.db.base import Base

logger = setup_logger(__name__)


class RefreshTokenDBModel(Base):
    __tablename__ = "refresh_tokens"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
    )
    user_id = Column(UUID(as_uuid=True), primary_key=True)
    refresh_token: Mapped[str] = mapped_column(String)
    expires_at: Mapped[datetime.datetime] = mapped_column(DateTime)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=datetime.datetime.now
    )
    updated_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, onupdate=datetime.datetime.now, default=datetime.datetime.now
    )

    def __init__(self, **kwargs):
        logger.debug("Creating RefreshTokenDBModel instance")
        super().__init__(**kwargs)


