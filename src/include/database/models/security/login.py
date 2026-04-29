__all__ = ["LoginThrottle", "TrafficThrottle"]

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column

from include.database.handler import Base


class LoginThrottle(Base):
    __tablename__ = "login_throttles"

    username: Mapped[str] = mapped_column(String(255), primary_key=True)
    ip_address: Mapped[str] = mapped_column(String(45), primary_key=True, index=True)

    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    last_attempt: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), onupdate=func.now()
    )
    locked_until: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    def is_locked(self) -> bool:
        if self.locked_until is not None:
            return self.locked_until > datetime.now()
        return False

    @classmethod
    def get_record(cls, session, username: str, ip_address: str):
        return session.get(cls, (username, ip_address))

    @classmethod
    def make_cache_key(cls, username: str, ip_address: str) -> tuple[str, str, str]:
        return ("user_ip", username, ip_address)


class TrafficThrottle(Base):
    __tablename__ = "traffic_throttles"

    ip_address: Mapped[str] = mapped_column(String(45), primary_key=True)

    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    last_attempt: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), onupdate=func.now()
    )
    locked_until: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    def is_locked(self) -> bool:
        if self.locked_until is not None:
            return self.locked_until > datetime.now()
        return False

    @classmethod
    def get_record(cls, session, ip_address: str):
        return session.get(cls, ip_address)

    @classmethod
    def make_cache_key(cls, ip_address: str) -> tuple[str, str]:
        return ("ip", ip_address)
