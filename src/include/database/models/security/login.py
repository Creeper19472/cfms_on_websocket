from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column

from include.database.handler import Base


class LoginSecurity(Base):
    __tablename__ = "login_security"

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
