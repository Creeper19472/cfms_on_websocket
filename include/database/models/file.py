import secrets
from sqlalchemy import VARCHAR, Float, ForeignKey, Integer, Text
from include.database.handler import Base
from typing import List
from typing import Optional
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from sqlalchemy.orm import relationship
import time
from sqlalchemy.orm.session import object_session
import os, sys


class File(Base):
    __tablename__ = "files"
    id: Mapped[str] = mapped_column(
        VARCHAR(255), primary_key=True, default=lambda: secrets.token_hex(32)
    )

    sha256: Mapped[str] = mapped_column(VARCHAR(64), nullable=True)
    # calculate sha256 takes time, especially for large files lol
    #
    # there are also a lot of situations where sha256 in the database is null
    # or mismatch, so don't use it as a must

    path: Mapped[str] = mapped_column(Text, nullable=False)
    created_time: Mapped[float] = mapped_column(
        Float, nullable=False, default=lambda: time.time()
    )
    tasks: Mapped[List["FileTask"]] = relationship("FileTask", back_populates="file")

    @property
    def size(self):
        if os.path.exists(self.path):
            return os.path.getsize(self.path)
        else:
            return None

    @property
    def active(self):
        if sys.platform == "win32":
            import win32file, pywintypes

            hFile = None
            try:
                if os.path.exists(self.path):
                    hFile = win32file.CreateFile(
                        self.path,
                        win32file.GENERIC_READ,
                        win32file.FILE_SHARE_READ,
                        None,
                        win32file.OPEN_EXISTING,
                        0,
                        None,
                    )
            except pywintypes.error:
                return False
            finally:
                if hFile:
                    hFile.Close()

        # elif sys.platform == "linux":
        #     import fcntl
        #     try:
        #         with open(self.path, 'a') as f:
        #             fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        #     except IOError:
        #         return False

        # unsafe: for unknown platforms, won't check if the file is locked
        return os.path.exists(self.path) and os.path.getsize(self.path) > 0

    def delete(self):
        session = object_session(self)
        if session is not None:
            session.query(FileTask).filter(FileTask.file_id == self.id).delete(
                synchronize_session=False
            )  # be careful
            session.commit()

        try:
            os.remove(self.path)
        except (OSError, PermissionError):
            if os.path.exists(self.path):
                raise

    def get_latest_task(self):
        """
        返回最后一个尚未结束（也包括尚未开始）的任务，按起始时间排序。
        """

        now = time.time()
        active_tasks = [
            task
            for task in self.tasks
            if (task.end_time and now < task.end_time) or not task.end_time
        ]

        return (
            max(active_tasks, key=lambda task: task.start_time)
            if active_tasks
            else None
        )

    def __repr__(self) -> str:
        return f"File(id={self.id!r}, file_path={self.path!r}, created_time={self.created_time!r})"


class FileTask(Base):
    __tablename__ = "file_tasks"
    id: Mapped[str] = mapped_column(
        VARCHAR(255), primary_key=True, default=lambda: secrets.token_hex(32)
    )
    file_id: Mapped[str] = mapped_column(VARCHAR(255), ForeignKey("files.id"), nullable=False)
    # 0: 等待中, 1: 已完成, 2: 已取消
    status: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    mode: Mapped[int] = mapped_column(
        Integer, nullable=False, comment="0: download, 1: upload"
    )
    start_time: Mapped[float] = mapped_column(Float, nullable=False)
    end_time: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    # encryption_mode: Mapped[Optional[str]] = mapped_column(
    #     VARCHAR(32), nullable=True, default=None
    # )  # 加密模式，如 'AES', 'RSA'，未加密则为 None

    file: Mapped["File"] = relationship(
        "File", back_populates="tasks"
    )

    def __repr__(self) -> str:
        return (
            f"FileTask(id={self.id!r}, "
            f"file_id={self.file_id!r}, status={self.status!r})"
        )