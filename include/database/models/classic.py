from typing import TYPE_CHECKING
from typing import List
from typing import Optional
from typing import Set

import secrets
from sqlalchemy import VARCHAR, Float, ForeignKey, Integer, Text
from include.database.handler import Base, Session
from include.conf_loader import global_config
from include.classes.auth import Token
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from sqlalchemy.orm import relationship
from sqlalchemy import Boolean
from sqlalchemy import event
import time
from sqlalchemy.orm.session import object_session
from sqlalchemy import JSON
import jwt
import hashlib
import os


if TYPE_CHECKING:
    from include.database.models.blocking import UserBlockEntry


class User(Base):
    __tablename__ = "users"
    # id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(VARCHAR(255), primary_key=True)
    pass_hash: Mapped[str] = mapped_column(Text)
    salt: Mapped[str] = mapped_column(Text)
    passwd_last_modified: Mapped[float] = mapped_column(Float, default=0, nullable=False)
    nickname: Mapped[Optional[str]] = mapped_column(VARCHAR(255), nullable=True)
    last_login: Mapped[Optional[float]] = mapped_column(Float)
    created_time: Mapped[Optional[float]] = mapped_column(Float, nullable=False)

    # 这是对应每个用户的 secret_key. 每次更改密码时将重新生成，如果该属性不为空，则在验证 token 时使用此
    # 密钥，否则，使用从 config.toml 加载的全局密钥。
    secret_key: Mapped[str] = mapped_column(
        VARCHAR(32), default=secrets.token_hex(32), nullable=True
    )

    groups: Mapped[List["UserMembership"]] = relationship(
        "UserMembership", back_populates="user"
    )
    rights: Mapped[List["UserPermission"]] = relationship(
        "UserPermission", back_populates="user"
    )

    block_entries: Mapped[List["UserBlockEntry"]] = relationship(
        "UserBlockEntry", back_populates="user"
    )
    audit_entries: Mapped[List["AuditEntry"]] = relationship(
        "AuditEntry", back_populates="user"
    )

    def __repr__(self) -> str:
        return (
            f"User(username={self.username!r}, "
            f"nickname={self.nickname!r}, last_login={self.last_login!r}, "
            f"created_time={self.created_time!r})"
        )

    def authenticate_and_create_token(self, plain_password: str) -> Optional[Token]:
        salted = plain_password + self.salt
        password_hash = hashlib.sha256(salted.encode("utf-8")).hexdigest()
        if password_hash == self.pass_hash:
            secret = (
                global_config["server"]["secret_key"]
                if not self.secret_key
                else self.secret_key
            )
            token = Token(secret, self.username)
            token.new(3600)

            session = object_session(self)
            if session is not None:
                self.last_login = time.time()
                session.add(self)
                session.commit()
            return token
        return

    def is_token_valid(self, token: str) -> bool:
        """
        验证JWT令牌的有效性。
        如果令牌有效且未过期，返回True；否则返回False。
        """
        try:
            payload = jwt.decode(
                token,
                (
                    global_config["server"]["secret_key"]
                    if not self.secret_key
                    else self.secret_key
                ),
                algorithms=["HS256"],
            )
            return payload.get("username") == self.username
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            return False

    def renew_token(self) -> Token:
        """
        重新生成用户的JWT令牌。
        """

        secret = (
            global_config["server"]["secret_key"]
            if not self.secret_key
            else self.secret_key
        )
        new_token = Token(secret, self.username)
        new_token.new(3600)

        return new_token

    def set_password(self, plain_password: str):
        """
        修改用户密码，自动生成新盐并保存哈希，写入数据库。
        """
        self.salt = os.urandom(16).hex()
        salted = plain_password + self.salt
        self.pass_hash = hashlib.sha256(salted.encode("utf-8")).hexdigest()

        self.secret_key = os.urandom(64).hex()  # int/2
        self.passwd_last_modified = time.time()

        # 写入数据库
        session = object_session(self)
        if session is not None:
            session.add(self)
            session.commit()

    @property
    def all_groups(self):
        """
        获取用户所有有效的用户组名称集合。
        """
        now = time.time()
        return {
            membership.group_name
            for membership in self.groups
            if (membership.start_time is None or membership.start_time <= now)
            and (membership.end_time is None or membership.end_time >= now)
        }

    @all_groups.setter
    def all_groups(self, new_group_list: list[str]):
        session = object_session(self)
        if not session:
            raise RuntimeError()

        for old_group in self.groups:
            session.delete(old_group)
        self.groups.clear()
        for group_name in new_group_list:
            membership = UserMembership(
                user=self, group_name=group_name, start_time=time.time(), end_time=None
            )
            session.add(membership)
            self.groups.append(membership)
        # session.commit()

    @property
    def all_permissions(self) -> Set[str]:
        now = time.time()
        # 用户自身有效权限
        user_perms = {
            perm.permission
            for perm in self.rights
            if perm.granted and (perm.end_time is None or perm.end_time >= now)
        }
        # 用户组有效权限与剥夺权限
        group_granted_perms = set()
        group_revoked_perms = set()
        for membership in getattr(self, "groups", []):
            membership: UserMembership
            # 检查用户组的起止时间
            if membership.start_time is not None and membership.start_time > now:
                continue  # 尚未生效
            if membership.end_time is not None and membership.end_time < now:
                continue  # 已过期

            # 查找组权限
            if hasattr(membership, "group_name"):
                with Session() as session:
                    group = session.get(UserGroup, membership.group_name)
                    if group:
                        for perm in group.permissions:
                            if perm.end_time is None or perm.end_time >= now:
                                if perm.granted:
                                    group_granted_perms.add(perm.permission)
                                else:
                                    group_revoked_perms.add(perm.permission)

            else:
                raise ValueError(
                    f"UserMembership {membership.id} does not have a valid group_name attribute."
                )
        # 合并
        all_perms = user_perms | group_granted_perms
        # 再减去被剥夺的权限（包括用户自身和用户组）
        revoked_perms = {
            perm.permission
            for perm in self.rights
            if not perm.granted and (perm.end_time is None or perm.end_time >= now)
        }
        revoked_perms |= group_revoked_perms
        return (all_perms - revoked_perms) if (all_perms or revoked_perms) else set()


# 用户权限表，支持权限的给予/剥夺及持续时间
class UserPermission(Base):
    __tablename__ = "user_permissions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(ForeignKey("users.username"))
    permission: Mapped[str] = mapped_column(VARCHAR(255))
    granted: Mapped[bool] = mapped_column(
        Boolean, default=True
    )  # True: 给予, False: 剥夺
    start_time: Mapped[Optional[float]] = mapped_column(
        Float, nullable=False
    )  # 权限生效时间（时间戳）
    end_time: Mapped[Optional[float]] = mapped_column(
        Float, nullable=True
    )  # 权限失效时间（时间戳）
    user: Mapped["User"] = relationship("User", back_populates="rights")

    def __repr__(self) -> str:
        return (
            f"UserPermission(id={self.id!r}, username={self.username!r}, "
            f"permission={self.permission!r}, granted={self.granted!r}, "
            f"start_time={self.start_time!r}, end_time={self.end_time!r})"
        )


@event.listens_for(User, "load")
def filter_permissions_on_load(target, context):
    now = time.time()
    # 只保留granted=True且未过期的权限
    valid_permissions = []
    session = object_session(target)
    for perm in list(target.rights):
        if not perm.granted or (perm.end_time is not None and perm.end_time < now):
            # 从数据库中永久删除过期或被剥夺的权限
            if session is not None:
                session.delete(perm)
        else:
            valid_permissions.append(perm)
    target.rights = valid_permissions


# 用户所属组，包括在此用户组中的持续时间
class UserMembership(Base):
    __tablename__ = "user_memberships"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(ForeignKey("users.username"))
    group_name: Mapped[str] = mapped_column(ForeignKey("user_groups.group_name"))
    start_time: Mapped[float] = mapped_column(Float, nullable=False)  # 加入组的时间戳
    end_time: Mapped[Optional[float]] = mapped_column(
        Float, nullable=True
    )  # 离开组的时间戳
    user: Mapped["User"] = relationship("User", back_populates="groups")

    def __repr__(self) -> str:
        return (
            f"UserMembership(id={self.id!r}, username={self.username!r}, "
            f"group_name={self.group_name!r}, start_time={self.start_time!r}, "
            f"end_time={self.end_time!r})"
        )


@event.listens_for(User.groups, "append", retval=True)
def filter_expired_group(user, group, initiator):
    now = time.time()
    if group.end_time is not None and group.end_time < now:
        return None  # 不添加
    return group


class UserGroup(Base):
    __tablename__ = "user_groups"
    group_name: Mapped[str] = mapped_column(VARCHAR(255), primary_key=True)
    group_display_name: Mapped[Optional[str]] = mapped_column(
        VARCHAR(128), nullable=True
    )

    permissions: Mapped[List["UserGroupPermission"]] = relationship(
        "UserGroupPermission", back_populates="group"
    )

    @property
    def all_permissions(self) -> Set[str]:
        """
        该属性的实现是对 User.all_permissions 的复制。
        """

        now = time.time()
        # 用户组自身有效权限
        group_granted_perms = {
            perm.permission
            for perm in self.permissions
            if perm.granted and (perm.end_time is None or perm.end_time >= now)
        }
        # 用户组剥夺权限
        group_revoked_perms = set()

        for perm in self.permissions:
            if perm.end_time is None or perm.end_time >= now:
                if perm.granted:
                    group_granted_perms.add(perm.permission)
                else:
                    group_revoked_perms.add(perm.permission)
        # 合并
        all_perms = group_granted_perms
        # 再减去被剥夺的权限
        return (
            (all_perms - group_revoked_perms)
            if (all_perms or group_revoked_perms)
            else set()
        )

    @all_permissions.setter
    def all_permissions(self, new_permission_list: list[str]):
        session = object_session(self)
        if not session:
            raise RuntimeError()

        for old_permission in self.permissions:
            session.delete(old_permission)
        self.permissions.clear()
        for new_permission in new_permission_list:
            permission = UserGroupPermission(
                group=self,
                group_name=self.group_name,
                permission=new_permission,
                start_time=time.time(),
                end_time=None,
            )
            session.add(permission)
            self.permissions.append(permission)

    @property
    def members(self) -> set[str]:
        session = object_session(self)
        if not session:
            raise RuntimeError("No active object session found")

        now = time.time()
        _members = set()
        for membership in (
            session.query(UserMembership)
            .filter(UserMembership.group_name == self.group_name)
            .all()
        ):
            if membership.end_time is None or membership.end_time >= now:
                _members.add(membership.username)

        return _members

    def __repr__(self) -> str:
        return (
            f"UserGroup(group_name={self.group_name!r}, "
            f"permissions={self.permissions!r})"
        )


# 用户组权限表，支持权限的给予/剥夺及持续时间
class UserGroupPermission(Base):
    __tablename__ = "group_permissions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    group_name: Mapped[str] = mapped_column(ForeignKey("user_groups.group_name"))
    permission: Mapped[str] = mapped_column(VARCHAR(255))
    granted: Mapped[bool] = mapped_column(
        Boolean, default=True
    )  # True: 给予, False: 剥夺
    start_time: Mapped[Optional[float]] = mapped_column(
        Float, nullable=False, default=0.0
    )  # 权限生效时间（时间戳）
    end_time: Mapped[Optional[float]] = mapped_column(
        Float, nullable=True
    )  # 权限失效时间（时间戳）
    group: Mapped["UserGroup"] = relationship("UserGroup", back_populates="permissions")

    def __repr__(self) -> str:
        return (
            f"UserGroupPermission(id={self.id!r}, group_name={self.group_name!r}, "
            f"permission={self.permission!r}, granted={self.granted!r}, "
            f"start_time={self.start_time!r}, end_time={self.end_time!r})"
        )


class AuditEntry(Base):  # 审计条目
    __tablename__ = "audit_entries"
    id: Mapped[str] = mapped_column(
        VARCHAR(255), primary_key=True, default=lambda: secrets.token_hex(32)
    )
    action: Mapped[str] = mapped_column(VARCHAR(255), nullable=False)
    username: Mapped[str] = mapped_column(ForeignKey("users.username"), nullable=True)
    user: Mapped[User] = relationship("User", back_populates="audit_entries")
    target: Mapped[str] = mapped_column(VARCHAR(255), nullable=True)
    data: Mapped[dict] = mapped_column(JSON, nullable=True)
    result: Mapped[int] = mapped_column(Integer, nullable=False)
    remote_address: Mapped[Optional[str]] = mapped_column(VARCHAR(64), nullable=True)
    logged_time: Mapped[Optional[float]] = mapped_column(
        Float, nullable=False, default=time.time
    )


class ObjectAccessEntry(Base):
    """
    Model for `User`/`UserGroup` access.
    """

    __tablename__ = "object_access_entries"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # User / UserGroup
    entity_type: Mapped[str] = mapped_column(VARCHAR(16), nullable=False)
    entity_identifier: Mapped[str] = mapped_column(VARCHAR(255), nullable=False)

    # Document / Folder
    target_type: Mapped[str] = mapped_column(VARCHAR(16), nullable=False)
    target_identifier: Mapped[str] = mapped_column(VARCHAR(255), nullable=False)

    # read, write, move
    access_type: Mapped[str] = mapped_column(VARCHAR(16), nullable=False)

    start_time: Mapped[Optional[float]] = mapped_column(Float, nullable=False)
    end_time: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
