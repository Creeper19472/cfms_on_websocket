from sqlalchemy import VARCHAR, Float, ForeignKey, Table, Column, Integer, Text
from include.database.handler import Base, Session
from include.conf_loader import global_config
from typing import List
from typing import Optional
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from sqlalchemy.orm import relationship
from sqlalchemy import Boolean, BigInteger
from sqlalchemy import event
import time
from sqlalchemy.orm.session import object_session
from sqlalchemy import JSON
import jwt
import hashlib
import os


class User(Base):
    __tablename__ = "users"
    # id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(VARCHAR(255), primary_key=True)
    pass_hash: Mapped[str] = mapped_column(Text)
    salt: Mapped[str] = mapped_column(Text)
    nickname: Mapped[Optional[str]] = mapped_column(VARCHAR(255), nullable=True)
    last_login: Mapped[Optional[float]] = mapped_column(Float)
    created_time: Mapped[Optional[float]] = mapped_column(Float, nullable=False)

    groups: Mapped[List["UserMembership"]] = relationship(
        "UserMembership", back_populates="user"
    )
    rights: Mapped[List["UserPermission"]] = relationship(
        "UserPermission", back_populates="user"
    )

    def __repr__(self) -> str:
        return (
            f"User(username={self.username!r}, "
            f"nickname={self.nickname!r}, last_login={self.last_login!r}, "
            f"created_time={self.created_time!r})"
        )
    
    def authenticate_and_create_token(self, plain_password: str) -> Optional[str]:
        salted = plain_password + self.salt
        password_hash = hashlib.sha256(salted.encode("utf-8")).hexdigest()
        if password_hash == self.pass_hash:
            payload = {
                "username": self.username,
                "exp": time.time() + 3600
            }
            token = jwt.encode(payload, global_config["server"]["secret_key"], algorithm="HS256")
            return token
        session = object_session(self)
        if session is not None:
            self.last_login = time.time()
            session.add(self)
            session.commit()
        return
    
    def is_token_valid(self, token: str) -> bool:
        """
        验证JWT令牌的有效性。
        如果令牌有效且未过期，返回True；否则返回False。
        """
        try:
            payload = jwt.decode(token, global_config["server"]["secret_key"], algorithms=["HS256"])
            return payload.get("username") == self.username
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            return False
    
    def renew_token(self) -> Optional[str]:
        """
        重新生成用户的JWT令牌。
        """
        payload = {
            "username": self.username,
            "exp": time.time() + 3600  # 令牌有效期为1小时
        }
        token = jwt.encode(payload, global_config["server"]["secret_key"], algorithm="HS256")
        return token
    
    def set_password(self, plain_password: str):
        """
        修改用户密码，自动生成新盐并保存哈希，写入数据库。
        """
        self.salt = os.urandom(16).hex()
        salted = plain_password + self.salt
        self.pass_hash = hashlib.sha256(salted.encode("utf-8")).hexdigest()
        # 写入数据库
        session = object_session(self)
        if session is not None:
            session.add(self)
            session.commit()
    


    @property
    def all_permissions(self):
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
                    if group and group.permissions:
                        for perm, info in group.permissions.items():
                            if info.get("start_time", 0) > now:
                                continue
                            if (
                                info.get("end_time") is not None
                                and info["end_time"] < now
                            ):
                                continue
                            (
                                group_granted_perms
                                if info.get("granted", True)
                                else group_revoked_perms
                            ).add(perm)
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
        return all_perms - revoked_perms


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


# 监听权限添加事件，若权限被剥夺或已过期则不添加
@event.listens_for(User.rights, "append", retval=True)
def filter_revoked_or_expired_permission(user, permission, initiator):
    now = time.time()
    if not permission.granted:
        return None  # 不添加被剥夺的权限
    if permission.end_time is not None and permission.end_time < now:
        return None  # 不添加已过期的权限
    return permission


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


@event.listens_for(User.rights, "append")
def set_username_on_permission(user, permission, initiator):
    if getattr(permission, "username", None) is None:
        permission.username = user.username


# 用户所属组，包括在此用户组中的持续时间
class UserMembership(Base):
    __tablename__ = "user_memberships"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[int] = mapped_column(ForeignKey("users.username"))
    group_name: Mapped[str] = mapped_column(ForeignKey("user_groups.group_name"))
    start_time: Mapped[Optional[float]] = mapped_column(
        Float, nullable=False
    )  # 加入组的时间戳
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
    group_name: Mapped[str] = mapped_column(
        VARCHAR(255), primary_key=True, unique=True, nullable=False
    )
    # permissions字段存储为JSON字符串，内容为权限字典

    permissions: Mapped[dict] = mapped_column(
        JSON, nullable=False, default=dict, server_default="{}"
    )

    def __repr__(self) -> str:
        return (
            f"UserGroup(group_name={self.group_name!r}, "
            f"permissions={self.permissions!r})"
        )


# class UserMeta(Base):
#     __tablename__ = "usermeta"
#     id: Mapped[int] = mapped_column(primary_key=True)
#     email_address: Mapped[str]
#     user_id = mapped_column(ForeignKey("user.id"))
#     user: Mapped[User] = relationship(back_populates="addresses")
#     def __repr__(self) -> str:
#         return f"Address(id={self.id!r}, email_address={self.email_address!r})"
