import secrets
from sqlalchemy import VARCHAR, Float, ForeignKey, Table, Column, Integer, Text
from include.database.handler import Base, Session
from include.conf_loader import global_config
from typing import List
from typing import Optional
from typing import Set
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
import os, sys


class NoActiveRevisionsError(RuntimeError):
    pass


class User(Base):
    __tablename__ = "users"
    # id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(VARCHAR(255), primary_key=True)
    pass_hash: Mapped[str] = mapped_column(Text)
    salt: Mapped[str] = mapped_column(Text)
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
            payload = {"username": self.username, "exp": time.time() + 3600}
            token = jwt.encode(
                payload,
                (
                    global_config["server"]["secret_key"]
                    if not self.secret_key
                    else self.secret_key
                ),
                algorithm="HS256",
            )
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

    def renew_token(self) -> Optional[str]:
        """
        重新生成用户的JWT令牌。
        """
        payload = {
            "username": self.username,
            "exp": time.time() + 3600,  # 令牌有效期为1小时
        }
        token = jwt.encode(
            payload,
            (
                global_config["server"]["secret_key"]
                if not self.secret_key
                else self.secret_key
            ),
            algorithm="HS256",
        )
        return token

    def set_password(self, plain_password: str):
        """
        修改用户密码，自动生成新盐并保存哈希，写入数据库。
        """
        self.salt = os.urandom(16).hex()
        salted = plain_password + self.salt
        self.pass_hash = hashlib.sha256(salted.encode("utf-8")).hexdigest()

        self.secret_key = os.urandom(64).hex()  # int/2

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


class BaseObject(Base):
    __abstract__ = True

    access_rules: Mapped[List]

    def check_access_requirements(self, user: User, access_type=0) -> bool:
        """
        Checks if a given user meets the access requirements for a specific access type based on defined access rules.
        Args:
            user (User): The user object whose permissions and groups are to be checked.
            access_type (int, optional): The type of access to check for. Defaults to 0.
        Returns:
            bool: True if the user meets all access requirements for the specified access type, False otherwise.
        Raises:
            ValueError: If the "match" value in any rule is not "all" or "any".
        Access rules are evaluated as follows:
            - Each rule may specify required permissions ("rights") and/or groups ("groups").
            - Each requirement can specify a "match" mode: "all" (all required items must be present) or "any" (at least one must be present).
            - Rules are grouped and evaluated according to their match modes and requirements.
            - If no access rules are defined, access is granted by default.
        """

        def match_rights(sub_rights_group):
            if not sub_rights_group:
                return True

            sub_match_mode = sub_rights_group.get("match", "all")
            sub_rights_require = sub_rights_group.get("require", [])

            if not sub_rights_require:
                return True

            if sub_match_mode == "all":
                return set(sub_rights_require).issubset(user.all_permissions)

            elif sub_match_mode == "any":
                for right in sub_rights_require:
                    if right in user.all_permissions:
                        return True
                return False

            else:
                raise ValueError('the value of "match" must be "all" or "any"')

        def match_groups(sub_groups_group):
            if not sub_groups_group:
                return True

            sub_match_mode = sub_groups_group.get("match", "all")
            sub_groups_require = sub_groups_group.get("require", [])

            if not sub_groups_require:
                return True

            if sub_match_mode == "all":
                return set(sub_groups_require).issubset(user.all_groups)

            elif sub_match_mode == "any":
                for group in sub_groups_require:
                    if group in user.all_groups:
                        return True
                return False
            else:
                raise ValueError('the value of "match" must be "all" or "any"')

        def match_sub_group(sub_group):
            sub_match_mode = sub_group.get("match", "all")
            sub_rights_group = sub_group.get("rights", {})
            sub_groups_group = sub_group.get("groups", {})

            if not (sub_rights_group.get("require", [])) or (
                not sub_groups_group.get("require", [])
            ):
                sub_match_mode = "all"

            if sub_match_mode == "any":
                return match_rights(sub_rights_group) or match_groups(sub_groups_group)
            if sub_match_mode == "all":
                return match_rights(sub_rights_group) and match_groups(sub_groups_group)
            else:
                raise ValueError('the value of "match" must be "all" or "any"')

        def match_primary_sub_group(per_match_group):
            match_mode = per_match_group.get("match", "all")
            for sub_group in per_match_group["match_groups"]:
                if not sub_group:
                    continue

                state = match_sub_group(sub_group)

                if match_mode == "any":
                    if state:
                        return True
                elif match_mode == "all":
                    if not state:
                        return False

            if match_mode == "any":
                return False
            elif match_mode == "all":
                return True

        if not self.access_rules:
            return True

        for each_rule in self.access_rules:
            if not each_rule:
                continue

            if access_type == 0:  # 如果要检查的是读权限
                if each_rule.access_type != 0:
                    continue
            elif access_type == 1:  # 如果要检查写权限
                if each_rule.access_type not in [0, 1]:
                    continue
            elif access_type == 2:  # 如果要检查管理权限
                if each_rule.access_type not in [0, 2]:
                    continue

            if not match_primary_sub_group(each_rule.rule_data):
                return False

        return True


class Folder(BaseObject):  # 文档文件夹
    __tablename__ = "folders"
    id: Mapped[str] = mapped_column(
        VARCHAR(255), primary_key=True, default=lambda: secrets.token_hex(32)
    )
    name: Mapped[str] = mapped_column(VARCHAR(255), nullable=False)  # 文件夹名称
    created_time: Mapped[float] = mapped_column(
        Float, nullable=False, default=lambda: time.time()
    )
    parent_id: Mapped[Optional[str]] = mapped_column(
        VARCHAR(255), ForeignKey("folders.id")
    )  # 父文件夹ID
    parent: Mapped["Folder"] = relationship(
        "Folder", back_populates="children", remote_side=[id]
    )
    children: Mapped[List["Folder"]] = relationship("Folder", back_populates="parent")
    access_rules: Mapped[List["FolderAccessRule"]] = relationship(
        "FolderAccessRule", back_populates="folder", cascade="all, delete-orphan"
    )
    documents: Mapped[List["Document"]] = relationship(
        "Document", back_populates="folder"
    )

    @property
    def count_of_child(self):
        return len(self.children) + sum(1 for doc in self.documents if doc.active)

    def delete_all_children(self):
        session = object_session(self)
        if not session:
            raise Exception("The object is not associated with a session")

        if self.documents:
            for document in self.documents:
                document.delete_all_revisions()
                session.delete(document)
        self.documents.clear()

        if self.children:
            for child in self.children:
                child.delete_all_children()
                session.delete(child)
        self.children.clear()

        session.commit()


class Document(BaseObject):
    __tablename__ = "documents"
    id: Mapped[str] = mapped_column(
        VARCHAR(255), primary_key=True, default=lambda: secrets.token_hex(32)
    )
    title: Mapped[Optional[str]] = mapped_column(
        VARCHAR(255), nullable=False, default="Untitled Document"
    )  # 文档名称
    created_time: Mapped[float] = mapped_column(
        Float, nullable=False, default=lambda: time.time()
    )
    folder_id: Mapped[Optional[str]] = mapped_column(
        VARCHAR(255), ForeignKey("folders.id"), nullable=True
    )  # 文档所属文件夹ID
    folder: Mapped["Folder"] = relationship("Folder", back_populates="documents")

    # 每个文档有多个访问规则（AccessRule对象），以JSON格式存储规则数据
    access_rules: Mapped[List["DocumentAccessRule"]] = relationship(
        "DocumentAccessRule", back_populates="document", cascade="all, delete-orphan"
    )

    # 每个文档有多个修订版本
    revisions: Mapped[List["DocumentRevision"]] = relationship(
        "DocumentRevision",
        back_populates="document",
        order_by="DocumentRevision.created_time",
    )

    @property
    def active(self):
        try:
            self.get_latest_revision()
        except (RuntimeError, NoActiveRevisionsError):
            return False
        return True

    def get_latest_revision(self):
        """
        获取最新的修订版本（按created_time降序排列的第一个），且revision.active为True。
        """
        if not self.revisions:
            raise RuntimeError("A document cannot have no revisions.")

        # 过滤出active为True的修订版本
        active_revisions = [rev for rev in self.revisions if rev.active]

        if not active_revisions:
            raise NoActiveRevisionsError("No active revisions found.")

        return max(active_revisions, key=lambda rev: rev.created_time)

    def delete_all_revisions(self):
        session = object_session(self)
        if not session:
            raise Exception("The object is not associated with a session")

        for revision in self.revisions:
            revision.file
            # 检查该File对象是否被其他revision引用
            other_refs = (
                session.query(DocumentRevision)
                .filter(DocumentRevision.file_id == revision.file_id)
                .filter(DocumentRevision.id != revision.id)
                .count()
            )
            if other_refs == 0:
                try:
                    revision.file.delete()
                except PermissionError:
                    raise
                session.delete(revision.file)
            session.delete(revision)

        self.revisions.clear()
        session.commit()

    def __repr__(self) -> str:
        return f"Document(id={self.id!r}, created_time={self.created_time!r})"


class DocumentRevision(Base):
    __tablename__ = "document_revisions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    document_id: Mapped[str] = mapped_column(ForeignKey("documents.id"))
    file_id: Mapped[str] = mapped_column(ForeignKey("files.id"))
    created_time: Mapped[float] = mapped_column(
        Float, nullable=False, default=lambda: time.time()
    )
    # active: Mapped[bool] = mapped_column(
    #     Boolean, nullable=False, default=False
    # )  # 文件实际上传后激活

    document: Mapped["Document"] = relationship("Document", back_populates="revisions")
    file: Mapped["File"] = relationship(
        "File", primaryjoin="DocumentRevision.file_id == File.id"
    )

    @property
    def active(self):
        return self.file.active

    def __repr__(self) -> str:
        return (
            f"DocumentRevision(id={self.id!r}, document_id={self.document_id!r}, "
            f"file={self.file!r}, created_time={self.created_time!r})"
        )


class DocumentAccessRule(Base):
    __tablename__ = "document_access_rules"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    access_type: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="0: read, 1: write",  # rename is regarded as write
    )
    document_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("documents.id"), nullable=False
    )
    rule_data: Mapped[dict] = mapped_column(
        JSON, nullable=False
    )  # 存储单个Json格式的规则数据

    document: Mapped[Optional["Document"]] = relationship(
        "Document", back_populates="access_rules"
    )

    def __repr__(self) -> str:
        return f"AccessRule(id={self.id!r}, document_id={self.document_id!r}, rule_data={self.rule_data!r})"


class FolderAccessRule(Base):
    __tablename__ = "folder_access_rules"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    access_type: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="0: read, 1: write",  # rename is regarded as write
    )
    folder_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("folders.id"), nullable=True
    )
    rule_data: Mapped[dict] = mapped_column(
        JSON, nullable=False
    )  # 存储单个Json格式的规则数据

    folder: Mapped[Optional["Document"]] = relationship(
        "Folder", back_populates="access_rules"
    )

    def __repr__(self) -> str:
        return f"FolderAccessRule(id={self.id!r}, folder_id={self.folder_id!r}, rule_data={self.rule_data!r})"


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
        try:
            os.remove(self.path)
        except (OSError, PermissionError):
            if os.path.exists(self.path):
                raise

    def __repr__(self) -> str:
        return f"File(id={self.id!r}, file_path={self.path!r}, created_time={self.created_time!r})"


class FileTask(Base):
    __tablename__ = "file_tasks"
    id: Mapped[str] = mapped_column(
        VARCHAR(255), primary_key=True, default=lambda: secrets.token_hex(32)
    )
    file_id: Mapped[str] = mapped_column(VARCHAR(255), nullable=False)
    # 0: 等待中, 1: 已完成, 2: 已取消
    status: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    mode: Mapped[int] = mapped_column(
        Integer, nullable=False, comment="0: download, 1: upload"
    )
    start_time: Mapped[float] = mapped_column(Float, nullable=False)
    end_time: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    # created_time: Mapped[float] = mapped_column(
    #     Float, nullable=False, default=lambda: time.time()
    # )

    def __repr__(self) -> str:
        return (
            f"FileTask(id={self.id!r}, "
            f"file_id={self.file_id!r}, status={self.status!r})"
        )
