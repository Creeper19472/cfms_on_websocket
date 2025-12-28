from typing import List
from typing import Optional
from typing import TYPE_CHECKING

import secrets
from sqlalchemy import VARCHAR, Float, ForeignKey, Integer
from include.classes.exceptions import NoActiveRevisionsError
from include.constants import AVAILABLE_ACCESS_TYPES, AVAILABLE_BLOCK_TYPES
from include.database.handler import Base
from include.classes.access_rule import AccessRuleBase
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from sqlalchemy.orm import relationship
import time
from sqlalchemy.orm.session import object_session
from sqlalchemy import JSON

from include.database.models.file import File
from include.database.models.classic import User, ObjectAccessEntry
from include.database.models.blocking import UserBlockEntry, UserBlockSubEntry


class BaseObject(Base):
    __abstract__ = True

    id: Mapped[str]
    access_rules: Mapped[List]

    def get_password_protection(self):
        """
        Get the password protection entry for this object, if any.
        
        Returns:
            PasswordProtection object if password protected, None otherwise
        """
        from include.database.models.protection import PasswordProtection
        from include.constants import TARGET_TYPE_MAPPING
        
        session = object_session(self)
        if not session:
            raise RuntimeError("No active session found for object")
        
        target_type = TARGET_TYPE_MAPPING[self.__tablename__]
        
        protection = (
            session.query(PasswordProtection)
            .filter(
                PasswordProtection.target_type == target_type,
                PasswordProtection.target_id == self.id
            )
            .first()
        )
        
        return protection
    
    def is_password_protected(self) -> bool:
        """
        Check if this object is password protected.
        
        Returns:
            True if password protected, False otherwise
        """
        return self.get_password_protection() is not None
    
    def verify_password(self, password: Optional[str]) -> bool:
        """
        Verify the provided password against the stored password.
        
        Args:
            password: The password to verify (None if not provided)
            
        Returns:
            True if password is correct or object is not protected,
            False if password is incorrect or missing when required
        """
        protection = self.get_password_protection()
        
        if not protection:
            # Not password protected, access granted
            return True
        
        if password is None:
            # Password required but not provided
            return False
        
        # Verify the password
        return protection.verify_password(password)

    def check_access_requirements(self, user: User, access_type: str = "read") -> bool:
        """
        Checks if a given user meets the access requirements for a specific access type based on defined access rules.
        Args:
            user (User): The user object whose permissions and groups are to be checked.
            access_type (int, optional): The type of access to check for. Defaults to `"read"`.
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

        from include.constants import TARGET_TYPE_MAPPING

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

        # Checks whether the user or the user group to which he belongs
        # has special access rights to this object.

        # Get `session` from `User` object
        _session = object_session(user)
        if not _session:
            raise RuntimeError("No active session found for user")

        now = time.time()

        # check user blocks first
        if access_type in AVAILABLE_BLOCK_TYPES:
            block_entries = (
                _session.query(UserBlockEntry)
                .filter(
                    UserBlockEntry.username == user.username,
                    UserBlockEntry.expiry >= time.time(),
                )
                .all()
            )
            for entry in block_entries:
                filtered_sub_entries = (
                    _session.query(UserBlockSubEntry)
                    .filter(
                        UserBlockSubEntry.parent_id == entry.block_id,
                        UserBlockSubEntry.block_type == access_type,
                    )
                    .all()
                )
                if filtered_sub_entries:
                    return False

        # then check special access entries
        user_access_entries = (
            _session.query(ObjectAccessEntry)
            .filter(
                ObjectAccessEntry.entity_type == "user",
                ObjectAccessEntry.entity_identifier == user.username,
                ObjectAccessEntry.target_type
                == TARGET_TYPE_MAPPING[self.__tablename__],
                ObjectAccessEntry.target_identifier == self.id,
                ObjectAccessEntry.access_type == access_type,
                ObjectAccessEntry.start_time <= now,
                (
                    (ObjectAccessEntry.end_time == None)
                    | (ObjectAccessEntry.end_time >= now)
                ),
            )
            .all()
        )
        if user_access_entries:
            return True

        for group in user.groups:
            group_access_entries = (
                _session.query(ObjectAccessEntry)
                .filter(
                    ObjectAccessEntry.entity_type == "group",
                    ObjectAccessEntry.entity_identifier == group.group_name,
                    ObjectAccessEntry.target_type
                    == TARGET_TYPE_MAPPING[self.__tablename__],
                    ObjectAccessEntry.target_identifier == self.id,
                    ObjectAccessEntry.access_type == access_type,
                    ObjectAccessEntry.start_time <= now,
                    (
                        (ObjectAccessEntry.end_time == None)
                        | (ObjectAccessEntry.end_time >= now)
                    ),
                )
                .all()
            )
            if group_access_entries:
                return True

        if not self.access_rules:
            return True

        for each_rule in self.access_rules:
            if not each_rule:
                continue

            each_rule: AccessRuleBase

            # access_type 一览：
            # read - 读
            # write - 写（删除=清空数据，重命名=写文件元数据，因此都算写）
            # move - 移动
            # manage - 管理

            if access_type not in AVAILABLE_ACCESS_TYPES:
                raise ValueError(
                    f"Invaild access type for {self.__tablename__}: {access_type}"
                )

            match access_type:
                case "read":  # 如果要检查的是读权限
                    if each_rule.access_type != "read":
                        continue
                case "write":  # 如果要检查写权限
                    if each_rule.access_type not in ["read", "write"]:
                        continue
                case "move":
                    # 取消了对读权限的要求
                    if each_rule.access_type != "move":
                        continue
                case "manage":  # 如果要检查管理权限
                    if each_rule.access_type not in ["read", "manage"]:
                        continue
                case _:
                    raise NotImplementedError("Unsupported access type")

            if not each_rule.rule_data:
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
    parent: Mapped[Optional["Folder"]] = relationship(
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

    def is_descendant_of(self, potential_ancestor: "Folder") -> bool:
        """
        Check if this folder is a descendant of the given potential ancestor folder.

        Args:
            potential_ancestor: The folder to check if it's an ancestor

        Returns:
            True if this folder is a descendant of potential_ancestor, False otherwise
        """
        current = self.parent
        visited_ids = set()
        while current is not None:
            # Detect cycles in the parent chain to avoid infinite loops
            if current.id == potential_ancestor.id:
                return True
            if current.id in visited_ids:
                # Cycle detected; break to prevent an infinite loop
                break
            visited_ids.add(current.id)
            current = current.parent
        return False

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
    folder: Mapped[Optional["Folder"]] = relationship(
        "Folder", back_populates="documents"
    )

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
            # revision.file
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
    """
    This class implemented a model for document revisions.

    A document revision is a historical version of the document,
    should only be written once and not changed.
    """

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

    @property
    def writeable(self):
        return self.file.writeable

    def __repr__(self) -> str:
        return (
            f"DocumentRevision(id={self.id!r}, document_id={self.document_id!r}, "
            f"file={self.file!r}, created_time={self.created_time!r})"
        )


class DocumentAccessRule(Base, AccessRuleBase):
    __tablename__ = "document_access_rules"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    access_type: Mapped[str] = mapped_column(
        VARCHAR(64),
        nullable=False,
        default="read",
        # comment="0: read, 1: write",  # rename is regarded as write
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
        return f"DocumentAccessRule(id={self.id!r}, document_id={self.document_id!r}, rule_data={self.rule_data!r})"


class FolderAccessRule(Base, AccessRuleBase):
    __tablename__ = "folder_access_rules"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    access_type: Mapped[str] = mapped_column(
        VARCHAR(64),
        nullable=False,
        default="read",
    )
    folder_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("folders.id"), nullable=True
    )
    rule_data: Mapped[dict] = mapped_column(
        JSON, nullable=False
    )  # 存储单个Json格式的规则数据

    folder: Mapped[Optional["Folder"]] = relationship(
        "Folder", back_populates="access_rules"
    )

    def __repr__(self) -> str:
        return f"FolderAccessRule(id={self.id!r}, folder_id={self.folder_id!r}, rule_data={self.rule_data!r})"