from include.database.models.entity import Document, Folder
from include.database.models.classic import User, ObjectAccessEntry
from include.classes.access_rule import AccessRuleBase
from include.constants import AVAILABLE_ACCESS_TYPES


def check_access_for_object(
    obj: Document | Folder,
    user: User,
    access_type: str,
    all_folders: list[Folder],
    oae_by_target: dict,
    recursive: bool = True,
) -> bool:
    """
    对单个文档或文件夹做完整的访问权限检查，包含逐级上溯。

    参数：
        obj           - 要检查的目标对象（Document 或 Folder）
        user          - 当前用户
        access_type   - 访问类型，如 "read" / "write" / "manage" / "move"
        all_folders   - 由 search_*_with_access 预取的所有祖先文件夹列表
        oae_by_target - 由 search_*_with_access 预取的 OAE 字典

    返回：
        True  - 用户有权访问
        False - 用户无权访问
    """
    if access_type not in AVAILABLE_ACCESS_TYPES:
        raise ValueError(f"Invalid access type: {access_type}")

    # 将 all_folders 转成以 id 为键的字典，方便后续 O(1) 查找
    folder_map = {f.id: f for f in all_folders}

    # ── 内部复用：对单个节点（文档或文件夹）做权限检查 ──────────────────────
    def _check_single_node(node: Document | Folder) -> bool:
        """
        检查单个节点（不含上溯），分三步：
          1. 查 OAE（特殊授权），命中则直接返回 True
          2. 若 access_rules 为空��默认放行
          3. 逐条检查 access_rules
        """
        _TARGET_TYPE_MAPPING = {"folders": "directory", "documents": "document"}
        target_type = _TARGET_TYPE_MAPPING[node.__tablename__]

        # ── Step 1：检查 OAE（特殊授权优先） ──────────────────────────────
        entries: list[ObjectAccessEntry] = oae_by_target.get(node.id, [])

        # 检查用户自身的 OAE
        for entry in entries:
            if (
                entry.entity_type == "user"
                and entry.entity_identifier == user.username
                and entry.target_type == target_type
                and entry.access_type == access_type
            ):
                return True

        # 检查用户所属组的 OAE
        user_groups = user.all_groups  # set[str]
        for entry in entries:
            if (
                entry.entity_type == "group"
                and entry.entity_identifier in user_groups
                and entry.target_type == target_type
                and entry.access_type == access_type
            ):
                return True

        # ── Step 2：access_rules 为空时默认放行 ───────────────────────────
        if not node.access_rules:
            return True

        # ── Step 3：逐条检查 access_rules ─────────────────────────────────
        for rule in node.access_rules:
            rule: AccessRuleBase
            if not rule.rule_data:
                continue

            # 根据 access_type 决定哪些 rule 参与检查（与原逻辑一致）
            match access_type:
                case "read":
                    if rule.access_type != "read":
                        continue
                case "write":
                    if rule.access_type not in ["read", "write"]:
                        continue
                case "move":
                    if rule.access_type != "move":
                        continue
                case "manage":
                    if rule.access_type not in ["read", "manage"]:
                        continue
                case _:
                    raise NotImplementedError(f"Unsupported access type: {access_type}")

            if not _match_primary_sub_group(rule.rule_data, user):
                return False

        return True

    # ── 主逻辑：先检查对象自身，再逐级上溯 ──────────────────────────────────

    # 1. 检查对象自身
    if not _check_single_node(obj):
        return False

    # 2. 如果对象不继承父级规则，直接结束
    if not recursive or not obj.inherit:
        return True

    # 3. 沿祖先链逐级上溯
    #    - Document 的直接父级是 folder_id 指向的 Folder
    #    - Folder   的直接父级是 parent_id 指向的 Folder
    if isinstance(obj, Document):
        current_folder_id = obj.folder_id
    else:  # Folder
        current_folder_id = obj.parent_id

    visited_ids = set()  # 防止万一数据库存在环形引用导致死循环

    while current_folder_id is not None:
        if current_folder_id in visited_ids:
            raise RuntimeError("Cycle detected in folder hierarchy")
        visited_ids.add(current_folder_id)

        current_folder = folder_map.get(current_folder_id)
        if current_folder is None:
            # 祖先数据不在预取结果里（理论上不应发生，除非调用方传入的 all_folders 不完整）
            break

        # 检查当前这一级
        if not _check_single_node(current_folder):
            return False

        # 如果这一级不继承，停止向上
        if not current_folder.inherit:
            break

        current_folder_id = current_folder.parent_id

    return True


# ── 规则匹配逻辑（从原 check_access_requirements 提取，保持完全一致） ──────────
def _match_primary_sub_group(rule_data: dict, user: User) -> bool:
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
            return any(r in user.all_permissions for r in sub_rights_require)
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
            return any(g in user.all_groups for g in sub_groups_require)
        else:
            raise ValueError('the value of "match" must be "all" or "any"')

    def match_sub_group(sub_group):
        sub_match_mode = sub_group.get("match", "all")
        sub_rights_group = sub_group.get("rights", {})
        sub_groups_group = sub_group.get("groups", {})
        if not sub_rights_group.get("require", []) or not sub_groups_group.get("require", []):
            sub_match_mode = "all"
        if sub_match_mode == "any":
            return match_rights(sub_rights_group) or match_groups(sub_groups_group)
        if sub_match_mode == "all":
            return match_rights(sub_rights_group) and match_groups(sub_groups_group)
        else:
            raise ValueError('the value of "match" must be "all" or "any"')

    match_mode = rule_data.get("match", "all")
    for sub_group in rule_data.get("match_groups", []):
        if not sub_group:
            continue
        state = match_sub_group(sub_group)
        if match_mode == "any" and state:
            return True
        if match_mode == "all" and not state:
            return False

    return match_mode == "all"