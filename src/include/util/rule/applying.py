from include.constants import AVAILABLE_ACCESS_TYPES
from include.database.models.classic import User
from include.database.models.entity import (
    Document,
    DocumentAccessRule,
    Folder,
    FolderAccessRule,
)
from include.util.rule.validation import validate_access_rules


def apply_access_rules(
    target: Document | Folder, set_access_rules: dict[str, list[dict]], user: User
) -> bool:
    """
    只对对象进行更改，而不进行提交。
    """
    if not set_access_rules:
        for rule in target.access_rules.copy():
            target.access_rules.remove(rule)  # pyright: ignore[reportArgumentType]

    for access_type in set_access_rules:
        if access_type not in AVAILABLE_ACCESS_TYPES:
            raise ValueError(f"Invalid access type: {access_type}")

        this_type_rules: list[dict] = set_access_rules[access_type]
        if this_type_rules is None:
            raise ValueError(
                f"Access rule data for access type {access_type} can't be null"
            )
        validate_access_rules(this_type_rules)

        for rule in target.access_rules.copy():
            if rule.access_type == access_type:
                target.access_rules.remove(rule)  # pyright: ignore[reportArgumentType]

        for each_rule in this_type_rules:
            if each_rule:
                if type(target) == Document:
                    this_new_rule = DocumentAccessRule(
                        document_id=target.id,
                        access_type=access_type,
                        rule_data=each_rule,
                    )
                elif type(target) == Folder:
                    this_new_rule = FolderAccessRule(
                        folder_id=target.id,
                        access_type=access_type,
                        rule_data=each_rule,
                    )
                else:
                    raise TypeError("Unsupported Object Type")
                target.access_rules.append(
                    this_new_rule  # pyright: ignore[reportArgumentType]
                )

        if not target.check_access_requirements(user, access_type):
            return False

    return True
