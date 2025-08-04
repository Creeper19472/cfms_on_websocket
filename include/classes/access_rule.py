__all__ = ["AccessRuleBase"]

from sqlalchemy.orm import Mapped

class AccessRuleBase():
    id: Mapped[int]
    access_type: Mapped[int]
    rule_data: Mapped[dict]