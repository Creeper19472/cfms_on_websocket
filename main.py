import os
from include.conf_loader import global_config
from include.database.handler import engine, Base
from include.database.handler import Session
from include.classes.version import Version
from include.database.models import User, UserGroup

CORE_VERSION = Version("0.0.1.250616_alpha")

if not os.path.exists("./init"):
    Base.metadata.create_all(engine)

    session = Session()

    # 创建 sysop 用户组，并赋予 shutdown 权限
    sysop_group = UserGroup(group_name="sysop")
    sysop_group.permissions = {
        "shutdown": {"granted": True, "start_time": 0, "end_time": None},
        }
    session.add(sysop_group)
    session.commit()
    session.close()

    from include.function.user import create_user
    create_user(
        username="admin",
        password="123456",
        nickname="管理员",
        permissions=[],
        groups=[
            {"group": "sysop"}
        ]
    )

    with open("./init", "w") as f:
        f.write("This file indicates that the database has been initialized.\n")

with Session() as session:
    test_user = session.query(User).filter_by(id=1).first()

    print(test_user.username)
    print(test_user.all_permissions)


