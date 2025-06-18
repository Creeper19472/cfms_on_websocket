import string, secrets, hashlib
import time
from include.database.models import User, UserMembership, UserPermission
from include.database.handler import Session


def get_passwd_sha256(password: str, salt: str) -> str:
    # 使用SHA-256算法加密密码
    sha256 = hashlib.sha256()
    sha256.update((password + salt).encode("utf-8"))
    return sha256.hexdigest()


def create_user(**kwargs) -> None:
    # 随机生成8位salt
    alphabet = string.ascii_letters + string.digits
    salt = "".join(secrets.choice(alphabet) for i in range(8))  # 安全化

    salted_pwd = get_passwd_sha256(kwargs["password"], salt)
    user = User(
        username=kwargs["username"],
        pass_hash=salted_pwd,
        salt=salt,
        nickname=kwargs.get("nickname", None),
        last_login=0,
        created_time=time.time(),
    )
    for i in kwargs.get("permissions", []):
        permission = UserPermission(
            user=user,
            permission=i["permission"],
            granted=i.get("granted", True),
            start_time=i.get("start_time", time.time()),
            end_time=i.get("end_time", None)
        )
        user.rights.append(permission)

    for k in kwargs.get("groups", []):
        membership = UserMembership(
            user=user,
            group_name=k["group_name"],
            start_time=k.get("start_time", time.time()),
            end_time=k.get("end_time", None)
        )
        user.groups.append(membership)

    with Session() as session:
        session.add(user)
        session.commit()
