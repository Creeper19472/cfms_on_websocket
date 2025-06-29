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
    """
    Create a new user in the system.
    This function generates a random salt, hashes the provided password with the salt,
    and creates a user record along with associated permissions and group memberships.
    Args:
        **kwargs: Arbitrary keyword arguments that may include:
            - username (str): The username for the new user.
            - password (str): The password for the new user.
            - nickname (str, optional): The nickname for the new user.
            - permissions (list, optional): A list of dictionaries representing user permissions,
              where each dictionary may contain:
                - permission (str): The permission to be granted.
                - granted (bool, optional): Whether the permission is granted (default is True).
                - start_time (float, optional): The start time for the permission (default is current time).
                - end_time (float, optional): The end time for the permission (default is None).
            - groups (list, optional): A list of dictionaries representing user group memberships,
              where each dictionary may contain:
                - group_name (str): The name of the group.
                - start_time (float, optional): The start time for the membership (default is current time).
                - end_time (float, optional): The end time for the membership (default is None).
    Returns:
        None: This function does not return a value. It commits the new user to the database.
    """
    
    # 随机生成8位salt
    alphabet = string.ascii_letters + string.digits
    salt = "".join(secrets.choice(alphabet) for i in range(8))  # 安全化

    salted_pwd = get_passwd_sha256(kwargs["password"], salt)
    with Session() as session:
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

        session.add(user)
        session.commit()
