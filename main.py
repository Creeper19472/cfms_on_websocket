"""
Main entry point for initializing and testing the CFMS WebSocket application.
- Checks for the existence of an initialization file ("./init") to determine if the database needs to be set up.
- If not initialized:
    - Creates all database tables using SQLAlchemy's metadata.
    - Creates a default "sysop" user group with "shutdown" permission.
    - Adds an "admin" user with the "sysop" group.
    - Writes an "init" file to indicate initialization is complete.
- After initialization (or if already initialized):
    - Opens a database session and queries for the user with ID 1.
    - If the user exists, prints the username and all permissions.
Modules imported:
- os: For file existence checks.
- include.conf_loader.global_config: Loads global configuration.
- include.database.handler: Provides SQLAlchemy engine, Base, and Session.
- include.classes.version.Version: Handles versioning.
- include.database.models: Contains ORM models for User and UserGroup.
- include.function.user.create_user: Function to create a new user.
Constants:
- CORE_VERSION: The current version of the core application.
"""

import os
import ssl
from include.conf_loader import global_config
from include.database.handler import engine, Base
from include.database.handler import Session
from include.classes.version import Version
from include.database.models import User, UserGroup
from websockets.sync.server import serve
from include.connection_handler import handle_connection

CORE_VERSION = Version("0.0.1.250618_alpha")


def server_init():
    """
    Initializes the server by checking if the database is already set up.
    If not, it creates the necessary tables and a default admin user.
    """
    if os.path.exists("./app.db"):
        os.remove("./app.db")

    Base.metadata.create_all(engine)

    with Session() as session:
        # 创建 sysop 用户组，并赋予 shutdown 权限
        sysop_group = UserGroup(group_name="sysop")
        sysop_group.permissions = {
            "shutdown": {"granted": True, "start_time": 0, "end_time": None},
        }
        session.add(sysop_group)
        session.commit()

    from include.function.user import create_user
    import secrets
    import string

    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{};:,.<>?/"
    password = "".join(secrets.choice(alphabet) for _ in range(16))

    create_user(
        username="admin",
        password=password,
        nickname="管理员",
        permissions=[],
        groups=[
            {
                "group_name": "sysop",
                "start_time": 0,
                "end_time": None,
            },
        ],
    )

    # 将密码输出到运行目录下的 admin_password.txt 文件
    with open("admin_password.txt", "w", encoding="utf-8") as pwd_file:
        pwd_file.write(f"admin 用户的初始密码: {password}\n")

    os.makedirs("./content", exist_ok=True)
    secret_key = secrets.token_urlsafe(32)
    with open("./content/SECRET_KEY", "w", encoding="utf-8") as key_file:
        key_file.write(secret_key + "\n")

    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import datetime

    cert_path = global_config["server"]["ssl_certfile"]
    key_path = global_config["server"]["ssl_keyfile"]

    # 使用python包 cryptography 生成自签名证书和私钥
    if not (os.path.exists(cert_path) and os.path.exists(key_path)):

        # 生成私钥
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # 生成自签名证书
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
            ]
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.UTC))
            .not_valid_after(
                datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365)
            )
            .sign(key, hashes.SHA256())
        )

        # 写入私钥
        with open(key_path, "wb") as f:
            f.write(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

        # 写入证书
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

    with open("./init", "w") as f:
        f.write("This file indicates that the database has been initialized.\n")


def main():
    if not os.path.exists("./init"):
        server_init()

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(
        certfile=global_config["server"]["ssl_certfile"],
        keyfile=global_config["server"]["ssl_keyfile"],
    )

    with serve(
        handle_connection,
        global_config["server"]["host"],
        global_config["server"]["port"],
        ssl=ssl_context,
    ) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
