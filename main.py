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
- include.util.user.create_user: Function to create a new user.
Constants:
- CORE_VERSION: The current version of the core application.
"""

import os

# fix
os.makedirs("./content/logs/", exist_ok=True)
os.makedirs("./content/ssl/", exist_ok=True)

import ssl
from include.conf_loader import global_config
from include.constants import CORE_VERSION
from include.database.handler import engine, Base
from include.database.handler import Session
from include.database.models.classic import User, UserGroup, Document, DocumentRevision
from include.database.models.file import File
from websockets.sync.server import serve
from include.connection_handler import handle_connection
from include.util.log import getCustomLogger
import socket


def server_init():
    """
    Initializes the server by checking if the database is already set up.
    If not, it creates the necessary tables and a default admin user.
    """
    if os.path.exists("./app.db"):
        os.remove("./app.db")
    if os.path.exists("./ssl_cert.pem"):
        os.remove("./ssl_cert.pem")
    if os.path.exists("./ssl_key.pem"):
        os.remove("./ssl_key.pem")

    from include.util.group import create_group

    create_group(
        group_name="user",
        permissions=[
            {"permission": "set_passwd", "start_time": 0, "end_time": None},
        ],
    )
    create_group(
        group_name="sysop",
        permissions=[
            {"permission": "move"},
            {"permission": "shutdown", "start_time": 0, "end_time": None},
            {"permission": "super_create_document", "start_time": 0, "end_time": None},
            {"permission": "super_create_directory", "start_time": 0, "end_time": None},
            {"permission": "super_list_directory", "start_time": 0, "end_time": None},
            {"permission": "create_document", "start_time": 0, "end_time": None},
            {"permission": "create_directory", "start_time": 0, "end_time": None},
            {"permission": "delete_document", "start_time": 0, "end_time": None},
            {"permission": "rename_document", "start_time": 0, "end_time": None},
            {"permission": "delete_directory", "start_time": 0, "end_time": None},
            {"permission": "rename_directory", "start_time": 0, "end_time": None},
            {"permission": "manage_system", "start_time": 0, "end_time": None},
            {"permission": "create_user", "start_time": 0, "end_time": None},
            {"permission": "delete_user", "start_time": 0, "end_time": None},
            {"permission": "rename_user", "start_time": 0, "end_time": None},
            {"permission": "get_user_info", "start_time": 0, "end_time": None},
            {"permission": "get_group_info"},
            {"permission": "change_user_groups", "start_time": 0, "end_time": None},
            {"permission": "super_set_passwd", "start_time": 0, "end_time": None},
            {"permission": "view_access_rules", "start_time": 0, "end_time": None},
            {"permission": "set_access_rules", "start_time": 0, "end_time": None},
            {"permission": "list_users", "start_time": 0, "end_time": None},
            {"permission": "list_groups", "start_time": 0, "end_time": None},
            {"permission": "create_group", "start_time": 0, "end_time": None},
            {"permission": "delete_group", "start_time": 0, "end_time": None},
            {"permission": "rename_group", "start_time": 0, "end_time": None},
            {"permission": "set_group_permissions"},
            {"permission": "bypass_lockdown"},
            {"permission": "apply_lockdown"},
            {"permission": "view_audit_logs"},
            {"permission": "manage_access"},
            {"permission": "view_access_entries"},
            {"permission": "block"},
            {"permission": "unblock"},
        ],
    )
    with Session() as session:
        init_file = File(id="init", path="./content/hello")
        session.add(init_file)

        init_document = Document(id="hello", title="Hello World")
        init_document_revision = DocumentRevision(file_id=init_file.id)
        init_document.revisions.append(init_document_revision)
        session.add(init_document)
        session.add(init_document_revision)
        session.commit()

    from include.util.user import create_user
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
            {
                "group_name": "user",
                "start_time": 0,
                "end_time": None,
            },
        ],
    )

    # 将密码输出到运行目录下的 admin_password.txt 文件
    with open("admin_password.txt", "w", encoding="utf-8") as pwd_file:
        pwd_file.write(f"{password}\n")

    os.makedirs("./content", exist_ok=True)

    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.backends import default_backend
    import datetime

    cert_path = global_config["server"]["ssl_certfile"]
    key_path = global_config["server"]["ssl_keyfile"]

    # 使用python包 cryptography 生成自签名证书和私钥
    if not (os.path.exists(cert_path) and os.path.exists(key_path)):

        # 生成 ECC 私钥
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

        # 生成自签名证书
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(
                    NameOID.COMMON_NAME, global_config["server"]["host"]
                ),
            ]
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(
                datetime.datetime.now(datetime.timezone.utc)
                + datetime.timedelta(days=365)
            )
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.DNSName(global_config["server"]["host"])]
                ),
                critical=False,
            )
            .sign(private_key, hashes.SHA256(), default_backend())
        )

        # 写入私钥
        with open(key_path, "wb") as f:
            f.write(
                private_key.private_bytes(
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
    logger = getCustomLogger("CFMS", filepath="./content/logs/core.log")

    if not os.path.exists("./init"):
        logger.info("Database not initialized, initializing now...")
        server_init()

    logger.info("Initializating CFMS WebSocket server...")
    logger.info(f"CFMS Core Version: {CORE_VERSION}")
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(
        certfile=global_config["server"]["ssl_certfile"],
        keyfile=global_config["server"]["ssl_keyfile"],
    )

    # Always create tables that do not exist
    Base.metadata.create_all(engine)

    with serve(
        handle_connection,
        global_config["server"]["host"],
        global_config["server"]["port"],
        ssl=ssl_context,
        family=socket.AF_INET6,
        dualstack_ipv6=global_config["server"]["dualstack_ipv6"],
    ) as server:
        logger.info(
            f"CFMS WebSocket server started at wss://{global_config['server']['host']}:{global_config['server']['port']}"
        )  # TODO
        server.serve_forever()


if __name__ == "__main__":
    main()
