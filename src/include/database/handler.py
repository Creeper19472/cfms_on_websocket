from sqlalchemy import URL, create_engine
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.orm import sessionmaker

from include.conf_loader import global_config
from include.constants import DEFAULT_TOKEN_EXPIRY_SECONDS

__all__ = ["engine", "Session", "Base"]

SUPPORTED_DB_TYPES = {
    "mysql": "mysql+mysqlconnector",
    "postgresql": "postgresql+psycopg2",
    "sqlite": "sqlite",
}

debug_enabled = global_config["debug"]

db_type = global_config["database"]["type"]
drivername = SUPPORTED_DB_TYPES.get(db_type)
if not drivername:
    raise ValueError(f"Unsupported database type: {db_type}")

if db_type == "sqlite":
    db_file = global_config["database"]["file"]
    engine = create_engine(f"sqlite:///{db_file}", echo=debug_enabled)
else:
    username = global_config["database"]["username"]
    password = global_config["database"]["password"]
    host = global_config["database"]["host"]
    port = global_config["database"]["port"]
    db_name = global_config["database"]["name"]

    url = URL.create(
        drivername=drivername,
        username=username,
        password=password,
        host=host,
        port=port,
        database=db_name,
    )
    engine = create_engine(
        url,
        pool_recycle=DEFAULT_TOKEN_EXPIRY_SECONDS,
        echo=debug_enabled,
    )

Session = sessionmaker(bind=engine)


class Base(DeclarativeBase):
    pass


Base.metadata.naming_convention = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(column_0_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}
