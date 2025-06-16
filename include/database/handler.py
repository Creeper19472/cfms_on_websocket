from sqlalchemy import create_engine, URL, MetaData
from sqlalchemy.orm import sessionmaker
from include.conf_loader import global_config

from sqlalchemy.orm import DeclarativeBase

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
        pool_recycle=3600,
        echo=debug_enabled,
    )

Session = sessionmaker(bind=engine)
# metadata_obj = MetaData()

class Base(DeclarativeBase):
    # metadata = metadata_obj
    pass