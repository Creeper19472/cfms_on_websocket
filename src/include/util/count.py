__all__ = ["count_file_references"]

from itertools import islice
from typing import Any, Iterable, cast

from sqlalchemy import MetaData, Table, func, select, union_all
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from include.constants import QUERY_CHUNK_SIZE

_CACHED_REFS = None


def _get_file_references(engine: Engine) -> list[tuple[Table, str]]:
    global _CACHED_REFS
    if _CACHED_REFS is not None:
        return _CACHED_REFS

    meta = MetaData()
    meta.reflect(bind=engine)

    refs = []
    files_table_name = "files"
    for table in meta.sorted_tables:
        for col in table.columns:
            for fk in col.foreign_keys:
                if fk.column.table.name == files_table_name:
                    refs.append((table, col.name))

    _CACHED_REFS = refs
    return refs


def count_file_references(session: Session, file_ids: Iterable[Any] | None = None):
    """
    Count references to files in the database.

    Args:
        session (Session): The SQLAlchemy session to use for the query.
        file_ids (Iterable[Any] | None): An optional iterable of file IDs to filter
        by. If None, counts references for all files.
    """

    if file_ids is not None and not file_ids:
        return {}

    engine = cast(Engine, session.get_bind())
    refs = _get_file_references(engine)

    if not refs:
        return {}

    def _execute_query(chunk_ids):
        subqueries = []
        for table, colname in refs:
            col = table.c[colname]
            stmt = select(col.label("file_id"), func.count().label("cnt")).where(
                col.isnot(None)
            )

            if chunk_ids is not None:
                stmt = stmt.where(col.in_(chunk_ids))

            stmt = stmt.group_by(col)
            subqueries.append(stmt)

        union = union_all(*subqueries).alias("u")
        final = select(union.c.file_id, func.sum(union.c.cnt).label("total")).group_by(
            union.c.file_id
        )

        rows = session.execute(final).all()
        return {row.file_id: row.total for row in rows}

    if file_ids is None:
        return _execute_query(None)

    result = {}
    iterator = iter(file_ids)
    while chunk := tuple(islice(iterator, QUERY_CHUNK_SIZE)):
        chunk_result = _execute_query(chunk)
        for k, v in chunk_result.items():
            result[k] = result.get(k, 0) + v

    return result
