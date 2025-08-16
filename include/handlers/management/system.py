import json
import time
from typing import Optional

from sqlalchemy import desc, update, func, true
from include.classes.connection import ConnectionHandler
from include.classes.request import RequestHandler
from include.database.handler import Session
from include.database.models.file import FileTask
from include.database.models.classic import User, AuditEntry
from include.shared import lockdown_enabled
import include.system.messages as smsg


class RequestLockdownHandler(RequestHandler):
    data_schema = {
        "type": "object",
        "properties": {"status": {"type": "boolean"}},
        "required": ["status"],
        "additionalProperties": False,
    }

    def handle(self, handler: ConnectionHandler):
        status_to_change: bool = handler.data["status"]

        if not handler.username or not handler.token:
            handler.conclude_request(
                **{"code": 401, "message": smsg.MISSING_USERNAME_OR_TOKEN, "data": {}}
            )
            return 401

        with Session() as session:
            user = session.get(User, handler.username)
            if not user or not user.is_token_valid(handler.token):
                handler.conclude_request(
                    **{"code": 401, "message": smsg.INVALID_USER_OR_TOKEN, "data": {}}
                )
                return 401

            if "apply_lockdown" not in user.all_permissions:
                handler.conclude_request(403, {}, smsg.ACCESS_DENIED)
                return 403, None, handler.username

            if status_to_change:
                lockdown_enabled.set()
            else:
                lockdown_enabled.clear()

            # 接下来将数据库 tasks 表中的所有 end_time >= 当前时间的条目的 end_time 修改为当前时间
            # 令所有任务失效
            now = time.time()
            stmt = update(FileTask).where(FileTask.end_time >= now).values(end_time=now)
            session.execute(stmt)
            session.commit()

        handler.conclude_request(200, {}, smsg.SUCCESS)
        handler.broadcast(
            json.dumps({"action": "lockdown", "status": lockdown_enabled.is_set()})
        )
        return 0, None, handler.username


class RequestViewAuditLogsHandler(RequestHandler):
    data_schema = {
        "type": "object",
        "properties": {
            "offset": {"type": "integer", "minimum": 0},
            "count": {"type": "integer", "minimum": 0, "maximum": 100},
            "filters": {"type": "array", "items": {"type": "string"}},
        },
        "required": [],
        "additionalProperties": False,
    }
    require_auth = True

    def handle(self, handler: ConnectionHandler):
        offset: int = handler.data.get("offset", 0)
        entries_count: int = handler.data.get("count", 50)
        filtered_actions: list[str] = handler.data.get("filters", [])

        with Session() as session:
            user = session.get(User, handler.username)
            if not user or not user.is_token_valid(handler.token):
                handler.conclude_request(
                    **{"code": 401, "message": smsg.INVALID_USER_OR_TOKEN, "data": {}}
                )
                return 401

            if "view_audit_logs" not in user.all_permissions:
                handler.conclude_request(403, {}, smsg.ACCESS_DENIED)
                return 403, None, handler.username

            queried_entries = (
                session.query(AuditEntry)
                .order_by(desc(AuditEntry.logged_time))
                .filter(
                    AuditEntry.action.in_(filtered_actions)
                    if filtered_actions
                    else true()
                )
                .offset(offset)
                .limit(entries_count)
                .all()
            )
            total_count: int = (
                session.query(func.count(AuditEntry.id))
                .filter(
                    AuditEntry.action.in_(filtered_actions)
                    if filtered_actions
                    else true()
                )
                .scalar()
            )

            result = [
                {
                    "id": entry.id,
                    "action": entry.action,
                    "username": entry.username,
                    "target": entry.target,
                    "data": entry.data,
                    "result": entry.result,
                    "remote_address": entry.remote_address,
                    "logged_time": entry.logged_time,
                }
                for entry in queried_entries
            ]

        handler.conclude_request(
            200, {"total": total_count, "entries": result}, smsg.SUCCESS
        )
        return (
            0,
            None,
            {"offset": offset, "entries_count": entries_count},
            handler.username,
        )
