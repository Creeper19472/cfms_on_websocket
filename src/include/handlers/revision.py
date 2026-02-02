from typing import Optional

import jsonschema
from include.classes.connection import ConnectionHandler
from include.classes.request import RequestHandler
from include.conf_loader import global_config
from include.database.handler import Session
from include.database.models.classic import User
from include.database.models.entity import DocumentRevision, Folder, Document
from include.handlers.document import create_file_task
from include.util.audit import log_audit
from include.util.rule.applying import apply_access_rules
import include.system.messages as smsg


class RequestListRevisionsHandler(RequestHandler):

    schema = {
        "type": "object",
        "properties": {
            "document_id": {"type": "string", "minLength": 1},
        },
        "required": ["document_id"],
        "additionalProperties": False,
    }

    require_auth = True  # when True, handler.username is guaranteed to be not None

    def handle(self, handler: ConnectionHandler):
        document_id = handler.data["document_id"]

        with Session() as session:
            user = session.get(User, handler.username)
            document = session.get(Document, document_id)

            if document is None:
                handler.conclude_request(404, {}, "Document not found")
                return 404, document_id, handler.username

            assert user is not None  # due to require_auth being True
            if (
                "list_revisions" not in user.all_permissions
                or not document.check_access_requirements(user, "read")
            ):
                handler.conclude_request(403, {}, smsg.ACCESS_DENIED)
                return 403, document_id, handler.username

            revisions = [
                {
                    "id": rev.id,
                    "parent_id": rev.parent_revision_id,
                    "created_time": rev.created_time,
                }
                for rev in document.revisions
            ]

        handler.conclude_request(
            200, {"revisions": revisions}, "Revisions listed successfully"
        )
        return 200, document_id, handler.username


class RequestGetRevisionHandler(RequestHandler):
    schema = {
        "type": "object",
        "properties": {
            "id": {"type": "string", "minLength": 1},
        },
        "required": ["id"],
        "additionalProperties": False,
    }

    require_auth = True  # when True, handler.username is guaranteed to be not None

    def handle(self, handler: ConnectionHandler):
        revision_id = handler.data["revision_id"]

        with Session() as session:
            user = session.get(User, handler.username)
            revision = session.get(DocumentRevision, revision_id)

            if revision is None:
                handler.conclude_request(404, {}, "Revision not found")
                return 404, revision_id, handler.username

            assert user is not None  # due to require_auth being True
            if (
                "view_revision" not in user.all_permissions
                or not revision.document.check_access_requirements(user, "read")
            ):
                handler.conclude_request(403, {}, smsg.ACCESS_DENIED)
                return 403, revision_id, handler.username

            task_data = create_file_task(revision.file)

        handler.conclude_request(200, {"task_data": task_data}, smsg.SUCCESS)
        return 200, revision_id, handler.username
    

class RequestSetDocumentRevisionHandler(RequestHandler):
    schema = {
        "type": "object",
        "properties": {
            "document_id": {"type": "string", "minLength": 1},
            "revision_id": {"type": "string", "minLength": 1},
        },
        "required": ["document_id", "revision_id"],
        "additionalProperties": False,
    }

    require_auth = True  # when True, handler.username is guaranteed to be not None

    def handle(self, handler: ConnectionHandler):
        document_id = handler.data["document_id"]
        revision_id = handler.data["revision_id"]

        with Session() as session:
            user = session.get(User, handler.username)
            document = session.get(Document, document_id)
            revision = session.get(DocumentRevision, revision_id)

            if document is None or revision is None or revision.document_id != document.id:
                handler.conclude_request(404, {}, "Document or Revision not found")
                return 404, document_id, handler.username

            assert user is not None  # due to require_auth being True
            if (
                "set_current_revision" not in user.all_permissions
                or not document.check_access_requirements(user, "write")
            ):
                handler.conclude_request(403, {}, smsg.ACCESS_DENIED)
                return 403, document_id, handler.username

            document.current_revision_id = revision.id
            session.commit()

        handler.conclude_request(200, {}, "Current revision set successfully")
        return 200, document_id, handler.username
