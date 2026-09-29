"""
Appwrite-backed implementation of the RecordStore interface.

Activated when APPWRITE_ENDPOINT / APPWRITE_PROJECT_ID / APPWRITE_API_KEY are
configured (or APPWRITE_ENABLED=true). The SQL store remains available as a
transparent fallback so the platform never hard-depends on an external service.

Appwrite has no native JSON column type: `json`/`text` schema fields are stored
as string attributes and (de)serialized here, so the rest of the application
sees identical Python objects in both backends.
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional, Tuple

from app.core.config import settings
from app.core.utils import iso, new_id, to_utc
from app.storage.base import RecordStore
from app.storage.schema import COLLECTIONS

# --- SDK imports (compatible with Appwrite SDK >= 1.x and >= 24.x) ----------
try:  # SDK v24+ flat service modules
    from appwrite.services.account import Account
    from appwrite.services.databases import Databases
    from appwrite.services.storage import Storage
    from appwrite.services.users import Users
except ImportError:  # pragma: no cover - SDK <= 6.x nested modules
    from appwrite.services.account.account import Account  # type: ignore
    from appwrite.services.databases.databases import Databases  # type: ignore
    from appwrite.services.storage.storage import Storage  # type: ignore
    from appwrite.services.users.users import Users  # type: ignore

from appwrite.client import Client
from appwrite.exception import AppwriteException
from appwrite.id import ID
from appwrite.input_file import InputFile
from appwrite.permission import Permission
from appwrite.query import Query
from appwrite.role import Role

_JSON_TYPES = {"json", "text"}


class AppwriteError(RuntimeError):
    pass


class AppwriteRecordStore(RecordStore):
    backend = "appwrite"

    def __init__(self) -> None:
        self.client = (
            Client()
            .set_endpoint(settings.appwrite_endpoint)
            .set_project(settings.appwrite_project_id)
            .set_key(settings.appwrite_api_key)
        )
        self.databases = Databases(self.client)
        self.storage = Storage(self.client)
        self.users = Users(self.client)
        self.database_id = settings.appwrite_database_id
        self.bucket_id = settings.appwrite_bucket_id
        self._cache: Dict[str, float] = {}

    # -- serialization ----------------------------------------------------
    def _encode(self, collection: str, data: Dict[str, Any]) -> Dict[str, Any]:
        fields = COLLECTIONS[collection].field_map()
        out: Dict[str, Any] = {}
        for name, value in data.items():
            field = fields.get(name)
            if field is None:
                continue
            if field.type == "datetime":
                out[name] = iso(value)
            elif field.type in _JSON_TYPES:
                if isinstance(value, str) or value is None:
                    out[name] = value
                else:
                    out[name] = json.dumps(value, default=str)
            elif field.type == "boolean":
                out[name] = bool(value) if value is not None else None
            elif field.type in ("integer", "float") and value is not None:
                try:
                    out[name] = int(float(value)) if field.type == "integer" else float(value)
                except (TypeError, ValueError):
                    out[name] = None
            else:
                out[name] = value
        # Appwrite rejects explicit nulls for required attributes -> drop them.
        return {k: v for k, v in out.items() if v is not None}

    def _decode(self, collection: str, doc: Dict[str, Any]) -> Dict[str, Any]:
        fields = COLLECTIONS[collection].field_map()
        out: Dict[str, Any] = {}
        for name, field in fields.items():
            value = doc.get(name)
            if field.type == "datetime":
                out[name] = iso(value) if value else None
            elif field.type in _JSON_TYPES and isinstance(value, str):
                try:
                    out[name] = json.loads(value)
                except json.JSONDecodeError:
                    out[name] = value if field.type == "text" else {}
            else:
                out[name] = value
        out["id"] = doc.get("id") or doc.get("$id")
        return out

    # -- query translation -------------------------------------------------
    def _queries(self, collection: str, filters: Optional[Dict[str, Any]],
                 order_by: Optional[str], limit: int, offset: int,
                 search: Optional[str], search_fields: Optional[List[str]]) -> List[str]:
        queries: List[str] = []
        fields = COLLECTIONS[collection].field_map()
        for key, value in (filters or {}).items():
            if key not in fields:
                continue
            if isinstance(value, dict):
                for op, operand in value.items():
                    if operand is None:
                        continue
                    if op == "$gte":
                        queries.append(Query.greater_than_equal(key, _scalar(value=operand, f=fields[key])))
                    elif op == "$gt":
                        queries.append(Query.greater_than(key, _scalar(value=operand, f=fields[key])))
                    elif op == "$lte":
                        queries.append(Query.less_than_equal(key, _scalar(value=operand, f=fields[key])))
                    elif op == "$lt":
                        queries.append(Query.less_than(key, _scalar(value=operand, f=fields[key])))
                    elif op == "$ne":
                        queries.append(Query.not_equal(key, _scalar(value=operand, f=fields[key])))
                    elif op == "$like":
                        queries.append(Query.contains(key, str(operand).strip("%")))
                    elif op == "$in":
                        queries.append(Query.equal(key, [_scalar(value=v, f=fields[key]) for v in operand]))
                    elif op == "$null":
                        queries.append(Query.is_null(key) if operand else Query.is_not_null(key))
            elif isinstance(value, (list, tuple, set)):
                queries.append(Query.equal(key, [_scalar(value=v, f=fields[key]) for v in value]))
            elif value is not None:
                queries.append(Query.equal(key, _scalar(value=value, f=fields[key])))

        for part in (order_by or "").split(","):
            part = part.strip()
            if not part:
                continue
            name = part[1:] if part.startswith("-") else part
            if name not in fields:
                continue
            queries.append(Query.order_desc(name) if part.startswith("-") else Query.order_asc(name))

        if search:
            target = (search_fields or ["id"])[0]
            if target in fields:
                queries.append(Query.search(target, search.strip()))

        queries.append(Query.limit(max(1, min(int(limit), 2000))))
        if offset:
            queries.append(Query.offset(int(offset)))
        return queries

    # -- CRUD --------------------------------------------------------------
    def create(self, collection: str, data: Dict[str, Any]) -> Dict[str, Any]:
        doc_id = str(data.get("id") or new_id())
        payload = self._encode(collection, {**data, "id": doc_id})
        try:
            doc = self.databases.create_document(
                self.database_id, collection, doc_id, payload,
                permissions=[Permission.read(Role.any()), Permission.update(Role.any()), Permission.delete(Role.any())],
            )
        except AppwriteException as exc:
            raise AppwriteError(f"Appwrite create failed on '{collection}': {exc.message}") from exc
        return self._decode(collection, dict(doc))

    def create_many(self, collection: str, rows: List[Dict[str, Any]]) -> int:
        created = 0
        for row in rows:
            try:
                self.create(collection, row)
                created += 1
            except AppwriteError:
                continue
        return created

    def get(self, collection: str, record_id: str) -> Optional[Dict[str, Any]]:
        try:
            doc = self.databases.get_document(self.database_id, collection, record_id)
        except AppwriteException:
            return None
        return self._decode(collection, dict(doc))

    def find_one(self, collection: str, filters: Optional[Dict[str, Any]] = None,
                 order_by: Optional[str] = None) -> Optional[Dict[str, Any]]:
        rows, _ = self.list(collection, filters=filters, order_by=order_by, limit=1)
        return rows[0] if rows else None

    def list(self, collection: str, filters: Optional[Dict[str, Any]] = None,
             order_by: Optional[str] = None, limit: int = 50, offset: int = 0,
             search: Optional[str] = None, search_fields: Optional[List[str]] = None
             ) -> Tuple[List[Dict[str, Any]], int]:
        queries = self._queries(collection, filters, order_by, limit, offset, search, search_fields)
        try:
            result = self.databases.list_documents(self.database_id, collection, queries, total=True)
        except AppwriteException as exc:
            raise AppwriteError(f"Appwrite list failed on '{collection}': {exc.message}") from exc
        docs = [self._decode(collection, dict(d)) for d in result.get("documents", [])]
        return docs, int(result.get("total", len(docs)))

    def update(self, collection: str, record_id: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        payload = self._encode(collection, {k: v for k, v in data.items() if k != "id"})
        if not payload:
            return self.get(collection, record_id)
        try:
            doc = self.databases.update_document(self.database_id, collection, record_id, payload)
        except AppwriteException as exc:
            raise AppwriteError(f"Appwrite update failed on '{collection}/{record_id}': {exc.message}") from exc
        return self._decode(collection, dict(doc))

    def delete(self, collection: str, record_id: str) -> bool:
        try:
            self.databases.delete_document(self.database_id, collection, record_id)
            return True
        except AppwriteException:
            return False

    def count(self, collection: str, filters: Optional[Dict[str, Any]] = None) -> int:
        _, total = self.list(collection, filters=filters, limit=1)
        return total

    # -- storage -----------------------------------------------------------
    def upload_file(self, content: bytes, filename: str, content_type: str = "text/csv") -> Optional[str]:
        try:
            file = self.storage.create_file(
                self.bucket_id,
                ID.unique(),
                InputFile.from_bytes(content, filename),
                permissions=[Permission.read(Role.any())],
            )
            return dict(file).get("$id")
        except AppwriteException:
            return None

    def download_file(self, file_id: str) -> Optional[bytes]:
        try:
            return self.storage.get_file_download(self.bucket_id, file_id)
        except AppwriteException:
            return None

    # -- users (Appwrite Auth mirror) --------------------------------------
    def auth_create_user(self, email: str, password: str, name: str) -> Optional[str]:
        try:
            user = self.users.create_bcrypt_user(ID.unique(), email, password, name)
            return dict(user).get("$id")
        except AppwriteException:
            return None

    def auth_verify_password(self, email: str, password: str) -> bool:
        """Server-side credential check against Appwrite Auth.

        Creates an email/password session (the same REST call the login form
        uses); a success proves the credentials are valid. The session is
        deleted immediately so no long-lived session is left behind.
        """
        try:
            client = (
                Client()
                .set_endpoint(settings.appwrite_endpoint)
                .set_project(settings.appwrite_project_id)
            )
            session = Account(client).create_email_password_session(email, password)
            session_id = dict(session).get("$id")
            secret = dict(session).get("secret")
            if session_id and secret:
                try:
                    Account(client.set_session(session_id, secret)).delete_session(session_id)
                except AppwriteException:
                    pass
            return True
        except AppwriteException:
            return False
        except Exception:
            return False

    def auth_update_password(self, appwrite_user_id: str, password: str) -> bool:
        try:
            self.users.update_password(appwrite_user_id, password)
            return True
        except (AppwriteException, AttributeError):
            return False

    def verify_session_jwt(self, token: str) -> Optional[Dict[str, Any]]:
        """Validate an Appwrite session JWT server-side and return the user."""
        try:
            client = (
                Client()
                .set_endpoint(settings.appwrite_endpoint)
                .set_project(settings.appwrite_project_id)
                .set_jwt(token)
            )
            user = dict(Account(client).get())
            return {"id": user.get("$id"), "email": user.get("email"), "name": user.get("name")}
        except Exception:
            return None

    # -- health ------------------------------------------------------------
    def healthcheck(self) -> Dict[str, Any]:
        started = time.time()
        try:
            self.databases.get_collection(self.database_id, "users")
            return {
                "backend": self.backend,
                "ok": True,
                "endpoint": settings.appwrite_endpoint,
                "project_id": settings.appwrite_project_id,
                "database_id": self.database_id,
                "latency_ms": round((time.time() - started) * 1000, 1),
            }
        except AppwriteException as exc:
            return {"backend": self.backend, "ok": False, "error": str(exc.message)[:200]}
        except Exception as exc:  # network unreachable etc.
            return {"backend": self.backend, "ok": False, "error": str(exc)[:200]}


def _scalar(value: Any, f: Any) -> Any:
    """Appwrite queries need JSON-native scalars (dates as ISO strings)."""
    if f is not None and f.type == "datetime":
        return iso(value)
    if isinstance(value, bool):
        return value
    if f is not None and f.type in ("integer", "float"):
        try:
            return int(float(value)) if f.type == "integer" else float(value)
        except (TypeError, ValueError):
            return value
    return str(value) if value is not None else value
