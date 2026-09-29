"""SQLAlchemy-backed implementation of the RecordStore interface."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.utils import new_id, utcnow
from app.storage.base import RecordStore
from app.storage.orm import ATTR_ALIASES, MODELS, SessionLocal, dict_to_row_values, engine, row_to_dict
from app.storage.schema import COLLECTIONS


def _apply_filters(query, model, collection: str, filters: Optional[Dict[str, Any]]):
    if not filters:
        return query
    fields = COLLECTIONS[collection].field_map()
    aliases = ATTR_ALIASES.get(collection, {})
    for key, value in filters.items():
        if key not in fields or value is None:
            continue
        column = getattr(model, aliases.get(key, key))
        if isinstance(value, dict):
            for op, operand in value.items():
                if operand is None:
                    continue
                if op == "$gte":
                    query = query.where(column >= _coerce(fields[key].type, operand))
                elif op == "$gt":
                    query = query.where(column > _coerce(fields[key].type, operand))
                elif op == "$lte":
                    query = query.where(column <= _coerce(fields[key].type, operand))
                elif op == "$lt":
                    query = query.where(column < _coerce(fields[key].type, operand))
                elif op == "$ne":
                    query = query.where(column != _coerce(fields[key].type, operand))
                elif op == "$like":
                    query = query.where(func.lower(column).like(str(operand).lower()))
                elif op == "$in":
                    query = query.where(column.in_([_coerce(fields[key].type, v) for v in operand]))
                elif op == "$null":
                    query = query.where(column.is_(None) if operand else column.is_not(None))
        elif isinstance(value, (list, tuple, set)):
            query = query.where(column.in_([_coerce(fields[key].type, v) for v in value]))
        else:
            query = query.where(column == _coerce(fields[key].type, value))
    return query


def _coerce(field_type: str, value: Any) -> Any:
    from app.core.utils import as_naive_utc

    if field_type == "datetime":
        return as_naive_utc(value)
    if field_type == "boolean":
        return bool(value)
    if field_type == "integer":
        try:
            return int(float(value))
        except (TypeError, ValueError):
            return value
    if field_type == "float":
        try:
            return float(value)
        except (TypeError, ValueError):
            return value
    return value


def _apply_order(query, model, order_by: Optional[str], collection: str = ""):
    aliases = ATTR_ALIASES.get(collection, {})
    if not order_by:
        return query
    for part in order_by.split(","):
        part = part.strip()
        if not part:
            continue
        descending = part.startswith("-")
        name = part[1:] if descending else part
        column = getattr(model, aliases.get(name, name), None)
        if column is None:
            continue
        query = query.order_by(column.desc() if descending else column.asc())
    return query


def _apply_search(query, model, collection: str, search: Optional[str], search_fields: Optional[List[str]]):
    if not search:
        return query
    aliases = ATTR_ALIASES.get(collection, {})
    fields = search_fields or [
        f.name for f in COLLECTIONS[collection].fields if f.type in ("string", "text")
    ]
    clauses = []
    needle = f"%{search.strip().lower()}%"
    for name in fields:
        column = getattr(model, aliases.get(name, name), None)
        if column is None:
            continue
        clauses.append(func.lower(column).like(needle))
    return query.where(or_(*clauses)) if clauses else query


class SqlRecordStore(RecordStore):
    backend = "sql"

    def __init__(self, session: Optional[Session] = None) -> None:
        self._session = session

    # -- session handling -------------------------------------------------
    def _sess(self) -> Session:
        return self._session or SessionLocal()

    def _release(self, session: Session) -> None:
        if self._session is None:
            session.close()

    def __enter__(self) -> "SqlRecordStore":
        return self

    # -- CRUD -------------------------------------------------------------
    def create(self, collection: str, data: Dict[str, Any]) -> Dict[str, Any]:
        model = MODELS[collection]
        payload = dict_to_row_values(collection, data)
        payload.setdefault("id", new_id())
        session = self._sess()
        try:
            row = model(**payload)
            session.add(row)
            session.commit()
            session.refresh(row)
            return row_to_dict(row, collection)
        except Exception:
            session.rollback()
            raise
        finally:
            self._release(session)

    def create_many(self, collection: str, rows: List[Dict[str, Any]]) -> int:
        if not rows:
            return 0
        model = MODELS[collection]
        session = self._sess()
        try:
            payload = []
            for row in rows:
                values = dict_to_row_values(collection, row)
                values.setdefault("id", new_id())
                payload.append(model(**values))
            session.bulk_save_objects(payload)
            session.commit()
            return len(payload)
        except Exception:
            session.rollback()
            raise
        finally:
            self._release(session)

    def get(self, collection: str, record_id: str) -> Optional[Dict[str, Any]]:
        model = MODELS[collection]
        session = self._sess()
        try:
            row = session.get(model, record_id)
            return row_to_dict(row, collection) if row else None
        finally:
            self._release(session)

    def find_one(self, collection: str, filters: Optional[Dict[str, Any]] = None,
                 order_by: Optional[str] = None) -> Optional[Dict[str, Any]]:
        model = MODELS[collection]
        session = self._sess()
        try:
            query = _apply_filters(select(model), model, collection, filters)
            query = _apply_order(query, model, order_by, collection)
            row = session.execute(query.limit(1)).scalars().first()
            return row_to_dict(row, collection) if row else None
        finally:
            self._release(session)

    def list(self, collection: str, filters: Optional[Dict[str, Any]] = None,
             order_by: Optional[str] = None, limit: int = 50, offset: int = 0,
             search: Optional[str] = None, search_fields: Optional[List[str]] = None
             ) -> Tuple[List[Dict[str, Any]], int]:
        model = MODELS[collection]
        limit = max(1, min(int(limit or 50), 2000))
        offset = max(0, int(offset or 0))
        session = self._sess()
        try:
            base = _apply_filters(select(model), model, collection, filters)
            base = _apply_search(base, model, collection, search, search_fields)
            total = session.execute(
                select(func.count()).select_from(base.subquery())
            ).scalar_one()
            query = _apply_order(base, model, order_by).limit(limit).offset(offset)
            rows = session.execute(query).scalars().all()
            return [row_to_dict(r, collection) for r in rows], int(total)
        finally:
            self._release(session)

    def update(self, collection: str, record_id: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        model = MODELS[collection]
        session = self._sess()
        try:
            row = session.get(model, record_id)
            if not row:
                return None
            for key, value in dict_to_row_values(collection, data).items():
                if key == "id":
                    continue
                setattr(row, key, value)
            session.commit()
            session.refresh(row)
            return row_to_dict(row, collection)
        except Exception:
            session.rollback()
            raise
        finally:
            self._release(session)

    def delete(self, collection: str, record_id: str) -> bool:
        model = MODELS[collection]
        session = self._sess()
        try:
            row = session.get(model, record_id)
            if not row:
                return False
            session.delete(row)
            session.commit()
            return True
        except Exception:
            session.rollback()
            raise
        finally:
            self._release(session)

    def count(self, collection: str, filters: Optional[Dict[str, Any]] = None) -> int:
        model = MODELS[collection]
        session = self._sess()
        try:
            query = _apply_filters(select(func.count()).select_from(model), model, collection, filters)
            return int(session.execute(query).scalar_one())
        finally:
            self._release(session)

    # -- analytics helpers used by the API layer --------------------------
    def group_count(self, collection: str, field: str, filters: Optional[Dict[str, Any]] = None,
                    limit: int = 25) -> List[Dict[str, Any]]:
        model = MODELS[collection]
        column = getattr(model, ATTR_ALIASES.get(collection, {}).get(field, field), None)
        if column is None:
            return []
        session = self._sess()
        try:
            query = _apply_filters(select(column, func.count().label("count")).group_by(column),
                                   model, collection, filters)
            rows = session.execute(query.order_by(func.count().desc()).limit(limit)).all()
            return [{"key": r[0], "count": int(r[1])} for r in rows]
        finally:
            self._release(session)

    def sum_field(self, collection: str, field: str, filters: Optional[Dict[str, Any]] = None) -> float:
        model = MODELS[collection]
        column = getattr(model, ATTR_ALIASES.get(collection, {}).get(field, field), None)
        if column is None:
            return 0.0
        session = self._sess()
        try:
            query = _apply_filters(select(func.coalesce(func.sum(column), 0.0)), model, collection, filters)
            return float(session.execute(query).scalar_one() or 0.0)
        finally:
            self._release(session)

    def healthcheck(self) -> Dict[str, Any]:
        from app.storage.orm import database_dialect

        session = self._sess()
        try:
            session.execute(select(func.count()).select_from(MODELS["users"]))
            return {"backend": self.backend, "ok": True, "dialect": database_dialect(), "url_scheme": str(engine.url).split("://")[0]}
        except Exception as exc:
            return {"backend": self.backend, "ok": False, "error": str(exc)[:200]}
        finally:
            self._release(session)
