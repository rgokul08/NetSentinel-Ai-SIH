"""
SQLAlchemy ORM models generated from the canonical schema (app.storage.schema).

Generating the models from the same definition used by the Appwrite adapter
keeps field names, types and indexes identical in both persistence backends.
"""

from __future__ import annotations

import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import JSON, Boolean, Column, DateTime, Float, Index, Integer, String, Text, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from app.core.config import settings
from app.core.paths import BACKEND_ROOT
from app.core.utils import as_naive_utc, iso, to_utc
from app.storage.schema import COLLECTIONS, Collection, Field

Base = declarative_base()

_TYPE_MAP = {
    "string": lambda f: String(f.size),
    "text": lambda f: Text(),
    "integer": lambda f: Integer(),
    "float": lambda f: Float(),
    "boolean": lambda f: Boolean(),
    "datetime": lambda f: DateTime(),
    "json": lambda f: JSON(),
}


def _column(field: Field) -> Column:
    sql_type = _TYPE_MAP[field.type](field)
    kwargs: Dict[str, Any] = {"nullable": not (field.required or field.name == "id")}
    if field.name == "id":
        kwargs.update(primary_key=True, nullable=False)
    if field.default is not None:
        kwargs["default"] = field.default
    if field.indexed or field.type == "datetime":
        kwargs["index"] = True
    return Column(field.name, sql_type, **kwargs)


# `metadata` is reserved by SQLAlchemy's declarative base; the attribute is
# exposed as `metadata_` while the physical column keeps its canonical name.
RESERVED_ATTRS: Dict[str, str] = {"metadata": "metadata_"}

# collection -> {schema field name: python attribute name}
ATTR_ALIASES: Dict[str, Dict[str, str]] = {}


def _build_model(collection: Collection):
    attrs: Dict[str, Any] = {
        "__tablename__": collection.name,
        "__doc__": collection.description,
    }
    aliases: Dict[str, str] = {}
    table_args: List[Any] = []
    for field in collection.fields:
        attr = RESERVED_ATTRS.get(field.name, field.name)
        aliases[field.name] = attr
        column = _column(field)
        if attr != field.name:
            column = Column(field.name, column.type, **{k: v for k, v in column.kwargs.items()})
        attrs[attr] = column
    for index in collection.indexes:
        table_args.append(
            Index(index.name, *[aliases.get(f, f) for f in index.fields], unique=index.unique)
        )
    if table_args:
        attrs["__table_args__"] = tuple(table_args)
    ATTR_ALIASES[collection.name] = aliases
    return type(f"Row_{collection.name}", (Base,), attrs)


MODELS: Dict[str, Any] = {name: _build_model(c) for name, c in COLLECTIONS.items()}


# ---------------------------------------------------------------------------
# Serialization helpers (ORM row <-> plain dict used by the service layer)
# ---------------------------------------------------------------------------

def row_to_dict(row: Any, collection: str) -> Dict[str, Any]:
    fields = COLLECTIONS[collection].field_map()
    aliases = ATTR_ALIASES.get(collection, {})
    out: Dict[str, Any] = {}
    for name, field in fields.items():
        value = getattr(row, aliases.get(name, name), None)
        if field.type == "datetime":
            value = iso(value)
        out[name] = value
    return out


def dict_to_row_values(collection: str, data: Dict[str, Any]) -> Dict[str, Any]:
    """Coerce an incoming dict into column-ready values, dropping unknown keys."""
    fields = COLLECTIONS[collection].field_map()
    values: Dict[str, Any] = {}
    for name, field in fields.items():
        if name not in data:
            continue
        value = data[name]
        if field.type == "datetime":
            value = as_naive_utc(value)
        elif field.type == "integer":
            try:
                value = int(float(value)) if value not in (None, "") else None
            except (TypeError, ValueError):
                value = None
        elif field.type == "float":
            try:
                value = float(value) if value not in (None, "") else None
            except (TypeError, ValueError):
                value = None
        elif field.type == "boolean":
            value = bool(value) if value is not None else None
        elif field.type == "string":
            value = str(value)[: field.size] if value is not None else None
        elif field.type == "json":
            if value is not None and not isinstance(value, (dict, list)):
                value = {"value": value}
        values[RESERVED_ATTRS.get(name, name)] = value
    return values


# ---------------------------------------------------------------------------
# Engine / session
# ---------------------------------------------------------------------------

def _resolve_sqlite_url(url: str) -> str:
    """Make relative SQLite paths independent of the process working directory.

    ``sqlite:///./data/cyberforecast.db`` would otherwise create a second empty
    database whenever the backend is started from the repository root instead of
    ``backend/`` - the tables would be missing and every query would fail.
    Relative paths are resolved against the backend directory; ``:memory:`` and
    absolute paths are left untouched.
    """
    prefix = "sqlite:///"
    if not url.startswith(prefix) or url.startswith("sqlite:////"):
        return url
    relative = url[len(prefix):]
    if not relative or relative == ":memory:" or os.path.isabs(relative):
        return url
    return prefix + os.path.abspath(os.path.join(BACKEND_ROOT, relative))


def _build_engine():
    url = settings.database_url
    if url.startswith("sqlite"):
        # Serverless bundles are read-only: keep the fallback DB in /tmp there.
        if settings.is_serverless and url.startswith("sqlite:///") and "/tmp" not in url:
            url = "sqlite:////tmp/cyberforecast.db"
        else:
            url = _resolve_sqlite_url(url)
        os.makedirs(os.path.dirname(url.replace("sqlite:///", "")) or ".", exist_ok=True)
        return create_engine(url, connect_args={"check_same_thread": False}, future=True)
    kwargs: Dict[str, Any] = {"pool_pre_ping": True, "future": True}
    if settings.is_serverless:
        kwargs.update(pool_size=5, max_overflow=5, pool_recycle=1800)
    else:
        kwargs.update(pool_size=10, max_overflow=20)
    return create_engine(url, **kwargs)


engine = _build_engine()
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False, expire_on_commit=False, future=True)


_DDL_TYPES = {
    "string": "VARCHAR(255)",
    "text": "TEXT",
    "integer": "INTEGER",
    "float": "FLOAT",
    "boolean": "BOOLEAN",
    "datetime": "DATETIME",
    "json": "JSON",
}


def _migrate_schema() -> List[str]:
    """Add columns introduced by newer schema versions (forward-only migration).

    `create_all` never alters existing tables, so an upgraded deployment would
    otherwise fail with "no such column". ADD COLUMN is supported by both SQLite
    and PostgreSQL, which covers every backend this project targets.
    """
    from sqlalchemy import inspect as sa_inspect, text

    added: List[str] = []
    inspector = sa_inspect(engine)
    existing_tables = set(inspector.get_table_names())
    with engine.begin() as connection:
        for collection_name, collection in COLLECTIONS.items():
            if collection_name not in existing_tables:
                continue
            present = {column["name"] for column in inspector.get_columns(collection_name)}
            for field in collection.fields:
                if field.name in present:
                    continue
                column_type = _DDL_TYPES.get(field.type, "TEXT")
                connection.execute(
                    text(f'ALTER TABLE {collection_name} ADD COLUMN "{field.name}" {column_type}')
                )
                added.append(f"{collection_name}.{field.name}")
    return added


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
    try:
        migrated = _migrate_schema()
        if migrated:
            import logging

            logging.getLogger("cyberforecast.storage").info("Schema migration added: %s", ", ".join(migrated))
    except Exception:  # pragma: no cover - never block startup on migration
        import logging

        logging.getLogger("cyberforecast.storage").warning("Automatic schema migration failed", exc_info=True)


def get_db_session():
    """FastAPI dependency yielding a session."""
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def database_dialect() -> str:
    return engine.dialect.name
