"""Persistence factory: Appwrite when configured, SQL (SQLite/Postgres) otherwise."""

from __future__ import annotations

import logging
from typing import Optional

from app.core.config import settings
from app.storage.base import RecordStore
from app.storage.sql_store import SqlRecordStore

logger = logging.getLogger("cyberforecast.storage")

_store: Optional[RecordStore] = None
_appwrite_failed: bool = False


def get_store() -> RecordStore:
    """Return the active record store (process-wide singleton)."""
    global _store, _appwrite_failed
    if _store is not None:
        return _store

    if settings.appwrite_enabled and not _appwrite_failed:
        try:
            from app.storage.appwrite_store import AppwriteRecordStore

            candidate = AppwriteRecordStore()
            health = candidate.healthcheck()
            if health.get("ok"):
                _store = candidate
                logger.info("Persistence: Appwrite database '%s'", settings.appwrite_database_id)
                return _store
            logger.warning("Appwrite unreachable (%s) - falling back to SQL store", health.get("error"))
            _appwrite_failed = True
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Appwrite adapter failed to initialize (%s) - falling back to SQL store", exc)
            _appwrite_failed = True

    _store = SqlRecordStore()
    logger.info("Persistence: SQL store (%s)", settings.database_url.split("://")[0])
    return _store


def get_appwrite_store():
    """Return the Appwrite adapter when it is the active backend, else None."""
    store = get_store()
    return store if store.backend == "appwrite" else None


def reset_store() -> None:
    global _store, _appwrite_failed
    _store = None
    _appwrite_failed = False


__all__ = ["RecordStore", "SqlRecordStore", "get_store", "get_appwrite_store", "reset_store"]
