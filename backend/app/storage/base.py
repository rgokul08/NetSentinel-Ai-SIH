"""
Persistence interface shared by the SQL and Appwrite backends.

The service layer only ever talks to a `RecordStore`, so swapping SQLite for
Appwrite (or PostgreSQL) never changes application logic.

Filter grammar (supported by both stores):

    {"severity": "high"}                     -> equality
    {"severity": ["high", "critical"]}       -> IN
    {"timestamp": {"$gte": dt, "$lte": dt}}  -> range
    {"status": {"$ne": "resolved"}}          -> not equal
    {"title": {"$like": "%ddos%"}}           -> case-insensitive substring
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple


class RecordStore(ABC):
    backend: str = "abstract"

    @abstractmethod
    def create(self, collection: str, data: Dict[str, Any]) -> Dict[str, Any]: ...

    @abstractmethod
    def create_many(self, collection: str, rows: List[Dict[str, Any]]) -> int: ...

    @abstractmethod
    def get(self, collection: str, record_id: str) -> Optional[Dict[str, Any]]: ...

    @abstractmethod
    def find_one(self, collection: str, filters: Optional[Dict[str, Any]] = None,
                 order_by: Optional[str] = None) -> Optional[Dict[str, Any]]: ...

    @abstractmethod
    def list(self, collection: str, filters: Optional[Dict[str, Any]] = None,
             order_by: Optional[str] = None, limit: int = 50, offset: int = 0,
             search: Optional[str] = None, search_fields: Optional[List[str]] = None
             ) -> Tuple[List[Dict[str, Any]], int]: ...

    @abstractmethod
    def update(self, collection: str, record_id: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]: ...

    @abstractmethod
    def delete(self, collection: str, record_id: str) -> bool: ...

    @abstractmethod
    def count(self, collection: str, filters: Optional[Dict[str, Any]] = None) -> int: ...

    # -- optional capabilities -------------------------------------------
    def supports_aggregation(self) -> bool:
        return True

    def healthcheck(self) -> Dict[str, Any]:
        return {"backend": self.backend, "ok": True}
