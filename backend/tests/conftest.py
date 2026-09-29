"""Pytest configuration for the CyberForecast AI backend test suite.

The suite is hermetic: it points the persistence layer at a throwaway SQLite
database and disables EVM anchoring so no external node, network call or demo
data is touched. Environment variables are set *before* the application modules
are imported because ``app.core.config`` reads them at import time.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile

BACKEND_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_ROOT not in sys.path:
    sys.path.insert(0, BACKEND_ROOT)

TEST_ROOT = tempfile.mkdtemp(prefix="cyberforecast-tests-")

os.environ["STORAGE_BACKEND"] = "sql"
os.environ["DATABASE_URL"] = f"sqlite:///{os.path.join(TEST_ROOT, 'test.db')}"
os.environ["BLOCKCHAIN_ANCHOR_ENABLED"] = "false"
os.environ["BLOCKCHAIN_RPC_URL"] = ""
os.environ["BLOCKCHAIN_PRIVATE_KEY"] = ""
os.environ["SEED_DEMO_DATA"] = "false"   # never seed demo traffic during tests
os.environ["JWT_SECRET_KEY"] = "unit-test-secret-key-not-used-in-production"
os.environ["RATE_LIMIT"] = "10000/minute"        # tests must not trip the limiter
os.environ["AUTH_RATE_LIMIT"] = "10000/minute"

import pytest  # noqa: E402

from app.storage import get_store  # noqa: E402
from app.storage.orm import init_db  # noqa: E402

# The application normally creates its tables during FastAPI startup; tests drive
# the services directly, so the schema is created here instead.
init_db()


@pytest.fixture(scope="session", autouse=True)
def _cleanup() -> None:
    """Remove the temporary database directory once the session finishes."""
    yield
    shutil.rmtree(TEST_ROOT, ignore_errors=True)


@pytest.fixture()
def store():
    """A store handle with the ledger and audit collections cleared."""
    handle = get_store()
    for collection in ("blockchain_events", "audit_logs", "alerts"):
        rows, _ = handle.list(collection, limit=1000)
        for row in rows:
            handle.delete(collection, row["id"])
    return handle
