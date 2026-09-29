"""Guards against drift between the Solidity contract, the ABI and the backend.

Build artifacts are not committed, so the backend ships an embedded ABI copy.
These tests fail if that copy stops covering anything the Python code calls, or
if it diverges from a freshly compiled artifact when one is present.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

import pytest

from app.blockchain.contract import ARTIFACT_PATH, EMBEDDED_ABI, abi_source, load_abi
from app.core.paths import REPO_ROOT

REQUIRED_FUNCTIONS = {
    "recordEventHash", "recordEventHashBatch", "verifyEventHash", "getEventRecord",
    "eventCount", "owner", "recorders", "setRecorder", "transferOwnership",
}
REQUIRED_EVENTS = {"EventHashRecorded", "RecorderUpdated", "BatchRecorded"}


def _functions(abi):
    return {entry["name"] for entry in abi if entry.get("type") == "function"}


def _events(abi):
    return {entry["name"] for entry in abi if entry.get("type") == "event"}


def test_embedded_abi_covers_every_contract_function():
    assert REQUIRED_FUNCTIONS <= _functions(EMBEDDED_ABI)
    assert REQUIRED_EVENTS <= _events(EMBEDDED_ABI)
    assert any(entry.get("type") == "constructor" for entry in EMBEDDED_ABI)


def test_backend_only_calls_functions_that_exist_in_the_abi():
    """Any `contract.functions.<name>(...)` call must be part of the ABI."""
    called = set()
    for path in Path(REPO_ROOT, "backend", "app", "blockchain").glob("*.py"):
        called.update(re.findall(r"functions\.([A-Za-z_]\w*)\s*\(", path.read_text(encoding="utf-8")))
        called.update(re.findall(r"events\.([A-Za-z_]\w*)\s*\(", path.read_text(encoding="utf-8")))
    assert called, "expected the backend to call contract functions"
    known = _functions(EMBEDDED_ABI) | _events(EMBEDDED_ABI)
    missing = {name for name in called if name not in known}
    assert not missing, f"backend calls ABI members that do not exist: {sorted(missing)}"


def test_abi_covers_every_external_member_of_the_solidity_source():
    """Cross-check the ABI against the contract source itself."""
    source = Path(REPO_ROOT, "blockchain", "contracts", "SecurityEventRegistry.sol")
    if not source.is_file():
        pytest.skip("contract source not available")
    text = source.read_text(encoding="utf-8")

    declared = re.findall(r"function\s+(\w+)\s*\([^)]*\)\s*([^{;]*)", text)
    external = {name for name, modifiers in declared if re.search(r"\b(public|external)\b", modifiers)}
    external |= set(re.findall(r"event\s+(\w+)\s*\(", text))
    assert external, "no external members parsed from the contract source"

    known = _functions(EMBEDDED_ABI) | _events(EMBEDDED_ABI)
    missing = external - known
    assert not missing, f"contract declares members missing from the ABI: {sorted(missing)}"


@pytest.mark.skipif(not os.path.isfile(ARTIFACT_PATH), reason="compiled artifact not present (run npm run compile:offline)")
def test_embedded_abi_matches_the_compiled_artifact():
    artifact = json.loads(Path(ARTIFACT_PATH).read_text(encoding="utf-8"))
    assert _functions(artifact["abi"]) == _functions(EMBEDDED_ABI)
    assert _events(artifact["abi"]) == _events(EMBEDDED_ABI)
    assert len(artifact["abi"]) == len(EMBEDDED_ABI)


def test_load_abi_prefers_the_artifact_when_present():
    abi = load_abi()
    if os.path.isfile(ARTIFACT_PATH):
        assert abi_source() == "hardhat-artifact"
        assert abi == json.loads(Path(ARTIFACT_PATH).read_text(encoding="utf-8"))["abi"]
    else:
        assert abi_source() == "embedded"
        assert abi == EMBEDDED_ABI
