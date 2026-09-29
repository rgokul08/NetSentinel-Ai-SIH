"""
ABI + address handling for the SecurityEventRegistry smart contract.

The ABI is loaded from the Hardhat build artifact when it exists (single source
of truth) and otherwise falls back to the embedded copy below, which is generated
from that same artifact for blockchain/contracts/SecurityEventRegistry.sol and is
kept in sync by backend/tests/test_contract_abi.py. The fallback matters because
build artifacts are not committed: a fresh clone can still anchor and verify
events without compiling Solidity first.
"""

from __future__ import annotations

import json
import os
from typing import List, Optional

from app.core.paths import REPO_ROOT

ARTIFACT_PATH = os.path.join(
    REPO_ROOT, "blockchain", "artifacts", "contracts",
    "SecurityEventRegistry.sol", "SecurityEventRegistry.json",
)

EMBEDDED_ABI: List[dict] = [
        {'inputs': [], 'stateMutability': 'nonpayable', 'type': 'constructor'},
        {   'anonymous': False,
            'inputs': [{'indexed': False, 'internalType': 'uint256', 'name': 'count', 'type': 'uint256'}],
            'name': 'BatchRecorded',
            'type': 'event'},
        {   'anonymous': False,
            'inputs': [   {'indexed': True, 'internalType': 'bytes32', 'name': 'eventId', 'type': 'bytes32'},
                          {'indexed': False, 'internalType': 'bytes32', 'name': 'eventHash', 'type': 'bytes32'},
                          {'indexed': False, 'internalType': 'string', 'name': 'eventType', 'type': 'string'},
                          {'indexed': False, 'internalType': 'address', 'name': 'recorder', 'type': 'address'},
                          {'indexed': False, 'internalType': 'uint256', 'name': 'timestamp', 'type': 'uint256'}],
            'name': 'EventHashRecorded',
            'type': 'event'},
        {   'anonymous': False,
            'inputs': [   {'indexed': True, 'internalType': 'address', 'name': 'recorder', 'type': 'address'},
                          {'indexed': False, 'internalType': 'bool', 'name': 'allowed', 'type': 'bool'}],
            'name': 'RecorderUpdated',
            'type': 'event'},
        {   'inputs': [],
            'name': 'eventCount',
            'outputs': [{'internalType': 'uint256', 'name': '', 'type': 'uint256'}],
            'stateMutability': 'view',
            'type': 'function'},
        {   'inputs': [{'internalType': 'bytes32', 'name': 'eventId', 'type': 'bytes32'}],
            'name': 'getEventRecord',
            'outputs': [   {'internalType': 'bool', 'name': 'exists', 'type': 'bool'},
                           {'internalType': 'bytes32', 'name': 'eventHash', 'type': 'bytes32'},
                           {'internalType': 'uint256', 'name': 'timestamp', 'type': 'uint256'},
                           {'internalType': 'address', 'name': 'recorder', 'type': 'address'},
                           {'internalType': 'string', 'name': 'eventType', 'type': 'string'}],
            'stateMutability': 'view',
            'type': 'function'},
        {   'inputs': [],
            'name': 'owner',
            'outputs': [{'internalType': 'address', 'name': '', 'type': 'address'}],
            'stateMutability': 'view',
            'type': 'function'},
        {   'inputs': [   {'internalType': 'bytes32', 'name': 'eventId', 'type': 'bytes32'},
                          {'internalType': 'bytes32', 'name': 'eventHash', 'type': 'bytes32'},
                          {'internalType': 'string', 'name': 'eventType', 'type': 'string'}],
            'name': 'recordEventHash',
            'outputs': [],
            'stateMutability': 'nonpayable',
            'type': 'function'},
        {   'inputs': [   {'internalType': 'bytes32[]', 'name': 'eventIds', 'type': 'bytes32[]'},
                          {'internalType': 'bytes32[]', 'name': 'eventHashes', 'type': 'bytes32[]'},
                          {'internalType': 'string[]', 'name': 'eventTypes', 'type': 'string[]'}],
            'name': 'recordEventHashBatch',
            'outputs': [{'internalType': 'uint256', 'name': 'recorded', 'type': 'uint256'}],
            'stateMutability': 'nonpayable',
            'type': 'function'},
        {   'inputs': [{'internalType': 'address', 'name': '', 'type': 'address'}],
            'name': 'recorders',
            'outputs': [{'internalType': 'bool', 'name': '', 'type': 'bool'}],
            'stateMutability': 'view',
            'type': 'function'},
        {   'inputs': [   {'internalType': 'address', 'name': 'recorder', 'type': 'address'},
                          {'internalType': 'bool', 'name': 'allowed', 'type': 'bool'}],
            'name': 'setRecorder',
            'outputs': [],
            'stateMutability': 'nonpayable',
            'type': 'function'},
        {   'inputs': [{'internalType': 'address', 'name': 'newOwner', 'type': 'address'}],
            'name': 'transferOwnership',
            'outputs': [],
            'stateMutability': 'nonpayable',
            'type': 'function'},
        {   'inputs': [   {'internalType': 'bytes32', 'name': 'eventId', 'type': 'bytes32'},
                          {'internalType': 'bytes32', 'name': 'eventHash', 'type': 'bytes32'}],
            'name': 'verifyEventHash',
            'outputs': [{'internalType': 'bool', 'name': '', 'type': 'bool'}],
            'stateMutability': 'view',
            'type': 'function'}]
def load_abi() -> List[dict]:
    """Prefer the compiled Hardhat artifact so the ABI can never drift."""
    if os.path.isfile(ARTIFACT_PATH):
        try:
            with open(ARTIFACT_PATH, "r", encoding="utf-8") as handle:
                artifact = json.load(handle)
            abi = artifact.get("abi")
            if abi:
                return abi
        except (json.JSONDecodeError, OSError):
            pass
    return EMBEDDED_ABI


def abi_source() -> str:
    return "hardhat-artifact" if os.path.isfile(ARTIFACT_PATH) else "embedded"
