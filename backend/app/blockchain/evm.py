"""
Optional EVM anchoring for security-event hashes.

Uses web3.py against any JSON-RPC endpoint (Hardhat node, Anvil, Polygon Amoy).
When no RPC / key / contract address is configured - or the node is unreachable -
the platform transparently continues with the local hash-chain ledger, so the
rest of the application never depends on blockchain availability.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Dict, Optional

from app.blockchain.contract import abi_source, load_abi
from app.blockchain.hashing import bytes32_to_hash, event_id_to_bytes32, hash_to_bytes32
from app.core.config import settings

logger = logging.getLogger("cyberforecast.blockchain")


class EvmAnchor:
    """Thin, thread-safe wrapper around the SecurityEventRegistry contract."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._w3 = None
        self._contract = None
        self._account = None
        self._last_error: Optional[str] = None
        self._last_check: float = 0.0
        self.enabled = bool(settings.blockchain_anchor)

    # -- connection --------------------------------------------------------
    def _connect(self):
        if self._w3 is not None:
            return self._w3
        if not self.enabled:
            return None
        from web3 import Web3

        rpc = settings.blockchain_rpc_url
        if rpc.startswith("ws"):
            from web3 import WebsocketProviderV2 as _WS  # type: ignore  # noqa: F401

            raise RuntimeError("WebSocket RPC is not supported by the anchor; use an HTTP(S) RPC URL")
        w3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": settings.blockchain_tx_timeout}))
        if not w3.is_connected():
            raise RuntimeError(f"RPC endpoint unreachable: {rpc}")
        account = w3.eth.account.from_key(settings.blockchain_private_key)
        contract = w3.eth.contract(address=w3.to_checksum_address(settings.blockchain_contract_address), abi=load_abi())
        self._w3, self._contract, self._account = w3, contract, account
        return w3

    @property
    def configured(self) -> bool:
        return self.enabled

    def status(self) -> Dict[str, Any]:
        """Live status used by the health endpoint and the Admin console."""
        if not self.enabled:
            return {
                "mode": "local-hash-chain",
                "configured": False,
                "connected": False,
                "reason": "BLOCKCHAIN_RPC_URL / PRIVATE_KEY / CONTRACT_ADDRESS not configured",
                "abi_source": abi_source(),
            }
        now = time.time()
        if now - self._last_check > 30:  # cache probe for 30s
            self._last_check = now
            try:
                w3 = self._connect()
                chain_id = int(w3.eth.chain_id)
                block = int(w3.eth.block_number)
                recorder_allowed = bool(self._contract.functions.recorders(self._account.address).call())
                count = int(self._contract.functions.eventCount().call())
                self._last_error = None
                self._status_cache = {
                    "mode": "evm",
                    "configured": True,
                    "connected": True,
                    "chain_id": chain_id,
                    "expected_chain_id": settings.blockchain_chain_id,
                    "block_number": block,
                    "recorder_address": self._account.address,
                    "recorder_allowed": recorder_allowed,
                    "contract_address": settings.blockchain_contract_address,
                    "onchain_event_count": count,
                    "abi_source": abi_source(),
                }
            except Exception as exc:
                self._last_error = str(exc)[:200]
                self._status_cache = {
                    "mode": "evm",
                    "configured": True,
                    "connected": False,
                    "error": self._last_error,
                    "abi_source": abi_source(),
                }
        return getattr(self, "_status_cache", {"mode": "evm", "configured": True, "connected": False})

    @staticmethod
    def _apply_fee_strategy(w3: Any, tx: Dict[str, Any]) -> None:
        """Fill gas pricing that matches what the connected chain expects.

        web3.py v7 rejects a legacy `gasPrice` next to the EIP-1559 fields it
        auto-populates, so the two strategies must never be mixed: chains that
        report a base fee get `maxFeePerGas`/`maxPriorityFeePerGas`, older or
        simpler chains (some local nodes) get `gasPrice`.
        """
        base_fee = None
        try:
            block = w3.eth.get_block("latest")
            base_fee = block.get("baseFeePerGas") if hasattr(block, "get") else getattr(block, "baseFeePerGas", None)
        except Exception:
            base_fee = None

        if base_fee is not None:
            try:
                priority = int(w3.eth.max_priority_fee)
            except Exception:
                priority = 1_000_000_000  # 1 gwei
            tx["maxPriorityFeePerGas"] = priority
            tx["maxFeePerGas"] = int(base_fee) * 2 + priority
            tx.pop("gasPrice", None)
            return

        tx.pop("maxFeePerGas", None)
        tx.pop("maxPriorityFeePerGas", None)
        tx["gasPrice"] = int(w3.eth.gas_price)

    # -- writes ------------------------------------------------------------
    def record(self, event_id: str, event_hash: str, event_type: str) -> Dict[str, Any]:
        """Anchor a hash on-chain. Returns tx metadata or a failure description."""
        if not self.enabled:
            return {"anchored": False, "reason": "evm-anchor-disabled"}
        with self._lock:
            try:
                w3 = self._connect()
                fn = self._contract.functions.recordEventHash(
                    event_id_to_bytes32(event_id), hash_to_bytes32(event_hash), event_type[:64]
                )
                tx = fn.build_transaction({
                    "from": self._account.address,
                    "nonce": w3.eth.get_transaction_count(self._account.address),
                    "chainId": int(w3.eth.chain_id),
                })
                try:
                    tx["gas"] = int(fn.estimate_gas({"from": self._account.address}) * 1.25)
                except Exception:
                    tx["gas"] = 350_000
                self._apply_fee_strategy(w3, tx)
                signed = self._account.sign_transaction(tx)
                tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction if hasattr(signed, "raw_transaction") else signed.rawTransaction)
                receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=settings.blockchain_tx_timeout)
                return {
                    "anchored": bool(receipt and receipt.get("status") == 1),
                    "tx_hash": w3.to_hex(tx_hash),
                    "block_number": int(receipt.get("blockNumber")) if receipt else None,
                    "chain_id": int(w3.eth.chain_id),
                    "contract_address": settings.blockchain_contract_address,
                    "recorder_address": self._account.address,
                    "gas_used": int(receipt.get("gasUsed")) if receipt else None,
                }
            except Exception as exc:
                logger.warning("EVM anchoring failed for %s: %s", event_id, exc)
                self._last_error = str(exc)[:200]
                return {"anchored": False, "reason": str(exc)[:200]}

    # -- reads -------------------------------------------------------------
    def read_record(self, event_id: str) -> Dict[str, Any]:
        """Fetch the on-chain record for an event id."""
        if not self.enabled:
            return {"available": False, "reason": "evm-anchor-disabled"}
        try:
            w3 = self._connect()
            exists, event_hash, timestamp, recorder, event_type = self._contract.functions.getEventRecord(
                event_id_to_bytes32(event_id)
            ).call()
            return {
                "available": True,
                "exists": bool(exists),
                "event_hash": bytes32_to_hash(event_hash) if exists else None,
                "timestamp": int(timestamp) if exists else None,
                "recorder": recorder if exists else None,
                "event_type": event_type if exists else None,
                "contract_address": settings.blockchain_contract_address,
                "chain_id": int(w3.eth.chain_id),
            }
        except Exception as exc:
            self._last_error = str(exc)[:200]
            return {"available": False, "reason": str(exc)[:200]}

    def verify_onchain(self, event_id: str, event_hash: str) -> Dict[str, Any]:
        if not self.enabled:
            return {"available": False, "reason": "evm-anchor-disabled"}
        try:
            w3 = self._connect()
            matches = bool(
                self._contract.functions.verifyEventHash(
                    event_id_to_bytes32(event_id), hash_to_bytes32(event_hash)
                ).call()
            )
            return {"available": True, "matches": matches}
        except Exception as exc:
            self._last_error = str(exc)[:200]
            return {"available": False, "reason": str(exc)[:200]}


anchor = EvmAnchor()
