// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/**
 * SecurityEventRegistry — on-chain integrity anchor for CyberForecast AI.
 *
 * Design rule enforced by this contract: ONLY 32-byte hashes and a short event
 * type label ever reach the chain. Traffic captures, alert bodies, user emails,
 * passwords and model artifacts stay in the off-chain database. A hash is a
 * commitment, not a disclosure.
 *
 * What the contract guarantees
 *  1. Immutability  — once an eventId is anchored its hash can never be changed
 *                     or deleted (there is no setter and no delete path).
 *  2. Authorization — only the owner or addresses explicitly whitelisted through
 *                     `setRecorder` may anchor events.
 *  3. Verifiability — anyone can call the view functions (`verifyEventHash`,
 *                     `getEventRecord`) without a role, so a third party can
 *                     confirm that a stored security event matches what was
 *                     published at a given block time.
 *
 * The backend recomputes `eventHash = keccak256/SHA-256(canonical JSON of the
 * ledger entry)` off-chain, then anchors it here. The FastAPI service degrades
 * gracefully to a local hash chain whenever no RPC is reachable, so this
 * contract is an *additional* trust anchor, never a hard dependency.
 */
contract SecurityEventRegistry {
    /// @notice A single anchored security event.
    struct EventRecord {
        bytes32 eventHash;   // SHA-256 of the canonical ledger entry
        uint256 timestamp;   // block.timestamp at anchoring time
        address recorder;    // address that submitted the anchor
        string eventType;    // short label, e.g. "alert", "model_activated"
    }

    address public owner;
    uint256 public eventCount;

    mapping(address => bool) public recorders;
    mapping(bytes32 => EventRecord) private _records;

    event EventHashRecorded(
        bytes32 indexed eventId,
        bytes32 eventHash,
        string eventType,
        address recorder,
        uint256 timestamp
    );
    event RecorderUpdated(address indexed recorder, bool allowed);
    event BatchRecorded(uint256 count);

    modifier onlyOwner() {
        require(msg.sender == owner, "SecurityEventRegistry: caller is not the owner");
        _;
    }

    modifier onlyRecorder() {
        require(
            msg.sender == owner || recorders[msg.sender],
            "SecurityEventRegistry: caller is not authorized to record events"
        );
        _;
    }

    constructor() {
        owner = msg.sender;
        recorders[msg.sender] = true;
        emit RecorderUpdated(msg.sender, true);
    }

    /**
     * @notice Anchor the hash of one security event.
     * @param eventId   Deterministic identifier hash of the off-chain ledger entry.
     * @param eventHash SHA-256 hash over the canonical event content.
     * @param eventType Short human-readable label used for filtering.
     */
    function recordEventHash(bytes32 eventId, bytes32 eventHash, string calldata eventType)
        external
        onlyRecorder
    {
        require(eventId != bytes32(0), "SecurityEventRegistry: empty eventId");
        require(eventHash != bytes32(0), "SecurityEventRegistry: empty eventHash");
        require(_records[eventId].timestamp == 0, "SecurityEventRegistry: event already anchored (immutable)");

        _records[eventId] = EventRecord({
            eventHash: eventHash,
            timestamp: block.timestamp,
            recorder: msg.sender,
            eventType: eventType
        });
        unchecked {
            eventCount += 1;
        }

        emit EventHashRecorded(eventId, eventHash, eventType, msg.sender, block.timestamp);
    }

    /**
     * @notice Anchor many events in a single transaction to amortise gas.
     * @return recorded Number of newly anchored events (duplicates are skipped).
     */
    function recordEventHashBatch(
        bytes32[] calldata eventIds,
        bytes32[] calldata eventHashes,
        string[] calldata eventTypes
    ) external onlyRecorder returns (uint256 recorded) {
        require(
            eventIds.length == eventHashes.length && eventIds.length == eventTypes.length,
            "SecurityEventRegistry: batch length mismatch"
        );

        for (uint256 i = 0; i < eventIds.length; i++) {
            bytes32 eventId = eventIds[i];
            bytes32 eventHash = eventHashes[i];
            if (eventId == bytes32(0) || eventHash == bytes32(0)) continue;
            if (_records[eventId].timestamp != 0) continue; // already anchored: never overwrite

            _records[eventId] = EventRecord({
                eventHash: eventHash,
                timestamp: block.timestamp,
                recorder: msg.sender,
                eventType: eventTypes[i]
            });
            unchecked {
                eventCount += 1;
            }
            emit EventHashRecorded(eventId, eventHash, eventTypes[i], msg.sender, block.timestamp);
            unchecked {
                recorded += 1;
            }
        }

        emit BatchRecorded(recorded);
    }

    /**
     * @notice Public verification: does the anchored hash match the supplied one?
     * @dev View function — free to call, no authorization required.
     */
    function verifyEventHash(bytes32 eventId, bytes32 eventHash) external view returns (bool) {
        EventRecord storage record = _records[eventId];
        return record.timestamp != 0 && record.eventHash == eventHash;
    }

    /**
     * @notice Full record lookup used by the Integrity Ledger UI.
     */
    function getEventRecord(bytes32 eventId)
        external
        view
        returns (bool exists, bytes32 eventHash, uint256 timestamp, address recorder, string memory eventType)
    {
        EventRecord storage record = _records[eventId];
        exists = record.timestamp != 0;
        if (!exists) {
            return (false, bytes32(0), 0, address(0), "");
        }
        return (true, record.eventHash, record.timestamp, record.recorder, record.eventType);
    }

    /**
     * @notice Whitelist or revoke a backend recorder address (owner only).
     */
    function setRecorder(address recorder, bool allowed) external onlyOwner {
        require(recorder != address(0), "SecurityEventRegistry: zero address");
        recorders[recorder] = allowed;
        emit RecorderUpdated(recorder, allowed);
    }

    /**
     * @notice Transfer contract ownership (owner only).
     * @dev The previous owner loses write access unless it is explicitly
     *      whitelisted again with `setRecorder`, so ownership transfer is a real
     *      revocation of anchoring rights.
     */
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "SecurityEventRegistry: zero address");
        require(newOwner != owner, "SecurityEventRegistry: already the owner");

        address previousOwner = owner;
        owner = newOwner;
        recorders[newOwner] = true;
        emit RecorderUpdated(newOwner, true);

        if (previousOwner != newOwner && recorders[previousOwner]) {
            recorders[previousOwner] = false;
            emit RecorderUpdated(previousOwner, false);
        }
    }
}
