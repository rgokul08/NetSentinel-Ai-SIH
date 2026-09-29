# CyberForecast AI — Blockchain Integrity Layer

On-chain trust anchor for the platform's security-event ledger. **Only 32-byte
hashes and a short event-type label ever reach the chain** — traffic captures,
alert bodies, emails, passwords and model artifacts stay in the off-chain
database.

```
contracts/SecurityEventRegistry.sol   the anchored-hash registry (Solidity 0.8.24)
scripts/compile-solcjs.js             offline compiler -> Hardhat-compatible artifacts
scripts/test-contract.js              offline test-suite (in-process Ganache EVM)
scripts/deploy.js                     deploy + write deployments/<network>.json
scripts/record-hash.js                anchor one hash, or sync every unanchored entry
scripts/verify-events.js              third-party verification of the whole ledger
test/SecurityEventRegistry.test.js    same guarantees expressed as Hardhat/Chai tests
hardhat.config.js                     networks: hardhat, localhost, amoy (Polygon testnet)
deployments/                          generated deployment records (git-ignored)
artifacts/                            generated compiler output (git-ignored)
```

## What the contract guarantees

| Guarantee | Mechanism |
| --- | --- |
| **Immutability** | `recordEventHash` reverts if the `eventId` is already anchored; there is no update or delete path. |
| **Authorization** | only `owner` or addresses whitelisted via `setRecorder` may write; `transferOwnership` revokes the previous owner. |
| **Public verifiability** | `verifyEventHash` and `getEventRecord` are `view` functions — anyone can check a stored event without a role. |
| **Privacy** | storage holds `bytes32` hash + timestamp + recorder + short label. No payload, no PII, no packet data. |
| **Gas efficiency** | `recordEventHashBatch` anchors many events in one transaction (≈⅓ of the gas per event). |

## Quick start (fully offline)

Everything below works without internet access: the Solidity compiler ships in
`node_modules/solc` and the EVM in `node_modules/ganache`.

```bash
cd blockchain
npm install

npm run compile:offline     # solc-js 0.8.24 -> artifacts/ (Hardhat layout)
npm run test:offline        # 43 assertions against a real in-process EVM
```

`compile:offline` writes
`artifacts/contracts/SecurityEventRegistry.sol/SecurityEventRegistry.json`, which
the backend loads automatically — `GET /api/blockchain/contract` then reports
`abi_source: "hardhat-artifact"` instead of the embedded fallback, so the ABI can
never drift from the source.

## Run a local chain and anchor for real

```bash
# terminal 1 — local EVM on :8545, chainId 31337, deterministic funded accounts
npm run node:offline

# terminal 2 — deploy (uses BLOCKCHAIN_PRIVATE_KEY from blockchain/.env)
cp .env.example .env        # then paste account (0)'s key from the node output
npm run deploy:local
```

The deploy script prints the exact lines to add to `backend/.env`:

```dotenv
BLOCKCHAIN_ANCHOR_ENABLED=true
BLOCKCHAIN_RPC_URL=http://127.0.0.1:8545
BLOCKCHAIN_CHAIN_ID=31337
BLOCKCHAIN_CONTRACT_ADDRESS=0x...
BLOCKCHAIN_PRIVATE_KEY=0x...   # an authorized recorder key
```

Restart the backend and `GET /api/blockchain/status` reports
`anchor.mode = "evm"`, `connected = true`, `recorder_allowed = true`. Every new
ledger entry is then anchored in the same request that writes it
(`anchor_mode`, `tx_hash`, `block_number`, `chain_id`, `contract_address` and
`recorder_address` are stored on the entry).

### Anchoring entries written while the chain was unreachable

The local hash chain stays authoritative, so a failed anchor never blocks an
event — it is marked pending and can be anchored later:

```bash
# backend-side retry (anchors pending entries)
curl -X POST -H "Authorization: Bearer $JWT" "$API/blockchain/retry-pending?limit=20"

# or from the blockchain tooling, batched into ONE transaction
npm run record -- --sync --token "$JWT" --limit 200
```

### Independent verification

`verify-events.js` does **not** trust the backend's verdict. It reads the ledger
through the public API, recomputes the contract key (`SHA-256` of the ledger id,
identical to `backend/app/blockchain/hashing.py:event_id_to_bytes32`) and asks
the contract whether each stored hash still matches:

```bash
npm run verify:events -- --token "$JWT" --limit 200
# or sign in with the demo admin
npm run verify:events -- --email admin@cyberforecast.ai --password Admin@1234
```

```
RPC          : http://127.0.0.1:8545 (chainId 31337)
Contract     : 0xe78A0F7E598Cc8b0Bb87894B0F60dD2a88d6a8Ab
On-chain     : 64 anchored events
Ledger rows  : 65 of 65 inspected

  matched     : 64
  mismatched  : 0
  not anchored: 0
  tamper demos: 1 (intentionally excluded from anchoring)

RESULT: PASS — every anchored entry matches its on-chain commitment.
```

The script exits non-zero on any mismatch, so it can run in CI. Tamper-demonstration
entries (created deliberately broken by the seeder and by the Integrity Ledger UI)
are excluded — a known-corrupt record must never be blessed on-chain.

## Polygon Amoy testnet

```bash
# .env
BLOCKCHAIN_PRIVATE_KEY=0x<throwaway testnet key>
BLOCKCHAIN_RPC_URL=https://rpc-amoy.polygon.technology
BLOCKCHAIN_CHAIN_ID=80002
POLYGONSCAN_API_KEY=<optional, for verification>

npm run deploy:amoy
npm run verify:events -- --token "$JWT"
```

Fund the wallet from an Amoy faucet first. The same `backend/.env` values switch
the platform from `local-hash-chain` to `evm` mode; the UI (Integrity Ledger page)
shows the contract address, chain id, recorder address and on-chain event count.

## Graceful degradation

The backend never hard-depends on a chain:

| Condition | Behaviour |
| --- | --- |
| No RPC configured | `anchor.mode = "local-hash-chain"`; SHA-256 hash chain still detects tampering. |
| RPC configured but unreachable | entries are written locally with `anchor_mode = "local"` and can be anchored later via retry/sync. |
| Contract deployed, recorder not whitelisted | `recorder_allowed = false` is surfaced in `/api/blockchain/status` and the UI. |
| Chain returns a different id than expected | `chain_id` and `expected_chain_id` are both reported; anchoring is refused. |

## Tests

```bash
npm run test:offline   # 43 assertions, no internet, ~2s
npm test               # Hardhat/Chai version of the same suite (needs `hardhat compile`)
```

Covered: deployment state, anchoring + event emission, hash verification,
tamper detection, immutability (re-anchor reverts), empty-input reverts,
recorder authorization and revocation, batch anchoring (including duplicate
skipping, length validation and per-event gas savings), ownership transfer with
revocation of the previous owner, and the privacy guarantee that no payload
content is recoverable from storage or bytecode.
