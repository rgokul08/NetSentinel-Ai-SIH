# CyberForecast AI — System Architecture

**AI-Based Network Attack Forecasting from Network Traffic Data**
Smart India Hackathon · Blockchain & Cybersecurity theme

---

## 1. High-level topology

```
                        +------------------------------------------+
                        |        React 18 + Vite + Tailwind        |
                        |   SOC dashboard (19 pages, dark theme)   |
                        |   Recharts · WebSocket live feed · RBAC  |
                        +---------------------+--------------------+
                                              |  /api/*  (same-origin, proxied)
                                              |  REST + WebSocket (/api/traffic/ws)
                        +---------------------v--------------------+
                        |          FastAPI backend (98 routes)      |
                        |  JWT auth · RBAC dependencies · ratelimit |
                        |  audit trail · Pydantic v2 validation     |
                        +----+---------------+----------------+----+
                             |               |                |
        +--------------------+     +---------+--------+  +----+-------------------+
        v                          v                  v                        |
+---------------------+   +---------------------+   +---------------------+    |
|      AI/ML engine   |   |   Persistence layer |   |  Integrity ledger   |    |
| sklearn pipeline    |   | SQLAlchemy store    |   | SHA-256 hash chain  |    |
| - classifier (8cls) |   | (SQLite/PostgreSQL) |   | (tamper-evident)    |    |
| - IsolationForest   |   | + optional Appwrite |   +----------+----------+    |
| - Ridge forecaster  |   |   cloud fallback    |              | EVM anchor   |
| - XAI attributions  |   +---------------------+   +----------v----------+    |
+---------------------+                             | SecurityEventRegistry|    |
                                                    | (Solidity 0.8.24)    |    |
                                                    | Hardhat/Ganache/Amoy |    |
                                                    +----------------------+
```

Every arrow is a real, running integration — the repo ships a live smoke test
(`backend/scripts/smoke_test.py`, 127 checks), a unit suite (`backend/tests`,
173 tests) and an offline contract suite (`blockchain`, 43 assertions) that
exercise all of them.

## 2. Runtime data flow

```
network flows / simulation ticks
        │  normalize (aliases → canonical schema, unit fixes)
        ▼
feature engineering (48 features: rates, ratios, one-hot protocol/flags)
        │
        ├──► classifier  → P(class) over 8 classes          (RandomForest default)
        ├──► IsolationForest → anomaly score 0..1           (benign-only training)
        └──► heuristic baseline when no model is active     (labelled honestly)
        ▼
risk score = 0.72·P(attack) + 0.16·anomaly + 0.12·severity(class)   → level
        ▼
persist traffic_records + predictions → alert engine (throttled per src/dst)
        ▼                                  │
RealtimeHub (WebSocket frames)             ├──► integrity ledger event
forecast service (Ridge on lags,           ▼
Poisson link, 5/15/30/60 min horizons)   blockchain.record_event()
                                           ├─ SHA-256 canonical hash → chain
                                           └─ optional EVM anchor (tx hash back)
```

## 3. Repository layout

| Path | Contents |
| --- | --- |
| `backend/app/api/` | 15 routers: auth, traffic, predict, forecast, alerts, models, datasets, reports, blockchain, simulation, audit, admin, system, common |
| `backend/app/ml/` | `features` (normalization + 48-feature frame), `trainer`, `inference`, `forecast`, `scoring`, `xai`, `algorithms` |
| `backend/app/services/` | domain services: pipeline, traffic, analytics, alert, model, dataset, forecast, report, simulation, audit, blockchain-adjacent, seed, settings, health, realtime |
| `backend/app/blockchain/` | `hashing` (canonical hashes), `ledger` (hash chain), `evm` (web3 anchor), `contract` (ABI loader) |
| `backend/app/storage/` | canonical `schema`, SQLAlchemy `orm` (auto-migrating), `sql_store`, optional `appwrite_store` |
| `backend/tests/` | 173 pytest tests: hashing, ledger, audit chain, RBAC, ML pipeline, ABI drift, HTTP API |
| `backend/scripts/smoke_test.py` | 127-check live end-to-end verification |
| `frontend/src/pages/` | 19 pages (Login → Admin), all lazy-loaded behind capability guards |
| `frontend/src/components/` | `ui` primitives, `charts` (Recharts wrappers), `layout`, `threat` widgets |
| `blockchain/` | Solidity contract, offline compiler, offline test-runner, deploy/record/verify scripts |
| `docs/` | this architecture doc, Vercel guide, SIH presentation guide |

## 4. Data model (canonical collections)

Shared by the SQL store and the Appwrite adapter (`app/storage/schema.py`):

| Collection | Key fields |
| --- | --- |
| `users` | email, password_hash (bcrypt) or appwrite_user_id, role, is_active, mfa fields, capabilities (derived) |
| `traffic_records` | timestamp, 5-tuple, counters, engineered rates, risk_score/level, attack_type, true label, is_simulated, region (abstracted) |
| `predictions` | per-flow verdict: probabilities, anomaly, risk, explanation, model ids |
| `alerts` | alert_code, severity, attack_type, IPs (masked for viewers), status, notes, assignment, history[] |
| `forecasts` | run metadata, per-horizon overall + per-category rows, per-bucket probability, confidence, method, disclaimer |
| `datasets` | file metadata, storage backend, row/column counts, profile summary, column mapping |
| `models` | algorithm, task, metrics (accuracy/precision/recall/F1/AUC, confusion matrix, class report, importance), artifact path, active flag |
| `blockchain_events` | event_type, event_hash, prev_hash, chain_position, sanitized payload, anchor_mode, tx_hash, block_number, verification_status |
| `audit_logs` | actor, action, category, resource, outcome, metadata (sanitized), ip, integrity_hash + prev_hash (chained) |
| `reports` / `password_resets` | report metadata/sections; single-use hashed reset tokens |

## 5. Security model

- **Auth**: bcrypt password hashing, JWT access tokens (`HS256`, expiring), optional
  RFC-6238 TOTP MFA (challenge-then-verify login), single-use password-reset tokens.
- **Authorization**: every route declares a capability (`require_capability`) or role
  (`require_role`); the matrix lives in `app/security/rbac.py` and is published at
  `GET /api/auth/roles`. The frontend mirrors it for navigation only.
- **Rate limiting**: slowapi on auth, prediction, ledger writes and exports.
- **Audit**: every security-relevant action is appended to a SHA-256 chained audit
  log; secrets are stripped before hashing and storage.
- **Privacy**: raw packets, credentials and PII never leave the process. IPs are
  masked for the viewer role and the threat map uses abstracted /16 prefixes and
  deterministic synthetic regions (clearly labelled — not geolocation).
- **Blockchain layer**: only 32-byte hashes and a short event-type label reach the
  chain. The local hash chain stays authoritative; EVM anchoring is additive and
  degrades gracefully (pending → retried later) when no RPC is reachable.

## 6. Frontend architecture

- React 18 + Vite 5 + Tailwind 3; SOC-dark design system in `index.css`
  (reduce-motion + compact-density preference hooks).
- Router with `RequireAuth` / `RequireCapability` guards; 19 lazy-loaded pages.
- `AuthContext` (login, MFA challenge branch, capabilities), `RealtimeContext`
  (single WebSocket, fan-out to pages, simulation frames labelled), `ToastContext`.
- `useApi` / `usePoll` / `useAction` hooks give every page consistent
  loading / error / empty states; stats are always fetched, never hard-coded.
- Recharts wrappers (time series, donut, bar, radar, gauge, sparkline) with a
  shared empty-state contract.

## 7. Deployment shapes

| Target | Config |
| --- | --- |
| Local dev | `run_project.ps1` / `run_project.bat`, or backend `uvicorn app.main:app --reload` + frontend `npm run dev` (Vite proxies `/api` + WS) |
| Docker | `docker-compose.yml` (Postgres + backend + nginx frontend, optional `chain` profile with Ganache) |
| Vercel | `vercel.json` Services project: `frontend` (Vite) + `backend` (FastAPI), `/api/*` routed to the backend |
| Render/Railway/Fly | `backend/render.yaml` blueprint; any Python host running `uvicorn app.main:app` |
| Blockchain | local Ganache (`npm run node:offline`) or Polygon Amoy testnet (`npm run deploy:amoy`) |
