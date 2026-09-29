# CyberForecast AI

**AI-Based Network Attack Forecasting from Network Traffic Data**
*Smart India Hackathon — Blockchain & Cybersecurity theme*

A production-grade Security Operations Center (SOC) platform that doesn't just
detect attacks — it **forecasts** them. Network flows are scored by a real
scikit-learn pipeline (multi-class classifier + Isolation Forest anomaly
detector), aggregated into time-series attack forecasts across 5–60 minute
horizons, triaged into alerts, and anchored into a **tamper-evident integrity
ledger** whose hashes can be committed to an EVM blockchain.

Everything in this repository works: no mock buttons, no hard-coded statistics,
no placeholder pages. The backend exposes **98 documented REST endpoints**, the
frontend ships **19 complete pages**, and three test suites (173 unit tests +
127 live smoke checks + 43 on-chain contract assertions) verify it end to end.

---

## ✨ What it does

| Capability | Detail |
| --- | --- |
| **Attack detection** | RandomForest / HistGradientBoosting / ExtraTrees / LogisticRegression classifiers over 48 engineered features, 8 classes (Benign, DoS, DDoS, Port Scan, Brute Force, Bot Activity, Intrusion, Network Anomaly) + Isolation Forest anomaly scoring. A transparent heuristic baseline takes over — clearly labelled — when no model is active. |
| **Attack forecasting** | Ridge regression over lagged features with a Poisson link, per attack category, at 5/15/30/60-minute horizons, with confidence bands and explicit uncertainty. Refuses to guess with insufficient history. |
| **Explainable AI** | Per-prediction feature attributions, model-wide feature importance, confusion matrices and per-class precision/recall/F1 in the ML Model Center. |
| **Live SOC dashboard** | KPIs, threat gauge, attack distribution, live activity feed and trend charts over a WebSocket channel (`/api/traffic/ws`) — all computed from stored data. |
| **Simulation mode** | 7 labelled attack scenarios with intensity/duration/tick controls, one-shot attack injection and live tick telemetry. Every simulated artefact is flagged `is_simulated` and badged "Simulation Mode" in the UI — never presented as real traffic. |
| **Alert triage** | Throttled alert creation, status workflow, analyst notes, assignment, full triage history, CSV export. |
| **Integrity ledger** | Every security event is SHA-256 hash-chained (canonical JSON). Optional EVM anchoring stores only 32-byte hashes on-chain via the `SecurityEventRegistry` Solidity contract, with one-click verification, chain-wide auditing and a deliberately broken "tamper demo" entry that proves detection works. |
| **Reports** | Executive PDF briefs (ReportLab) and CSV exports with real sections: KPIs, attack summary, forecasts, model performance, ledger integrity. |
| **Datasets** | Upload CSV/JSON (auto schema mapping incl. CIC-IDS-style headers), preview with column mapping, profiling, one-click analysis through the live pipeline, retraining, forecasting — plus bundled sample datasets. |
| **Auth & RBAC** | JWT auth, bcrypt hashing, optional TOTP MFA with QR provisioning, three roles (Admin / Analyst / Viewer) with a server-enforced capability matrix and a hash-chained audit trail of every privileged action. |

## 🚀 Quick start

**Backend** (Python 3.10+):

```bash
cd backend
pip install -r requirements.txt
cp .env.example .env            # optional — sane defaults are built in
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
# API docs: http://localhost:8000/api/docs
```

**Frontend** (Node 18+):

```bash
cd frontend
npm install
npm run dev                     # http://localhost:3000 (proxies /api + WebSocket)
```

Or one-click on Windows: `run_project.bat` / `run_project.ps1`.
Or the full stack with Docker: `docker compose up --build`.

**Demo logins** (seeded automatically on first boot):

| Role | Email | Password |
| --- | --- | --- |
| Administrator | `admin@cyberforecast.ai` | `Admin@1234` |
| Security Analyst | `analyst@cyberforecast.ai` | `Analyst@1234` |
| Viewer (read-only) | `viewer@cyberforecast.ai` | `Viewer@1234` |

> The seeder trains real models on the bundled labelled dataset, generates
> traffic through the normal analysis pipeline, runs a forecast and writes the
> ledger genesis entry. Nothing is faked; first boot takes a minute or two.

## 🧪 Verify it yourself

```bash
# unit + HTTP integration suite (173 tests, hermetic, no server needed)
cd backend && python -m pytest tests

# live end-to-end smoke test against a running backend (127 checks)
python backend/scripts/smoke_test.py

# blockchain layer: compile + 43 contract assertions, fully offline
cd blockchain && npm install && npm run test:offline
```

## ⛓️ Blockchain integrity layer

```
blockchain/contracts/SecurityEventRegistry.sol   the on-chain hash registry
blockchain/scripts/compile-solcjs.js             offline Solidity 0.8.24 compiler
blockchain/scripts/test-contract.js              43-assertion suite on a real in-process EVM
blockchain/scripts/deploy.js                     deploy → deployments/<network>.json + backend .env lines
blockchain/scripts/record-hash.js                anchor one hash, or batch-sync unanchored entries
blockchain/scripts/verify-events.js              independent third-party verification (CI-friendly)
```

Design rules (enforced by contract + tests):

- **Only hashes go on-chain** — event content, IPs, emails and credentials never do.
- **Immutability** — an anchored `eventId` can never be re-anchored or altered.
- **Authorization** — only the owner or whitelisted recorder addresses may write.
- **Public verifiability** — `verifyEventHash` / `getEventRecord` are free view calls.
- **Graceful degradation** — no RPC? The local SHA-256 hash chain still detects any
  tampering; entries written while offline are anchored later via retry/sync.

```bash
cd blockchain
npm run node:offline          # local EVM on :8545 (chainId 31337)
npm run deploy:local          # → prints the backend/.env lines to enable EVM mode
npm run record -- --sync --token "$JWT"       # batch-anchor pending entries
npm run verify:events -- --token "$JWT"       # independent PASS/FAIL audit
```

See [`blockchain/README.md`](blockchain/README.md) for the full guide, including
Polygon Amoy testnet deployment.

## 🖥️ Frontend pages (19)

Login (with MFA challenge) · Reset password · Dashboard · Live Traffic ·
Analytics · Timeline · Threat Map · Detection Lab · Forecast · Alerts ·
Reports · ML Model Center · Datasets · Integrity Ledger (blockchain) ·
Simulation Console · Audit Logs · Admin Console · Settings · 404.

Every page implements real loading, error and empty states, and every statistic
is fetched from the API. Role-gated pages hide controls in the UI *and* are
enforced server-side.

## ⚙️ Configuration

Copy `backend/.env.example` → `backend/.env` and `frontend/.env.example` →
`frontend/.env.local` if you need to deviate from the defaults (SQLite storage,
local hash-chain ledger, demo seeding). Highlights:

| Variable | Purpose |
| --- | --- |
| `DATABASE_URL` | SQLite by default; point at PostgreSQL for persistence |
| `JWT_SECRET_KEY` | **Set a long random value in production** |
| `CORS_ORIGINS` / `CORS_ALLOW_ALL` | Lock CORS to your frontend origin when deploying |
| `APPWRITE_*` | Optional Appwrite cloud backend (auth/DB/storage) with SQL fallback |
| `BLOCKCHAIN_*` | Optional EVM anchoring (RPC, chain id, contract, recorder key) |
| `SEED_DEMO_DATA` / `SEED_TRAFFIC_RECORDS` | Demo bootstrap volume |
| `VITE_API_URL` | Frontend → backend URL when not same-origin |

**Never commit real secrets or a funded wallet key.** Testnet keys only.

## ☁️ Deployment

| Target | How |
| --- | --- |
| **Vercel** (frontend + backend) | `vercel.json` defines a Services project; see [`docs/VERCEL_DEPLOYMENT.md`](docs/VERCEL_DEPLOYMENT.md) |
| **Render** (backend) | [`backend/render.yaml`](backend/render.yaml) blueprint (Postgres optional) |
| **Docker** | `docker-compose.yml` — Postgres + FastAPI + nginx frontend (+ optional local chain profile) |
| **Blockchain** | local Ganache for demos, Polygon Amoy (`chainId 80002`) for the real thing |

## 📁 Repository layout

```
frontend/    React 18 + Vite + Tailwind SOC dashboard (19 pages)
backend/     FastAPI app (app/), ML engine (app/ml), tests, smoke test
blockchain/  Solidity contract + Hardhat/offline tooling + tests
docs/        architecture, Vercel guide, SIH presentation guide
vercel.json  Vercel Services config (frontend + backend, /api routing)
docker-compose.yml, run_project.bat/.ps1, render blueprint (backend/render.yaml)
```

Full technical detail: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## 🔒 Security & honesty guarantees

- Passwords are bcrypt-hashed; secrets are stripped from every hash and log.
- The audit trail and the integrity ledger are both SHA-256 chained — silent
  edits are detectable and the UI shows the verification verdict.
- Predictions are presented as **estimates with confidence**, never certainty.
- Simulated traffic is always labelled; the threat map uses abstracted regions,
  not real geolocation, and says so.
- The frontend never makes trusted security decisions — every capability is
  re-validated by the API.

## 📄 License

MIT — see the header in `app/main.py`.
