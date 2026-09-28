# NetSentinel-AI

Predict emerging network attacks from traffic patterns before escalation.

AI-based network attack forecasting platform: a React (Vite) SOC dashboard in
front of a FastAPI backend with anomaly detection, multi-class attack
classification, time-series threat forecasting, and explainable AI.

## Project layout

```
frontend/    React + Vite + Tailwind single-page app
backend/     FastAPI API (entrypoint: backend/main.py, app in backend/app/)
backend/ml/      ML engine (preprocessing, training, forecasting, XAI, demo stream)
backend/dataset/ Sample network traffic dataset + generator
docs/        Documentation & presentation guides
vercel.json  Vercel Services config (frontend + backend in one project)
```

## Run locally

Backend (Python 3.10+):

```bash
cd backend
pip install -r requirements.txt
python app/main.py          # http://localhost:8000  (API docs: /docs)
```

Frontend (Node 18+):

```bash
cd frontend
npm install
npm run dev                 # http://localhost:3000 (proxies /api -> :8000)
```

Demo login: `admin@soc.guard` / `Admin@1234`

Or with Docker: `docker compose up --build`

## Deploy on Vercel

The repo is a Vercel **Services** project: `vercel.json` builds the React app
as the `frontend` service and the FastAPI app as the `backend` service, with
`/api/*` routed to the backend. See [docs/VERCEL_DEPLOYMENT.md](docs/VERCEL_DEPLOYMENT.md)
for the full step-by-step guide.

Quick version: push to GitHub → import the repo in Vercel → keep the
framework setting **Services** → deploy. The backend falls back to a writable
SQLite database in `/tmp` when no `DATABASE_URL` is configured.
