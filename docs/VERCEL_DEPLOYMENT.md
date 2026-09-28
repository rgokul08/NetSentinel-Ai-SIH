# Deploying NetSentinel-AI on Vercel

This project is configured as a Vercel **Services** project (see the root
`vercel.json`): one Vercel project builds and serves two services.

| Service   | Root       | Framework | Notes                                   |
| --------- | ---------- | --------- | --------------------------------------- |
| `frontend`| `frontend/`| Vite      | React SPA, output `dist`, `/api/*` proxied away |
| `backend` | `backend/` | FastAPI   | Python runtime, entrypoint `main:app`   |

Routing rules (top level in `vercel.json`):

1. `/api/*`  → `backend` service (original path is preserved, e.g. `/api/auth/login`)
2. `/*`      → `frontend` service (SPA fallback to `index.html` for client routes)

## Steps

1. Push this repository to GitHub.
2. In [Vercel](https://vercel.com/new), **Import** the repository.
3. Keep the project's **Framework** setting as **Services** — required for the
   `services` block in `vercel.json` to be used (Settings → General →
   Framework Preset). The build log showing `Service "backend" ...` confirms
   it is active.
4. Deploy. The build runs `vercel build`, which:
   - builds the Vite app in `frontend/` (`npm run build` → `dist/`),
   - packages the FastAPI app in `backend/` as a single Python function from
     the `main:app` entrypoint (`backend/main.py`, which re-exports
     `app.main:app`).

## Environment variables (optional but recommended)

| Variable        | Purpose                                                                 |
| --------------- | ----------------------------------------------------------------------- |
| `DATABASE_URL`  | PostgreSQL connection string. If unset, the backend uses SQLite at `/tmp/network_security.db` (per-instance demo data — fine for demos). For persistent data use a hosted Postgres such as [Neon](https://neon.tech) or Vercel Postgres: `postgresql://user:pass@host/db?sslmode=require` |
| `JWT_SECRET_KEY`| Secret for signing login tokens. Falls back to a development default — set your own in production. |

> The Docker/Postgres setup in `docker-compose.yml` is unaffected — it sets
> `DATABASE_URL` itself.

## What makes the backend Vercel-ready

- **Explicit entrypoint** — `services.backend.entrypoint = "main:app"`.
  Without it, Vercel fails with:
  `Service "backend" detected framework "fastapi" ... must specify an "entrypoint" for runtime "python".`
- **Self-contained service root** — `ml/` and `dataset/` live inside
  `backend/`, so everything is bundled with the function (Vercel only ships
  files under the service root).
- **Read-only filesystem** — CSV uploads and trained model artifacts fall
  back to `/tmp` automatically (`backend/app/paths.py`); the SQLite fallback
  database also lives in `/tmp`.
- **Docs under the proxy prefix** — on Vercel the OpenAPI docs are served at
  `/api/docs` (local: `/docs`).
- **Python 3.13-compatible dependency ranges** — `backend/requirements.txt`
  uses bounded ranges so pip resolves wheels for the current Vercel Python
  runtime. Python function bundles are limited to 500 MB uncompressed; this
  stack (numpy/pandas/scikit-learn/scipy/reportlab) fits with margin.

## Verify a deployment

- `GET /` — React dashboard (login: `admin@soc.guard` / `Admin@1234`)
- `GET /api/` — backend status JSON (`{"status": "ONLINE", ...}`)
- `GET /api/docs` — interactive API documentation
- Login, dashboard, traffic, detection, forecast, alerts and reports pages
  all call the backend through the same-origin `/api` prefix — no CORS
  configuration needed.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| `must specify an "entrypoint" for runtime "python"` | `services.backend.entrypoint` must be `main:app` (already set) and `backend/main.py` must exist. |
| Services config ignored (build behaves like a plain frontend) | Project Framework setting must be **Services**. |
| 404 on deep links like `/dashboard` | The frontend service has an SPA fallback rewrite to `index.html` (already set). |
| Login works but data resets on every deploy | No `DATABASE_URL` configured — add hosted Postgres for persistent data. |
| Function size errors | Keep heavy packages out of `backend/requirements.txt`; the Python limit is 500 MB uncompressed. |
