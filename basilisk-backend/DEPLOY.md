# Deploying Basilisk SaaS

## Live URLs

- Backend: https://basilisk-ja22.onrender.com
- Frontend: https://basilisk-livid.vercel.app

## After pulling these SaaS fixes

### 1. Redeploy backend (Render)

Required because device codes are now stored in the database (new `device_codes` table).

1. Push `basilisk-backend` changes (or the monorepo root if Render deploys from it).
2. Confirm env vars on Render:
   - `DATABASE_URL` (Postgres add-on)
   - `SECRET_KEY`
   - `DEBUG=False`
   - `BASILISK_FRONTEND_URL=https://basilisk-livid.vercel.app`
   - `BASILISK_BACKEND_URL=https://basilisk-ja22.onrender.com`
3. Deploy. On startup `create_tables()` creates the new `device_codes` table.

Smoke: open https://basilisk-ja22.onrender.com/api/health → `{"status":"ok"}`

### 2. Redeploy frontend (Vercel)

Important: the app entry is now `src/main.tsx` (React dashboard), not the Vite starter template.

1. Set env var (Production):
   - `VITE_BACKEND_URL=https://basilisk-ja22.onrender.com`
2. Build command: `npm run build`
3. Output: `dist`
4. Redeploy so Auth + Dashboard pick up the real API key flow.

### 3. CLI (already pointed at prod)

`basilisk/auth.py`, `reporter.py`, and `cli.py` use the Render/Vercel URLs.
Reinstall locally after pull:

```bash
pip install -e .
```

### 4. End-to-end check

```bash
basilisk auth
# Complete code + email on https://basilisk-livid.vercel.app/auth
basilisk scan https://example.com --no-llm
# Open dashboard → see the run → open scan detail
```

Note: Render free tier may cold-start (~30–60s). CLI auth poll timeout is 180s.
