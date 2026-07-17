# Deploying Basilisk Context

Since you are transitioning Basilisk into a full SaaS platform, the services must be hosted.
Here is the checklist.

## 1. Hosting the Backend (FastAPI + PostgreSQL)

We recommend **Railway**, **Render**, or **Heroku** as they seamlessly support Docker/Python and PostgreSQL.

### Steps:
1. Push `basilisk-backend` to a GitHub repository.
2. Sign in to your hosting provider and link the repo.
3. Add a PostgreSQL database add-on (often automatic).
4. Set the following environment variables in your provider's dashboard:
   - `DATABASE_URL` (usually provided automatically by the database add-on)
   - `SECRET_KEY` (generate a random 32+ char string and put it here)
   - `DEBUG=False`
   - `BASILISK_FRONTEND_URL` (e.g., `https://basilisk.app`)
   - `BASILISK_BACKEND_URL` (e.g., `https://api.basilisk.app`)
5. Deploy the service. (FastAPI via Uvicorn will automatically create all tables on startup due to `create_tables()` in `main.py`).

## 2. Hosting the Frontend (React + Vite)

We recommend **Vercel**, **Netlify**, or **Cloudflare Pages** for static site hosting.

### Steps:
1. Push `basilisk-frontend` to a GitHub repository.
2. Link the repository to Vercel/Netlify.
3. Configure the build command: `npm run build`
4. Configure the output directory: `dist`
5. Set the environment variables in the dashboard:
   - `VITE_BACKEND_URL=https://api.basilisk.app` (Whatever domain the backend generated)
6. Deploy!

## 3. Updating the CLI (Production Configuration)

Once both the backend and frontend are live, you MUST update the hardcoded local URLs in the Basilisk CLI:

1. Open `basilisk/reporter.py`
2. Change: `BACKEND_URL = "http://localhost:8000"` to your real backend URL.
3. Open `basilisk/auth.py`
4. Change: `BACKEND_URL` to your real backend URL.
5. Change: `FRONTEND_URL` to your real frontend URL.
6. Open `basilisk/cli.py`
7. Change: `DASHBOARD_URL = "http://localhost:3000"` to your real frontend URL.
8. Re-install the CLI (`pip install -e .` or publish to PyPI).

Done! Your full platform is now live.
