# FYP Python Web App

Flask-based web app with admin/user flows, OTP emails, and scan history. This repo is prepared for deployment on Render.

## Local Setup
- Create and activate a virtual environment.
- `pip install -r requirements.txt`
- Create `.env` with your secrets (see Environment variables).
- Run locally: `python app.py` (debug) or `gunicorn app:app`.

## Environment Variables
Set these in `.env` locally and in Render as Service Environment Variables (don’t commit `.env`).

Core:
- `SECRET_KEY` — Flask session key
- `MONGO_URI` — MongoDB connection string
- `MONGO_DB` — Database name (default: `fyp_app`)
- `ADMIN_USERNAME` — Admin login username
- `ADMIN_PASSWORD` or `ADMIN_PASSWORD_HASH` — Admin credential

Email (choose one path):
- SendGrid: `SENDGRID_API_KEY`, `EMAIL_FROM`
- SMTP: `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `EMAIL_FROM`

Optional integrations:
- `VT_API_KEY` — VirusTotal
- AI provider: `AI_PROVIDER` (`heuristic`, `openai`, or `ollama`)
- OpenAI: `OPENAI_API_KEY`, `OPENAI_MODEL` (e.g., `gpt-4o-mini`)
- Ollama: `OLLAMA_HOST`, `OLLAMA_MODEL`
- Google OAuth: `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`

## Deploy to Render
1. Push this repo to GitHub.
2. In Render, create a new **Web Service** and connect the repo.
3. Set:
   - **Environment**: `Python 3`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn app:app`
4. Add your Environment Variables in the Render service settings.
5. Deploy.

Notes:
- External CLI tools (`subfinder`, `nuclei`, etc.) may not be available on Render; features depending on them will be disabled or should be guarded.
- Ensure secrets are present in Render; missing envs can cause email or DB features to fail.

## Admin & Cascade Delete
- Deleting a user in the admin panel also deletes their associated scans.
- The admin UI shows how many scans will be removed before deletion.