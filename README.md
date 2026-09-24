# 🛡️ SOC Sentinel — AI-Assisted Security Operations Center

SOC Sentinel is a portfolio-ready mini Security Operations Center (SOC) platform built with FastAPI, SQLite, SQLAlchemy, JWT authentication, a rule-based threat detection engine, and a responsive JavaScript dashboard.

## Features

- Secure login with JWT + bcrypt password hashing
- Analyst/Admin roles
- Security event ingestion
- Rule-based brute-force, port-scan, suspicious-request and privilege-escalation detection
- Alert severity and status workflow
- Incident management
- Dashboard analytics
- Log/CSV upload and parsing
- IP intelligence placeholder service
- AI-assisted alert explanation abstraction
- API documentation via FastAPI/OpenAPI
- Security headers, CORS configuration, request-rate limiting
- Automated tests and GitHub Actions
- Docker + Docker Compose

## Quick start

### 1. Create a virtual environment

Windows PowerShell:
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

macOS/Linux:
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 2. Install dependencies
```bash
pip install -r backend/requirements.txt
```

### 3. Configure environment
```bash
copy .env.example .env
```
On macOS/Linux:
```bash
cp .env.example .env
```

### 4. Start the API
```bash
uvicorn backend.app.main:app --reload
```

Open:
- Dashboard: http://127.0.0.1:8000
- API docs: http://127.0.0.1:8000/docs

Demo login:
- Email: `analyst@soc.local`
- Password: `ChangeMe123!`

The demo account is created automatically on first startup. Change it before any real deployment.

## Docker
```bash
docker compose up --build
```

## Project structure

```text
soc-sentinel/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   ├── core/
│   │   ├── detection/
│   │   ├── models/
│   │   ├── schemas/
│   │   ├── services/
│   │   ├── static/
│   │   └── main.py
│   ├── tests/
│   └── requirements.txt
├── data/
├── docs/
├── .github/workflows/ci.yml
├── Dockerfile
├── docker-compose.yml
├── .env.example
└── README.md
```

## Security notes

This project is intended for learning and portfolio demonstration. The threat detector is deliberately defensive and analyzes supplied logs/events; it does not execute attacks. For production, use a managed secrets store, HTTPS, PostgreSQL, stronger account lifecycle controls, centralized logging, and a vetted LLM provider with appropriate data handling.

## License
MIT
