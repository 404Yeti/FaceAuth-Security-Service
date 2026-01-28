# FaceAuth Security Service (Python)

A security-focused facial authentication API built with FastAPI.  
Uses pretrained face embeddings (via `face_recognition`) + similarity matching + simple liveness checks, and ships with JWT auth, RBAC, lockouts, and audit logging.

## Features
- Face enrollment (`/enroll`)
- Face verification + liveness (2-photo motion heuristic) (`/verify`)
- JWT token issuance on successful verification
- RBAC roles: `user`, `admin`, `analyst`
- Protected endpoints (`/me`, `/search`, `/admin/events`)
- 1:N face search (authenticated) (`/search`)
- Quality gate (blur/brightness checks)
- Lockout policy (basic brute-force protection)
- Audit log/events (`/admin/events`, plus internal event logging)

## Architecture (high-level)
1. **Enrollment**
   - image → face embedding → store in SQLite
2. **Verification**
   - image1+image2 → embedding match (cosine distance) + liveness (motion) → decision
   - on success → issue JWT
3. **Search**
   - query image → embedding → nearest neighbors over stored embeddings (1:N)

## Tech Stack
- Python 3.10+
- FastAPI + Uvicorn
- OpenCV
- face_recognition (dlib embeddings)
- SQLite
- JWT (python-jose)

## Setup

### 1) Install system deps (Ubuntu/WSL)
```bash
sudo apt update
sudo apt install -y python3-venv build-essential cmake python3-dev libopenblas-dev liblapack-dev
```
### 2) Create venv + install deps
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip

pip install fastapi uvicorn python-multipart numpy opencv-python face_recognition "python-j

### 3) Set environment variables
export FACEAUTH_SECRET_KEY="change-this-to-a-long-random-string"
export ACCESS_TOKEN_TTL_SECONDS="3600"

### 4) Run
uvicorn app:app --reload --port 8000

### Open docs:

http://127.0.0.1:8000/docs

### API Quickstart
Enroll

POST /enroll?username=rob with multipart form-data image

Verify (returns JWT)

POST /verify?username=rob with image1 and image2

Example success response:
```
{
  "authenticated": true,
  "token": "JWT_HERE",
  "role": "user",
  "d1": 0.04,
  "d2": 0.05,
  "motion": 0.12,
  "liveness_pass": true
}
```

### Use token (Swagger)

Click Authorize and paste:

Bearer <token>

### 1:N Search (authenticated)

POST /search with multipart image

Admin: view events (admin/analyst)

GET /admin/events

### Security Notes (MVP)

Liveness is a basic motion heuristic (not true anti-spoof). Upgrade path: blink/head-turn challenge with facial landmarks.

Uses a pretrained embedding model (no model training in this repo).

Do not store real user face data in public repos.

Do not commit .env or DB files.

### Roadmap

True liveness (blink/head turn)

FAISS vector index for scalable search

Metrics endpoint (top failed IPs, lockouts/hour)

Docker + CI

Tests (matcher, liveness, API)
