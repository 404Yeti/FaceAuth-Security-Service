from __future__ import annotations

from fastapi import FastAPI, UploadFile, File, HTTPException, Request, Depends
import numpy as np

from db import init_db, upsert_user, get_user, set_user_role, list_users, log_event, list_events
from recognition import extract_embedding, cosine_distance, motion_heuristic
from security import check_lockout, register_fail, register_success
from auth import create_access_token, get_current_user, require_role

app = FastAPI(title="FaceAuth Security Service", version="0.2.0")

# Tunables
MATCH_THRESHOLD = 0.35
MOTION_THRESHOLD = 0.03

ALLOWED_ROLES = {"user", "admin", "analyst"}

@app.on_event("startup")
def _startup() -> None:
    init_db()

def _client_ip(req: Request) -> str:
    return req.client.host if req.client else "unknown"

@app.get("/me")
def me(user=Depends(get_current_user)):
    return user

@app.post("/enroll")
async def enroll(request: Request, username: str, image: UploadFile = File(...)):
    ip = _client_ip(request)

    image_bytes = await image.read()
    try:
        res = extract_embedding(image_bytes)
    except ValueError as e:
        log_event("enroll_error", username, ip, {"error": str(e)})
        raise HTTPException(status_code=400, detail=str(e))

    if not res.quality_ok:
        log_event("enroll_rejected", username, ip, {"reason": "quality_gate", "detail": res.quality_reason})
        raise HTTPException(status_code=400, detail={"error": "quality_gate", "detail": res.quality_reason})

    if res.face_count != 1:
        log_event("enroll_rejected", username, ip, {"reason": "invalid_face_count", "face_count": res.face_count})
        raise HTTPException(status_code=400, detail=f"Expected exactly 1 face, found {res.face_count}.")

    # Default role "user" on enrollment
    upsert_user(username, res.embedding.tolist(), role="user")
    log_event("enroll_success", username, ip, {"note": "user embedding stored"})
    return {"ok": True, "username": username, "role": "user"}

@app.post("/verify")
async def verify(
    request: Request,
    username: str,
    image1: UploadFile = File(...),
    image2: UploadFile = File(...),
):
    ip = _client_ip(request)

    locked, fails, remaining = check_lockout(username, ip)
    if locked:
        log_event("verify_locked", username, ip, {"fails": fails, "seconds_remaining": remaining})
        raise HTTPException(status_code=429, detail=f"Locked out. Try again in {remaining}s.")

    user_row = get_user(username)
    if user_row is None:
        log_event("verify_failed", username, ip, {"reason": "unknown_user"})
        raise HTTPException(status_code=404, detail="Unknown user. Enroll first.")

    enrolled_vec = np.array(user_row["embedding"], dtype=np.float64)
    role = user_row["role"]

    b1 = await image1.read()
    b2 = await image2.read()

    try:
        r1 = extract_embedding(b1)
        r2 = extract_embedding(b2)
    except ValueError as e:
        log_event("verify_error", username, ip, {"error": str(e)})
        raise HTTPException(status_code=400, detail=str(e))

    if not r1.quality_ok or not r2.quality_ok:
        f, locked_now, _ = register_fail(username, ip)
        log_event("verify_failed", username, ip, {
            "reason": "quality_gate",
            "quality_1": r1.quality_reason,
            "quality_2": r2.quality_reason,
            "fails": f,
            "locked": locked_now
        })
        raise HTTPException(status_code=400, detail={
            "error": "quality_gate",
            "quality_1": r1.quality_reason,
            "quality_2": r2.quality_reason
        })

    if r1.face_count != 1 or r2.face_count != 1:
        f, locked_now, _ = register_fail(username, ip)
        log_event("verify_failed", username, ip, {
            "reason": "invalid_face_count",
            "face_count_1": r1.face_count,
            "face_count_2": r2.face_count,
            "fails": f,
            "locked": locked_now
        })
        raise HTTPException(status_code=400, detail={
            "error": "invalid_face_count",
            "face_count_1": r1.face_count,
            "face_count_2": r2.face_count
        })

    d1 = cosine_distance(r1.embedding, enrolled_vec)
    d2 = cosine_distance(r2.embedding, enrolled_vec)

    match1 = d1 <= MATCH_THRESHOLD
    match2 = d2 <= MATCH_THRESHOLD

    motion = motion_heuristic(b1, b2)
    liveness_pass = motion >= MOTION_THRESHOLD

    authenticated = bool(match1 and match2 and liveness_pass)

    meta = {
        "d1": d1,
        "d2": d2,
        "match_threshold": MATCH_THRESHOLD,
        "motion": motion,
        "motion_threshold": MOTION_THRESHOLD,
        "liveness_pass": liveness_pass
    }

    if authenticated:
        register_success(username, ip)
        token = create_access_token(username=username, role=role)
        log_event("verify_success", username, ip, meta)
        return {"authenticated": True, "token": token, "role": role, **meta}

    f, locked_now, locked_until = register_fail(username, ip)
    meta.update({"fails": f, "locked": locked_now, "locked_until": locked_until if locked_now else None})
    log_event("verify_failed", username, ip, meta)
    raise HTTPException(status_code=401, detail={"authenticated": False, **meta})

@app.post("/search")
async def search(
    request: Request,
    image: UploadFile = File(...),
    top_k: int = 5,
    user=Depends(get_current_user),
):
    """
    1:N search across enrolled users.
    Requires auth token. (Any role)
    """
    ip = _client_ip(request)
    b = await image.read()

    try:
        r = extract_embedding(b)
    except ValueError as e:
        log_event("search_error", user["username"], ip, {"error": str(e)})
        raise HTTPException(status_code=400, detail=str(e))

    if not r.quality_ok:
        raise HTTPException(status_code=400, detail={"error": "quality_gate", "detail": r.quality_reason})

    if r.face_count != 1:
        raise HTTPException(status_code=400, detail={"error": "invalid_face_count", "face_count": r.face_count})

    candidates = []
    for u in list_users():
        emb = np.array(u["embedding"], dtype=np.float64)
        dist = cosine_distance(r.embedding, emb)
        candidates.append({"username": u["username"], "role": u["role"], "distance": dist})

    candidates.sort(key=lambda x: x["distance"])
    results = candidates[: max(1, min(top_k, 25))]

    log_event("search_success", user["username"], ip, {"top_k": top_k, "returned": len(results)})
    return {"results": results, "match_threshold": MATCH_THRESHOLD}

@app.post("/admin/set-role")
def admin_set_role(
    username: str,
    role: str,
    request: Request,
    admin=Depends(require_role("admin")),
):
    ip = _client_ip(request)
    role = role.strip().lower()
    if role not in ALLOWED_ROLES:
        raise HTTPException(status_code=400, detail=f"Invalid role. Allowed: {sorted(ALLOWED_ROLES)}")

    ok = set_user_role(username, role)
    if not ok:
        raise HTTPException(status_code=404, detail="User not found")

    log_event("admin_set_role", admin["username"], ip, {"target": username, "role": role})
    return {"ok": True, "username": username, "role": role}

@app.get("/admin/events")
def admin_events(limit: int = 50, admin=Depends(require_role("admin", "analyst"))):
    return {"events": list_events(limit=limit)}
