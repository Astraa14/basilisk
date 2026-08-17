"""FastAPI main application with authentication and scan endpoints."""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Callable
from contextlib import asynccontextmanager
from functools import wraps

from fastapi import Depends, FastAPI, HTTPException, Header, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import func

import auth
import database
import models
import schemas
from database import get_db

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("basilisk.backend")

FRONTEND_URL = os.getenv("BASILISK_FRONTEND_URL", "https://basilisk-livid.vercel.app")

# Simple in-memory rate limiter (per-IP, fixed window)
RATE_LIMIT_STORE: dict[str, list[float]] = {}
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX = 60


def rate_limit(window: int = RATE_LIMIT_WINDOW, max_requests: int = RATE_LIMIT_MAX):
    def decorator(handler: Callable):
        @wraps(handler)
        async def wrapper(request: Request, *args, **kwargs):
            ip = request.client.host if request.client else "unknown"
            now = time.time()
            timestamps = RATE_LIMIT_STORE.get(ip, [])
            timestamps = [t for t in timestamps if now - t < window]
            if len(timestamps) >= max_requests:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Rate limit exceeded. Try again later.",
                )
            timestamps.append(now)
            RATE_LIMIT_STORE[ip] = timestamps
            return await handler(request, *args, **kwargs)
        return wrapper
    return decorator


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting up Basilisk backend...")
    database.create_tables()
    yield
    logger.info("Shutting down Basilisk backend...")


app = FastAPI(title="Basilisk API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        FRONTEND_URL,
        "https://basilisk-livid.vercel.app",
        "https://basilisk-scan.vercel.app",
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_current_user(
    authorization: str | None = Header(None), db: Session = Depends(get_db)
) -> models.User:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization header",
        )
    api_key = authorization.split("Bearer ")[1].strip()
    user = auth.get_user_by_api_key(api_key, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )
    return user


# ---------------------------------------------------------------------------
# Auth Endpoints
# ---------------------------------------------------------------------------

@app.post("/api/auth/device-code", response_model=schemas.DeviceCodeSchema)
def request_device_code(db: Session = Depends(get_db)):
    return auth.generate_device_code(db)


@app.post("/api/auth/verify", response_model=schemas.VerifyResponseSchema)
def verify_device(payload: schemas.VerifyDeviceSchema, db: Session = Depends(get_db)):
    auth.cleanup_expired_codes(db)

    user = (
        db.query(models.User)
        .filter(
            (models.User.email == payload.email)
            | (models.User.username == payload.username)
        )
        .first()
    )

    api_key = auth.generate_api_key()

    if not user:
        user = models.User(
            username=payload.username,
            email=payload.email,
            api_key=api_key,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    else:
        user.api_key = api_key
        db.commit()

    success = auth.verify_device_code(
        db, payload.user_code, user.id, api_key, user.username
    )
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired code",
        )

    return {
        "verified": True,
        "api_key": api_key,
        "username": user.username,
    }


@app.post("/api/auth/token", response_model=schemas.TokenResponseSchema)
def poll_for_token(payload: schemas.TokenPollSchema, db: Session = Depends(get_db)):
    auth.cleanup_expired_codes(db)

    try:
        result = auth.get_verified_token(db, payload.device_code)
    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Device code not found or expired",
        ) from None

    if not result:
        return JSONResponse(
            status_code=status.HTTP_202_ACCEPTED,
            content={"status": 202, "api_key": "", "username": ""},
        )

    return {"status": 200, "api_key": result["api_key"], "username": result["username"]}


# ---------------------------------------------------------------------------
# Scan Endpoints
# ---------------------------------------------------------------------------

@app.post("/api/scans/upload", status_code=status.HTTP_201_CREATED)
def upload_scan(
    payload: schemas.ScanReportSchema,
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    scan = models.Scan(
        user_id=user.id,
        target_url=payload.target,
        pages_scanned=payload.pages_scanned,
        forms_found=payload.forms_found,
        vulnerable=payload.vulnerable,
        mode=payload.mode,
        status="complete",
    )
    db.add(scan)
    db.flush()

    for finding_data in payload.findings:
        finding = models.Finding(
            scan_id=scan.id,
            vulnerability=finding_data.vulnerability,
            severity=finding_data.severity,
            description=finding_data.description,
            target=finding_data.target,
            attack_type=finding_data.attack_type,
            payload=finding_data.payload,
        )
        db.add(finding)

    for exploit_data in payload.exploits_found:
        exploit = models.Exploit(
            scan_id=scan.id,
            payload=exploit_data.payload,
            status_code=exploit_data.status_code,
            reason=exploit_data.reason,
        )
        db.add(exploit)

    db.commit()
    return {"scan_id": scan.id, "status": "created"}


@app.get("/api/scans", response_model=schemas.ScanListResponseSchema)
def list_scans(
    page: int = 1,
    per_page: int = 20,
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    per_page = min(max(per_page, 1), 100)
    page = max(page, 1)

    base_query = (
        db.query(models.Scan)
        .options(joinedload(models.Scan.findings), joinedload(models.Scan.exploits))
        .filter(models.Scan.user_id == user.id)
    )

    total = base_query.count()
    scans = (
        base_query
        .order_by(models.Scan.created_at.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )

    return {
        "total": total,
        "page": page,
        "per_page": per_page,
        "scans": scans,
    }


@app.get("/api/scans/{scan_id}", response_model=schemas.ScanResponseSchema)
def get_scan(
    scan_id: int,
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    scan = (
        db.query(models.Scan)
        .options(joinedload(models.Scan.findings), joinedload(models.Scan.exploits))
        .filter(models.Scan.id == scan_id, models.Scan.user_id == user.id)
        .first()
    )
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )
    return scan


@app.delete("/api/scans/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scan(
    scan_id: int,
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    scan = (
        db.query(models.Scan)
        .filter(models.Scan.id == scan_id, models.Scan.user_id == user.id)
        .first()
    )
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )
    db.delete(scan)
    db.commit()


@app.get("/api/health")
def health(db: Session = Depends(get_db)):
    db_status = "ok"
    try:
        db.execute(func.now())
    except Exception:
        db_status = "error"
    return {"status": "ok", "database": db_status}
