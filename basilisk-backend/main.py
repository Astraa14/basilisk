"""FastAPI main application with authentication and scan endpoints."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Header, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

import auth
import database
import models
import schemas
from database import get_db

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("basilisk.backend")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting up Basilisk backend...")
    database.create_tables()
    yield
    logger.info("Shutting down Basilisk backend...")


app = FastAPI(title="Basilisk API", lifespan=lifespan)

# Allow all origins for dev. In prod, restrict to BASILISK_FRONTEND_URL
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_current_user(
    authorization: str | None = Header(None), db: Session = Depends(get_db)
) -> models.User:
    """Dependency: Extract API key from header and return User."""
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
def request_device_code():
    auth.cleanup_expired_codes()
    return auth.generate_device_code()


@app.post("/api/auth/verify")
def verify_device(payload: schemas.VerifyDeviceSchema, db: Session = Depends(get_db)):
    auth.cleanup_expired_codes()

    # Get or create user
    user = db.query(models.User).filter(
        (models.User.email == payload.email) | (models.User.username == payload.username)
    ).first()

    api_key = auth.generate_api_key()

    if not user:
        user = models.User(
            username=payload.username,
            email=payload.email,
            api_key=api_key
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    else:
        # Update existing user's API key
        user.api_key = api_key
        db.commit()

    success = auth.verify_device_code(payload.user_code, user.id, api_key, user.username)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired code",
        )

    return {"verified": True}


@app.post("/api/auth/token", response_model=schemas.TokenResponseSchema)
def poll_for_token(payload: schemas.TokenPollSchema):
    auth.cleanup_expired_codes()

    if payload.device_code not in auth._store:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Device code not found or expired",
        )

    result = auth.get_verified_token(payload.device_code)
    if not result:
        # 202 Accepted = still waiting
        from fastapi.responses import JSONResponse
        return JSONResponse(
            status_code=status.HTTP_202_ACCEPTED,
            content={"status": 202, "api_key": "", "username": ""}
        )

    return {"status": 200, "api_key": result["api_key"], "username": result["username"]}


# ---------------------------------------------------------------------------
# Scan Endpoints
# ---------------------------------------------------------------------------

@app.post("/api/scans/upload", status_code=status.HTTP_201_CREATED)
def upload_scan(
    payload: schemas.ScanReportSchema,
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    scan = models.Scan(
        user_id=user.id,
        target_url=payload.target,
        pages_scanned=payload.pages_scanned,
        forms_found=payload.forms_found,
        vulnerable=payload.vulnerable,
        mode=payload.mode,
        status="complete"
    )
    db.add(scan)
    db.flush()  # get scan.id

    for finding_data in payload.findings:
        finding = models.Finding(
            scan_id=scan.id,
            vulnerability=finding_data.vulnerability,
            severity=finding_data.severity,
            description=finding_data.description,
            target=finding_data.target
        )
        db.add(finding)

    db.commit()
    return {"scan_id": scan.id, "status": "created"}


@app.get("/api/scans", response_model=list[schemas.ScanResponseSchema])
def list_scans(
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    scans = (
        db.query(models.Scan)
        .filter(models.Scan.user_id == user.id)
        .order_by(models.Scan.created_at.desc())
        .all()
    )
    return scans


@app.get("/api/scans/{scan_id}", response_model=schemas.ScanResponseSchema)
def get_scan(
    scan_id: int,
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    scan = (
        db.query(models.Scan)
        .filter(models.Scan.id == scan_id, models.Scan.user_id == user.id)
        .first()
    )
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    return scan
