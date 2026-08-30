"""
main.py
-------
FastAPI application entry point for the AI Certificate Verification system.

Run with:
    uvicorn main:app --reload --port 8000
"""

import logging
from datetime import date
from typing import List, Optional

from fastapi import FastAPI, Depends, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware

from database import init_db, get_connection, UPLOAD_DIR
from models import (
    SignupRequest, LoginRequest, TokenResponse, UserOut,
    CertificateCreate, CertificateOut, VerificationResult, HistoryItem,
)
from auth import hash_password, verify_password, create_access_token, get_current_user, require_role
import verification as vpipe

# ---------------- Logging setup ----------------
# Important events are logged; passwords, tokens, and certificate file
# contents are NEVER written to logs.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger("certverify.main")

app = FastAPI(title="AI Certificate Verification API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # college project: open CORS. Restrict this in production.
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    init_db()
    logger.info("Database initialized and ready.")


# =========================================================================
# AUTH
# =========================================================================

@app.post("/api/auth/signup", response_model=TokenResponse)
def signup(payload: SignupRequest):
    conn = get_connection()
    cur = conn.cursor()

    existing = cur.execute("SELECT id FROM users WHERE email = ?", (payload.email,)).fetchone()
    if existing:
        conn.close()
        logger.warning("Signup rejected: email already registered.")
        raise HTTPException(status_code=400, detail="An account with this email already exists.")

    institution_id = None
    if payload.institution_name:
        inst = cur.execute(
            "SELECT id FROM institutions WHERE name = ?", (payload.institution_name,)
        ).fetchone()
        if inst:
            institution_id = inst["id"]
        else:
            code = "".join(w[0] for w in payload.institution_name.split()).upper()[:10]
            cur.execute(
                "INSERT INTO institutions (name, code) VALUES (?, ?)",
                (payload.institution_name, code),
            )
            institution_id = cur.lastrowid

    pwd_hash, salt = hash_password(payload.password)
    cur.execute(
        """INSERT INTO users (full_name, email, password_hash, password_salt, role, institution_id)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (payload.full_name, payload.email, pwd_hash, salt, payload.role, institution_id),
    )
    user_id = cur.lastrowid
    conn.commit()
    conn.close()

    logger.info("New user signed up: id=%s role=%s", user_id, payload.role)
    token = create_access_token(user_id, payload.role, payload.email)
    return TokenResponse(access_token=token, role=payload.role, full_name=payload.full_name)


@app.post("/api/auth/login", response_model=TokenResponse)
def login(payload: LoginRequest):
    conn = get_connection()
    row = conn.execute(
        "SELECT id, full_name, password_hash, password_salt, role FROM users WHERE email = ?",
        (payload.email,),
    ).fetchone()
    conn.close()

    if row is None or not verify_password(payload.password, row["password_hash"], row["password_salt"]):
        logger.warning("Failed login attempt.")
        raise HTTPException(status_code=401, detail="Incorrect email or password.")

    logger.info("User logged in: id=%s", row["id"])
    token = create_access_token(row["id"], row["role"], payload.email)
    return TokenResponse(access_token=token, role=row["role"], full_name=row["full_name"])


@app.get("/api/auth/me", response_model=UserOut)
def me(user: dict = Depends(get_current_user)):
    return UserOut(**user)


# =========================================================================
# CERTIFICATES  (admin / institution staff register genuine certificates)
# =========================================================================

@app.post("/api/certificates", response_model=CertificateOut)
def register_certificate(payload: CertificateCreate, user: dict = Depends(require_role("admin"))):
    conn = get_connection()
    cur = conn.cursor()

    inst = cur.execute("SELECT id FROM institutions WHERE name = ?", (payload.institution_name,)).fetchone()
    if inst:
        institution_id = inst["id"]
    else:
        code = "".join(w[0] for w in payload.institution_name.split()).upper()[:10]
        cur.execute("INSERT INTO institutions (name, code) VALUES (?, ?)", (payload.institution_name, code))
        institution_id = cur.lastrowid

    existing = cur.execute(
        "SELECT id FROM certificates WHERE certificate_id = ?", (payload.certificate_id,)
    ).fetchone()
    if existing:
        conn.close()
        raise HTTPException(status_code=400, detail="A certificate with this ID is already registered.")

    cur.execute(
        """INSERT INTO certificates
           (certificate_id, student_name, course, institution_id, issue_date, qr_data, status, created_by)
           VALUES (?, ?, ?, ?, ?, ?, 'active', ?)""",
        (
            payload.certificate_id, payload.student_name, payload.course, institution_id,
            str(payload.issue_date) if payload.issue_date else None,
            payload.qr_data or payload.certificate_id, user["id"],
        ),
    )
    cert_id = cur.lastrowid
    conn.commit()
    row = cur.execute(
        """SELECT c.*, i.name as institution_name FROM certificates c
           LEFT JOIN institutions i ON c.institution_id = i.id WHERE c.id = ?""",
        (cert_id,),
    ).fetchone()
    conn.close()

    logger.info("Admin %s registered new certificate id=%s", user["id"], cert_id)
    return _row_to_certificate_out(row)


@app.get("/api/certificates", response_model=List[CertificateOut])
def list_certificates(user: dict = Depends(require_role("admin"))):
    conn = get_connection()
    rows = conn.execute(
        """SELECT c.*, i.name as institution_name FROM certificates c
           LEFT JOIN institutions i ON c.institution_id = i.id
           ORDER BY c.created_at DESC"""
    ).fetchall()
    conn.close()
    return [_row_to_certificate_out(r) for r in rows]


@app.post("/api/certificates/{certificate_db_id}/revoke", response_model=CertificateOut)
def revoke_certificate(certificate_db_id: int, user: dict = Depends(require_role("admin"))):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("UPDATE certificates SET status = 'revoked' WHERE id = ?", (certificate_db_id,))
    if cur.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=404, detail="Certificate not found.")
    conn.commit()
    row = cur.execute(
        """SELECT c.*, i.name as institution_name FROM certificates c
           LEFT JOIN institutions i ON c.institution_id = i.id WHERE c.id = ?""",
        (certificate_db_id,),
    ).fetchone()
    conn.close()
    logger.info("Admin %s revoked certificate id=%s", user["id"], certificate_db_id)
    return _row_to_certificate_out(row)


def _row_to_certificate_out(row) -> CertificateOut:
    return CertificateOut(
        id=row["id"], certificate_id=row["certificate_id"], student_name=row["student_name"],
        course=row["course"], institution_name=row["institution_name"],
        issue_date=row["issue_date"], status=row["status"], created_at=row["created_at"],
    )


# =========================================================================
# VERIFICATION  (the core OCR / QR / hash / risk pipeline)
# =========================================================================

@app.post("/api/verify", response_model=VerificationResult)
async def verify_certificate(file: UploadFile = File(...), user: dict = Depends(get_current_user)):
    allowed_types = {".pdf", ".jpg", ".jpeg", ".png"}
    suffix = "." + file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
    if suffix not in allowed_types:
        raise HTTPException(status_code=400, detail="Only PDF, JPG, and PNG files are supported.")

    file_bytes = await file.read()
    if len(file_bytes) == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    if len(file_bytes) > 15 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="File is too large (max 15MB).")

    try:
        img = vpipe.load_image_from_bytes(file_bytes, file.filename)
        ocr_text = vpipe.extract_text(img)
        extracted_cert_id = vpipe.extract_certificate_id(ocr_text)
        qr_data = vpipe.detect_qr_code(img)
        file_hash = vpipe.sha256_of_bytes(file_bytes)
    except ValueError as exc:
        logger.error("Verification pipeline error for user %s: %s", user["id"], exc)
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception:
        logger.exception("Unexpected error while processing uploaded certificate for user %s", user["id"])
        raise HTTPException(status_code=500, detail="Could not process the uploaded file. Please try a clearer scan.")

    # Look up a matching certificate in the database, preferring the QR data
    # (harder to forge cleanly) and falling back to the OCR-extracted ID.
    conn = get_connection()
    lookup_id = None
    if qr_data:
        lookup_id = qr_data.strip()
    elif extracted_cert_id:
        lookup_id = extracted_cert_id

    cert_row = None
    if lookup_id:
        cert_row = conn.execute(
            """SELECT c.*, i.name as institution_name FROM certificates c
               LEFT JOIN institutions i ON c.institution_id = i.id
               WHERE UPPER(c.certificate_id) = UPPER(?)""",
            (lookup_id,),
        ).fetchone()

    risk_score, label, reasons = vpipe.calculate_risk(
        certificate_row=dict(cert_row) if cert_row else None,
        file_hash=file_hash,
        qr_data=qr_data,
        extracted_cert_id=extracted_cert_id,
        ocr_text_length=len(ocr_text.strip()),
    )

    # If this is the first time we see a genuine certificate's file, store its
    # hash so future uploads can be hash-verified (simulates the institution
    # having registered the original digital file).
    if cert_row and not cert_row["file_hash"] and label in ("verified", "needs_review"):
        conn.execute("UPDATE certificates SET file_hash = ? WHERE id = ?", (file_hash, cert_row["id"]))
        conn.commit()

    cur = conn.cursor()
    cur.execute(
        """INSERT INTO verification_history
           (user_id, uploaded_filename, extracted_certificate_id, matched_certificate_id,
            file_hash, qr_found, qr_matched, risk_score, result, reasons)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            user["id"], file.filename, extracted_cert_id, cert_row["id"] if cert_row else None,
            file_hash, 1 if qr_data else 0,
            1 if (qr_data and cert_row and qr_data.strip().upper() == cert_row["certificate_id"].upper()) else 0,
            risk_score, label, " | ".join(reasons),
        ),
    )
    conn.commit()
    conn.close()

    logger.info(
        "Verification complete: user=%s result=%s risk=%s matched=%s",
        user["id"], label, risk_score, bool(cert_row),
    )

    return VerificationResult(
        result=label,
        risk_score=risk_score,
        extracted_certificate_id=extracted_cert_id,
        matched=bool(cert_row),
        qr_found=bool(qr_data),
        qr_matched=bool(qr_data and cert_row and qr_data.strip().upper() == cert_row["certificate_id"].upper()),
        reasons=reasons,
        certificate=_row_to_certificate_out(cert_row) if cert_row else None,
    )


# =========================================================================
# HISTORY
# =========================================================================

@app.get("/api/history", response_model=List[HistoryItem])
def get_history(user: dict = Depends(get_current_user)):
    conn = get_connection()
    if user["role"] == "admin":
        rows = conn.execute(
            "SELECT * FROM verification_history ORDER BY created_at DESC LIMIT 200"
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM verification_history WHERE user_id = ? ORDER BY created_at DESC LIMIT 200",
            (user["id"],),
        ).fetchall()
    conn.close()
    return [
        HistoryItem(
            id=r["id"], uploaded_filename=r["uploaded_filename"],
            extracted_certificate_id=r["extracted_certificate_id"],
            risk_score=r["risk_score"], result=r["result"], reasons=r["reasons"],
            created_at=r["created_at"],
        )
        for r in rows
    ]


# =========================================================================
# ADMIN DASHBOARD STATS
# =========================================================================

@app.get("/api/admin/stats")
def admin_stats(user: dict = Depends(require_role("admin"))):
    conn = get_connection()
    total_users = conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
    total_certs = conn.execute("SELECT COUNT(*) c FROM certificates").fetchone()["c"]
    total_verifications = conn.execute("SELECT COUNT(*) c FROM verification_history").fetchone()["c"]
    by_result = conn.execute(
        "SELECT result, COUNT(*) c FROM verification_history GROUP BY result"
    ).fetchall()
    conn.close()
    return {
        "total_users": total_users,
        "total_certificates": total_certs,
        "total_verifications": total_verifications,
        "results_breakdown": {r["result"]: r["c"] for r in by_result},
    }


@app.get("/api/health")
def health():
    return {"status": "ok"}
