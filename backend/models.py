"""
models.py
---------
Pydantic schemas used for request validation and response shaping.
These are separate from the SQLite table definitions in database.py.
"""

from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List
from datetime import date


# ---------- Auth ----------

class SignupRequest(BaseModel):
    full_name: str = Field(..., min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(..., min_length=6, max_length=128)
    role: str = Field(..., pattern="^(student|recruiter|admin)$")
    institution_name: Optional[str] = None


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    full_name: str


class UserOut(BaseModel):
    id: int
    full_name: str
    email: str
    role: str
    institution_id: Optional[int] = None


# ---------- Certificates ----------

class CertificateCreate(BaseModel):
    certificate_id: str
    student_name: str
    course: Optional[str] = None
    institution_name: str
    issue_date: Optional[date] = None
    qr_data: Optional[str] = None


class CertificateOut(BaseModel):
    id: int
    certificate_id: str
    student_name: str
    course: Optional[str]
    institution_name: Optional[str]
    issue_date: Optional[str]
    status: str
    created_at: str


# ---------- Verification ----------

class VerificationResult(BaseModel):
    result: str  # verified | needs_review | suspicious | revoked
    risk_score: int
    extracted_certificate_id: Optional[str]
    matched: bool
    qr_found: bool
    qr_matched: bool
    reasons: List[str]
    certificate: Optional[CertificateOut] = None


class HistoryItem(BaseModel):
    id: int
    uploaded_filename: str
    extracted_certificate_id: Optional[str]
    risk_score: int
    result: str
    reasons: Optional[str]
    created_at: str
