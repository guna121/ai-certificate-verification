"""
verification.py
----------------
The AI/OCR verification pipeline:

    Upload -> OCR extracts text -> Read Certificate ID -> Check QR code
    -> Generate SHA-256 hash -> Compare with database -> Risk score -> Result

Kept dependency-light: OpenCV + pytesseract for OCR, OpenCV's built-in
QRCodeDetector (no extra native libs like zbar needed).
"""

import hashlib
import io
import logging
import re
from pathlib import Path
from typing import Optional

import cv2
import numpy as np
import pytesseract
from PIL import Image

logger = logging.getLogger("certverify.verification")

# Matches things like CERT-2024-0001, CERT2024001, CV-ANU-2024-55 etc.
CERT_ID_PATTERN = re.compile(r"\b([A-Z]{2,6}[-]?\d{2,4}[-]?\d{3,6})\b")


# ---------------- File loading ----------------

def load_image_from_bytes(file_bytes: bytes, filename: str) -> np.ndarray:
    """Load an uploaded JPG/PNG/PDF (first page) into an OpenCV BGR image array."""
    suffix = Path(filename).suffix.lower()

    if suffix == ".pdf":
        try:
            from pdf2image import convert_from_bytes
        except ImportError as exc:
            raise ValueError(
                "PDF verification requires the optional 'pdf2image' package "
                "and the system 'poppler-utils' tool. See README for install steps."
            ) from exc
        pages = convert_from_bytes(file_bytes, dpi=200, first_page=1, last_page=1)
        if not pages:
            raise ValueError("Could not read any pages from the uploaded PDF.")
        pil_image = pages[0].convert("RGB")
    else:
        pil_image = Image.open(io.BytesIO(file_bytes)).convert("RGB")

    return cv2.cvtColor(np.array(pil_image), cv2.COLOR_RGB2BGR)


# ---------------- OCR ----------------

def preprocess_for_ocr(img_bgr: np.ndarray) -> np.ndarray:
    """Basic OpenCV preprocessing to improve OCR accuracy on scanned certificates."""
    gray = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2GRAY)
    gray = cv2.bilateralFilter(gray, 9, 75, 75)
    thresh = cv2.adaptiveThreshold(
        gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 31, 11
    )
    return thresh


def extract_text(img_bgr: np.ndarray) -> str:
    try:
        processed = preprocess_for_ocr(img_bgr)
        text = pytesseract.image_to_string(processed)
        if len(text.strip()) < 5:
            # Fall back to OCR on the raw image if preprocessing hurt it
            text = pytesseract.image_to_string(img_bgr)
        return text
    except pytesseract.TesseractNotFoundError:
        logger.error("Tesseract OCR engine not found on this system.")
        raise ValueError(
            "Tesseract OCR engine is not installed on the server. "
            "See README for install instructions."
        )


def extract_certificate_id(text: str) -> Optional[str]:
    match = CERT_ID_PATTERN.search(text.upper())
    return match.group(1) if match else None


# ---------------- QR code ----------------

def detect_qr_code(img_bgr: np.ndarray) -> Optional[str]:
    """Return decoded QR code text if a QR code is found, else None."""
    detector = cv2.QRCodeDetector()
    data, points, _ = detector.detectAndDecode(img_bgr)
    if data:
        return data.strip()
    return None


# ---------------- Hashing ----------------

def sha256_of_bytes(file_bytes: bytes) -> str:
    return hashlib.sha256(file_bytes).hexdigest()


# ---------------- Risk scoring ----------------

def calculate_risk(
    *,
    certificate_row: Optional[dict],
    file_hash: str,
    qr_data: Optional[str],
    extracted_cert_id: Optional[str],
    ocr_text_length: int,
) -> tuple[int, str, list[str]]:
    """
    Rule-based risk scoring, 0 = completely safe, 100 = highly suspicious.

    Returns: (risk_score, result_label, reasons)
    result_label is one of: verified | needs_review | suspicious | revoked
    """
    reasons: list[str] = []
    risk = 0

    if certificate_row is None:
        risk += 45
        reasons.append("Certificate ID was not found in the verified database.")
    else:
        if certificate_row["status"] == "revoked":
            reasons.append("This certificate has been REVOKED by the issuing institution.")
            return 100, "revoked", reasons

        reasons.append(f"Certificate ID '{certificate_row['certificate_id']}' matched a record in the database.")

        stored_hash = certificate_row["file_hash"]
        if stored_hash and stored_hash != file_hash:
            risk += 30
            reasons.append("The uploaded file's content does not match the hash on record — possible tampering.")
        elif stored_hash and stored_hash == file_hash:
            reasons.append("File hash matches exactly with the original certificate on record.")
        else:
            risk += 5
            reasons.append("No reference file hash was on record yet to compare against (first-time verification).")

    if qr_data is None:
        risk += 15
        reasons.append("No QR code was detected on the certificate.")
    else:
        expected_id = certificate_row["certificate_id"] if certificate_row else extracted_cert_id
        if expected_id and qr_data.strip().upper() == str(expected_id).strip().upper():
            reasons.append("QR code content matches the certificate ID.")
        else:
            risk += 12
            reasons.append("QR code was found but its content does not match the certificate ID.")

    if extracted_cert_id is None:
        risk += 15
        reasons.append("OCR could not clearly detect a certificate ID on the document.")

    if ocr_text_length < 40:
        risk += 8
        reasons.append("Very little readable text was extracted — image quality may be poor or the document may be altered.")

    risk = max(0, min(100, risk))

    if risk <= 15 and certificate_row is not None:
        label = "verified"
    elif risk <= 50:
        label = "needs_review"
    else:
        label = "suspicious"

    return risk, label, reasons


RESULT_LABELS = {
    "verified": "✅ Verified",
    "needs_review": "⚠️ Needs Review",
    "suspicious": "❌ Suspicious",
    "revoked": "🚫 Revoked",
}
