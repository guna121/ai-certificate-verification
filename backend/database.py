"""
database.py
------------
Handles the SQLite connection and creates all tables used by the app.

We use the plain `sqlite3` module (no ORM) to keep the project easy to
read and easy to grade for a college project.
"""

import sqlite3
import logging
from pathlib import Path

logger = logging.getLogger("certverify.database")

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "certverify.db"
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)


def get_connection() -> sqlite3.Connection:
    """Return a new SQLite connection with row access by column name."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    """Create all tables if they do not already exist, and seed demo data."""
    conn = get_connection()
    cur = conn.cursor()

    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS institutions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            code TEXT NOT NULL UNIQUE,
            contact_email TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            password_salt TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('student', 'recruiter', 'admin')),
            institution_id INTEGER,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (institution_id) REFERENCES institutions(id)
        );

        -- The "source of truth" registry of genuinely issued certificates.
        CREATE TABLE IF NOT EXISTS certificates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            certificate_id TEXT NOT NULL UNIQUE,
            student_name TEXT NOT NULL,
            course TEXT,
            institution_id INTEGER,
            issue_date TEXT,
            file_hash TEXT,
            qr_data TEXT,
            status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'revoked')),
            created_by INTEGER,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (institution_id) REFERENCES institutions(id),
            FOREIGN KEY (created_by) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS verification_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            uploaded_filename TEXT,
            extracted_certificate_id TEXT,
            matched_certificate_id INTEGER,
            file_hash TEXT,
            qr_found INTEGER DEFAULT 0,
            qr_matched INTEGER DEFAULT 0,
            risk_score INTEGER NOT NULL,
            result TEXT NOT NULL CHECK(result IN ('verified', 'needs_review', 'suspicious', 'revoked')),
            reasons TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (matched_certificate_id) REFERENCES certificates(id)
        );
        """
    )
    conn.commit()

    # ---- Seed demo data (only if empty) so graders can test immediately ----
    cur.execute("SELECT COUNT(*) AS c FROM institutions")
    if cur.fetchone()["c"] == 0:
        cur.execute(
            "INSERT INTO institutions (name, code, contact_email) VALUES (?, ?, ?)",
            ("Anna University", "ANU", "registrar@anna.edu"),
        )
        conn.commit()
        logger.info("Seeded demo institution 'Anna University'")

    cur.execute("SELECT COUNT(*) AS c FROM certificates")
    if cur.fetchone()["c"] == 0:
        cur.execute("SELECT id FROM institutions WHERE code = 'ANU'")
        inst_id = cur.fetchone()["id"]
        cur.execute(
            """INSERT INTO certificates
               (certificate_id, student_name, course, institution_id, issue_date, file_hash, qr_data, status)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                "CERT-2024-0001",
                "Demo Student",
                "B.Tech Computer Science",
                inst_id,
                "2024-05-20",
                None,  # filled in automatically once a matching file is uploaded/verified
                "CERT-2024-0001",
                "active",
            ),
        )
        conn.commit()
        logger.info("Seeded demo certificate CERT-2024-0001")

    conn.close()
