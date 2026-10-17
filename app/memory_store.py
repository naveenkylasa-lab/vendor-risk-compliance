"""Persistent Session & Conversation Memory Store backed by SQLite (Rubric Section 2)."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional

from app.observability import redact_pii_payload, redact_pii_text

DB_PATH = Path(__file__).resolve().parent.parent / "vendor_sessions.db"


class PersistentVendorMemoryStore:
    """SQLite-backed session store that remembers vendor questions, extracted certs, and onboarding status."""

    def __init__(self, db_path: Path = DB_PATH) -> None:
        self.db_path = db_path
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS vendor_sessions (
                    vendor_id TEXT PRIMARY KEY,
                    vendor_name TEXT NOT NULL,
                    onboarding_status TEXT NOT NULL,
                    risk_level TEXT NOT NULL,
                    composite_score REAL DEFAULT 0.0,
                    pending_hitl INTEGER DEFAULT 0,
                    extracted_certifications_json TEXT DEFAULT '{}',
                    conversation_history_json TEXT DEFAULT '[]',
                    audit_logs_json TEXT DEFAULT '[]',
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.commit()

    def get_session(self, vendor_id: str) -> Optional[Dict[str, Any]]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM vendor_sessions WHERE vendor_id = ?", (vendor_id,)
            ).fetchone()
            if not row:
                return None
            return {
                "vendor_id": row["vendor_id"],
                "vendor_name": row["vendor_name"],
                "onboarding_status": row["onboarding_status"],
                "risk_level": row["risk_level"],
                "composite_score": row["composite_score"],
                "pending_hitl": bool(row["pending_hitl"]),
                "extracted_certifications": json.loads(row["extracted_certifications_json"]),
                "conversation_history": json.loads(row["conversation_history_json"]),
                "audit_logs": json.loads(row["audit_logs_json"]),
                "updated_at": row["updated_at"],
            }

    def upsert_session(
        self,
        *,
        vendor_id: str,
        vendor_name: str,
        onboarding_status: str,
        risk_level: str,
        composite_score: float = 0.0,
        pending_hitl: bool = False,
        extracted_certifications: Optional[Dict[str, Any]] = None,
        audit_logs: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        existing = self.get_session(vendor_id)
        conv_history = existing["conversation_history"] if existing else []
        certs = (
            extracted_certifications
            if extracted_certifications is not None
            else (existing["extracted_certifications"] if existing else {})
        )
        logs = (
            audit_logs
            if audit_logs is not None
            else (existing["audit_logs"] if existing else [])
        )

        # Enforce PII redaction before persisting to SQLite
        scrubbed_certs, _ = redact_pii_payload(certs)
        scrubbed_logs, _ = redact_pii_payload(logs)
        now = datetime.now(timezone.utc).isoformat()

        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO vendor_sessions (
                    vendor_id, vendor_name, onboarding_status, risk_level,
                    composite_score, pending_hitl, extracted_certifications_json,
                    conversation_history_json, audit_logs_json, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(vendor_id) DO UPDATE SET
                    vendor_name = excluded.vendor_name,
                    onboarding_status = excluded.onboarding_status,
                    risk_level = excluded.risk_level,
                    composite_score = excluded.composite_score,
                    pending_hitl = excluded.pending_hitl,
                    extracted_certifications_json = excluded.extracted_certifications_json,
                    audit_logs_json = excluded.audit_logs_json,
                    updated_at = excluded.updated_at
                """,
                (
                    vendor_id,
                    vendor_name,
                    onboarding_status,
                    risk_level,
                    composite_score,
                    1 if pending_hitl else 0,
                    json.dumps(scrubbed_certs),
                    json.dumps(conv_history),
                    json.dumps(scrubbed_logs),
                    now,
                ),
            )
            conn.commit()
        return self.get_session(vendor_id)  # type: ignore

    def append_conversation_turn(
        self,
        *,
        vendor_id: str,
        vendor_name: str,
        role: str,
        message: str,
        agent_name: str = "VendorSupportAgent",
        model_used: str = "gemini-2.5-flash",
    ) -> Dict[str, Any]:
        """Appends a PII-scrubbed conversational turn to the vendor's persistent session memory."""
        session = self.get_session(vendor_id)
        if not session:
            session = self.upsert_session(
                vendor_id=vendor_id,
                vendor_name=vendor_name,
                onboarding_status="IN_PROGRESS",
                risk_level="PENDING_ASSESSMENT",
            )

        scrubbed_msg, redactions = redact_pii_text(message)
        history: List[Dict[str, Any]] = session["conversation_history"]
        history.append(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "role": role,
                "agent": agent_name,
                "model": model_used,
                "content": scrubbed_msg,
                "pii_redactions": redactions,
            }
        )

        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                UPDATE vendor_sessions
                SET conversation_history_json = ?, updated_at = ?
                WHERE vendor_id = ?
                """,
                (json.dumps(history), datetime.now(timezone.utc).isoformat(), vendor_id),
            )
            conn.commit()
        return self.get_session(vendor_id)  # type: ignore

    def list_all_sessions(self) -> List[Dict[str, Any]]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT vendor_id FROM vendor_sessions ORDER BY updated_at DESC"
            ).fetchall()
            return [self.get_session(r["vendor_id"]) for r in rows if r["vendor_id"]]  # type: ignore


memory_store = PersistentVendorMemoryStore()
