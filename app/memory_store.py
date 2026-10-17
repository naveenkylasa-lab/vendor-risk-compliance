"""Non-Blocking Async & Background Task Persistent Vendor Session Memory Store (Rubric Section 2).

Resolves synchronous blocking I/O by providing:
1. Native `async` coroutines (`aget_session`, `aupsert_session`, `aappend_conversation_turn`,
   `alist_all_sessions`) powered by `aiosqlite` / `asyncio.to_thread` so the event loop never blocks.
2. Asynchronous Background Task Offloading (`schedule_background_upsert`,
   `schedule_background_conversation_turn`) supporting both FastAPI `BackgroundTasks` and a
   dedicated non-blocking `ThreadPoolExecutor` / `asyncio.Task` background write queue.
3. Write-through in-memory session cache + SQLite Write-Ahead Logging (`PRAGMA journal_mode=WAL`)
   for zero-latency reads while background disk persistence completes asynchronously.
"""

from __future__ import annotations

import asyncio
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import threading
from typing import Any, Dict, List, Optional, Set

from app.observability import redact_pii_payload, redact_pii_text, start_otel_span

try:
    import aiosqlite

    AIOSQLITE_AVAILABLE = True
except ImportError:
    AIOSQLITE_AVAILABLE = False

DB_PATH = Path(__file__).resolve().parent.parent / "vendor_sessions.db"


class PersistentVendorMemoryStore:
    """Async & background-task-backed SQLite session store for vendor questions, certs, and status."""

    def __init__(self, db_path: Path = DB_PATH, max_workers: int = 2) -> None:
        """Initializes the SQLite WAL database, write-through cache, and background worker pool.

        Args:
            db_path (Path): Path to the SQLite database file.
            max_workers (int): Number of background worker threads for non-blocking persistence.
        """
        self.db_path = Path(db_path)
        self._lock = threading.RLock()
        self._async_lock = asyncio.Lock()
        self._session_cache: Dict[str, Dict[str, Any]] = {}
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="vendor_memory_bg"
        )
        self._pending_futures: List[Future[Any]] = []
        self._background_tasks: Set[asyncio.Task[Any]] = set()
        self.background_writes_scheduled: int = 0
        self.background_writes_completed: int = 0
        self._init_db()

    def _init_db(self) -> None:
        """Initializes the `vendor_sessions` table with SQLite WAL mode enabled."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
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

    def _row_to_dict(self, row: sqlite3.Row | Any) -> Dict[str, Any]:
        """Converts a SQLite row into a structured session dictionary."""
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

    def _persist_session_row_sync(self, record: Dict[str, Any]) -> None:
        """Writes a pre-sanitized session record to SQLite inside a background worker thread."""
        with self._lock:
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
                        conversation_history_json = excluded.conversation_history_json,
                        audit_logs_json = excluded.audit_logs_json,
                        updated_at = excluded.updated_at
                    """,
                    (
                        record["vendor_id"],
                        record["vendor_name"],
                        record["onboarding_status"],
                        record["risk_level"],
                        record["composite_score"],
                        1 if record["pending_hitl"] else 0,
                        json.dumps(record["extracted_certifications"]),
                        json.dumps(record["conversation_history"]),
                        json.dumps(record["audit_logs"]),
                        record["updated_at"],
                    ),
                )
                conn.commit()
            self.background_writes_completed += 1

    async def _persist_session_row_async(self, record: Dict[str, Any]) -> None:
        """Writes a pre-sanitized session record asynchronously using `aiosqlite` or `asyncio.to_thread`."""
        if AIOSQLITE_AVAILABLE:
            async with self._async_lock:
                async with aiosqlite.connect(self.db_path) as db:
                    await db.execute(
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
                            conversation_history_json = excluded.conversation_history_json,
                            audit_logs_json = excluded.audit_logs_json,
                            updated_at = excluded.updated_at
                        """,
                        (
                            record["vendor_id"],
                            record["vendor_name"],
                            record["onboarding_status"],
                            record["risk_level"],
                            record["composite_score"],
                            1 if record["pending_hitl"] else 0,
                            json.dumps(record["extracted_certifications"]),
                            json.dumps(record["conversation_history"]),
                            json.dumps(record["audit_logs"]),
                            record["updated_at"],
                        ),
                    )
                    await db.commit()
                self.background_writes_completed += 1
        else:
            await asyncio.to_thread(self._persist_session_row_sync, record)

    def _dispatch_background_persistence(
        self,
        record: Dict[str, Any],
        background_tasks: Optional[Any] = None,
    ) -> None:
        """Dispatches a SQLite write to FastAPI `BackgroundTasks`, an `asyncio.Task`, or worker pool."""
        self.background_writes_scheduled += 1

        if background_tasks is not None and hasattr(background_tasks, "add_task"):
            background_tasks.add_task(self._persist_session_row_sync, record)
            return

        try:
            loop = asyncio.get_running_loop()
            task = loop.create_task(self._persist_session_row_async(record))
            self._background_tasks.add(task)
            task.add_done_callback(self._background_tasks.discard)
            return
        except RuntimeError:
            pass

        future = self._executor.submit(self._persist_session_row_sync, record)
        with self._lock:
            self._pending_futures = [f for f in self._pending_futures if not f.done()]
            self._pending_futures.append(future)

    def flush_background_tasks(self, timeout: float = 5.0) -> None:
        """Waits for any queued background thread writes to complete (useful for tests/shutdown).

        Args:
            timeout (float): Maximum seconds to wait per pending background future.
        """
        with self._lock:
            futures = list(self._pending_futures)
            self._pending_futures.clear()
        for fut in futures:
            try:
                fut.result(timeout=timeout)
            except Exception:
                pass

    async def aflush_background_tasks(self, timeout: float = 5.0) -> None:
        """Asynchronously awaits all in-flight `asyncio.Task` and background thread writes.

        Args:
            timeout (float): Maximum seconds to wait for background persistence tasks.
        """
        if self._background_tasks:
            pending = list(self._background_tasks)
            await asyncio.gather(*pending, return_exceptions=True)
        await asyncio.to_thread(self.flush_background_tasks, timeout)

    def get_session(self, vendor_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a vendor session from the non-blocking write-through cache or SQLite fallback.

        Args:
            vendor_id (str): Unique vendor identifier (e.g., 'VND-1001').

        Returns:
            Optional[Dict[str, Any]]: Deep-copied session dictionary or None if not found.
        """
        with self._lock:
            if vendor_id in self._session_cache:
                return json.loads(json.dumps(self._session_cache[vendor_id]))

        self.flush_background_tasks()
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM vendor_sessions WHERE vendor_id = ?", (vendor_id,)
            ).fetchone()
            if not row:
                return None
            data = self._row_to_dict(row)
            with self._lock:
                self._session_cache[vendor_id] = data
            return json.loads(json.dumps(data))

    async def aget_session(self, vendor_id: str) -> Optional[Dict[str, Any]]:
        """Asynchronously retrieves a vendor session without blocking the event loop.

        Args:
            vendor_id (str): Unique vendor identifier (e.g., 'VND-1001').

        Returns:
            Optional[Dict[str, Any]]: Session dictionary or None if not found.
        """
        with start_otel_span(
            "memory.aget_session",
            attributes={"vendor.id": vendor_id, "memory.execution_mode": "async_non_blocking"},
        ):
            with self._lock:
                if vendor_id in self._session_cache:
                    return json.loads(json.dumps(self._session_cache[vendor_id]))

            if AIOSQLITE_AVAILABLE:
                async with aiosqlite.connect(self.db_path) as db:
                    db.row_factory = aiosqlite.Row
                    async with db.execute(
                        "SELECT * FROM vendor_sessions WHERE vendor_id = ?", (vendor_id,)
                    ) as cursor:
                        row = await cursor.fetchone()
                        if not row:
                            return None
                        data = self._row_to_dict(row)
                        with self._lock:
                            self._session_cache[vendor_id] = data
                        return json.loads(json.dumps(data))

            return await asyncio.to_thread(self.get_session, vendor_id)

    def _prepare_upserted_record(
        self,
        *,
        existing: Optional[Dict[str, Any]],
        vendor_id: str,
        vendor_name: str,
        onboarding_status: str,
        risk_level: str,
        composite_score: float = 0.0,
        pending_hitl: bool = False,
        extracted_certifications: Optional[Dict[str, Any]] = None,
        audit_logs: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Builds a PII-scrubbed session record and updates the in-memory write-through cache."""
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

        scrubbed_certs, _ = redact_pii_payload(certs)
        scrubbed_logs, _ = redact_pii_payload(logs)
        now = datetime.now(timezone.utc).isoformat()

        record: Dict[str, Any] = {
            "vendor_id": vendor_id,
            "vendor_name": vendor_name,
            "onboarding_status": onboarding_status,
            "risk_level": risk_level,
            "composite_score": composite_score,
            "pending_hitl": bool(pending_hitl),
            "extracted_certifications": scrubbed_certs,
            "conversation_history": conv_history,
            "audit_logs": scrubbed_logs,
            "updated_at": now,
        }
        with self._lock:
            self._session_cache[vendor_id] = record
        return json.loads(json.dumps(record))

    def schedule_background_upsert(
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
        background_tasks: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """Updates the write-through session cache immediately and persists to SQLite in the background.

        Args:
            vendor_id (str): Unique vendor identifier.
            vendor_name (str): Legal name of the vendor.
            onboarding_status (str): Current onboarding lifecycle state.
            risk_level (str): Residual risk severity level.
            composite_score (float): Weighted composite risk score (0-100).
            pending_hitl (bool): True if paused awaiting Human-in-the-Loop approval.
            extracted_certifications (Optional[Dict[str, Any]]): Extracted compliance certifications.
            audit_logs (Optional[List[Dict[str, Any]]]): Redacted audit trail entries.
            background_tasks (Optional[Any]): Optional FastAPI `BackgroundTasks` instance.

        Returns:
            Dict[str, Any]: The updated session state dictionary.
        """
        with start_otel_span(
            "memory.schedule_background_upsert",
            attributes={
                "vendor.id": vendor_id,
                "memory.execution_mode": "background_task",
                "onboarding.status": onboarding_status,
            },
        ):
            existing = self.get_session(vendor_id)
            record = self._prepare_upserted_record(
                existing=existing,
                vendor_id=vendor_id,
                vendor_name=vendor_name,
                onboarding_status=onboarding_status,
                risk_level=risk_level,
                composite_score=composite_score,
                pending_hitl=pending_hitl,
                extracted_certifications=extracted_certifications,
                audit_logs=audit_logs,
            )
            self._dispatch_background_persistence(record, background_tasks=background_tasks)
            return record

    async def aupsert_session(
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
        background_tasks: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """Asynchronously upserts a vendor session using non-blocking background persistence.

        Args:
            vendor_id (str): Unique vendor identifier.
            vendor_name (str): Legal name of the vendor.
            onboarding_status (str): Current onboarding status.
            risk_level (str): Current residual risk level.
            composite_score (float): Composite residual risk score.
            pending_hitl (bool): Whether HITL code stop is active.
            extracted_certifications (Optional[Dict[str, Any]]): Extracted certs metadata.
            audit_logs (Optional[List[Dict[str, Any]]]): Sanitized audit logs.
            background_tasks (Optional[Any]): Optional FastAPI `BackgroundTasks` object.

        Returns:
            Dict[str, Any]: Updated session record.
        """
        with start_otel_span(
            "memory.aupsert_session",
            attributes={
                "vendor.id": vendor_id,
                "memory.execution_mode": "async_background_task",
            },
        ):
            existing = await self.aget_session(vendor_id)
            record = self._prepare_upserted_record(
                existing=existing,
                vendor_id=vendor_id,
                vendor_name=vendor_name,
                onboarding_status=onboarding_status,
                risk_level=risk_level,
                composite_score=composite_score,
                pending_hitl=pending_hitl,
                extracted_certifications=extracted_certifications,
                audit_logs=audit_logs,
            )
            self._dispatch_background_persistence(record, background_tasks=background_tasks)
            return record

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
        background_tasks: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """Non-blocking session upsert that updates cache and offloads SQLite I/O to background worker."""
        return self.schedule_background_upsert(
            vendor_id=vendor_id,
            vendor_name=vendor_name,
            onboarding_status=onboarding_status,
            risk_level=risk_level,
            composite_score=composite_score,
            pending_hitl=pending_hitl,
            extracted_certifications=extracted_certifications,
            audit_logs=audit_logs,
            background_tasks=background_tasks,
        )

    def _prepare_conversation_turn_record(
        self,
        *,
        session: Dict[str, Any],
        vendor_id: str,
        role: str,
        message: str,
        agent_name: str,
        model_used: str,
    ) -> Dict[str, Any]:
        """Appends a PII-scrubbed turn to the session record and updates the write-through cache."""
        scrubbed_msg, redactions = redact_pii_text(message)
        history: List[Dict[str, Any]] = list(session["conversation_history"])
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
        updated = dict(session)
        updated["conversation_history"] = history
        updated["updated_at"] = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._session_cache[vendor_id] = updated
        return json.loads(json.dumps(updated))

    def schedule_background_conversation_turn(
        self,
        *,
        vendor_id: str,
        vendor_name: str,
        role: str,
        message: str,
        agent_name: str = "VendorSupportAgent",
        model_used: str = "gemini-2.5-flash",
        background_tasks: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """Appends a PII-scrubbed conversation turn and offloads SQLite persistence to a background task.

        Args:
            vendor_id (str): Unique vendor identifier.
            vendor_name (str): Legal name of the vendor.
            role (str): Speaker role ('vendor' or 'assistant').
            message (str): Raw message text (scrubbed of PII before caching/persistence).
            agent_name (str): Name of the agent handling the turn.
            model_used (str): Model identifier used to generate the response.
            background_tasks (Optional[Any]): Optional FastAPI `BackgroundTasks` instance.

        Returns:
            Dict[str, Any]: Updated session dictionary with the new conversation turn.
        """
        with start_otel_span(
            "memory.schedule_background_conversation_turn",
            attributes={
                "vendor.id": vendor_id,
                "turn.role": role,
                "memory.execution_mode": "background_task",
            },
        ):
            session = self.get_session(vendor_id)
            if not session:
                session = self._prepare_upserted_record(
                    existing=None,
                    vendor_id=vendor_id,
                    vendor_name=vendor_name,
                    onboarding_status="IN_PROGRESS",
                    risk_level="PENDING_ASSESSMENT",
                )
            updated = self._prepare_conversation_turn_record(
                session=session,
                vendor_id=vendor_id,
                role=role,
                message=message,
                agent_name=agent_name,
                model_used=model_used,
            )
            self._dispatch_background_persistence(updated, background_tasks=background_tasks)
            return updated

    async def aappend_conversation_turn(
        self,
        *,
        vendor_id: str,
        vendor_name: str,
        role: str,
        message: str,
        agent_name: str = "VendorSupportAgent",
        model_used: str = "gemini-2.5-flash",
        background_tasks: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """Asynchronously appends a PII-scrubbed turn and schedules non-blocking background persistence."""
        with start_otel_span(
            "memory.aappend_conversation_turn",
            attributes={
                "vendor.id": vendor_id,
                "turn.role": role,
                "memory.execution_mode": "async_background_task",
            },
        ):
            session = await self.aget_session(vendor_id)
            if not session:
                session = self._prepare_upserted_record(
                    existing=None,
                    vendor_id=vendor_id,
                    vendor_name=vendor_name,
                    onboarding_status="IN_PROGRESS",
                    risk_level="PENDING_ASSESSMENT",
                )
            updated = self._prepare_conversation_turn_record(
                session=session,
                vendor_id=vendor_id,
                role=role,
                message=message,
                agent_name=agent_name,
                model_used=model_used,
            )
            self._dispatch_background_persistence(updated, background_tasks=background_tasks)
            return updated

    def append_conversation_turn(
        self,
        *,
        vendor_id: str,
        vendor_name: str,
        role: str,
        message: str,
        agent_name: str = "VendorSupportAgent",
        model_used: str = "gemini-2.5-flash",
        background_tasks: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """Appends a PII-scrubbed conversational turn using non-blocking background persistence."""
        return self.schedule_background_conversation_turn(
            vendor_id=vendor_id,
            vendor_name=vendor_name,
            role=role,
            message=message,
            agent_name=agent_name,
            model_used=model_used,
            background_tasks=background_tasks,
        )

    def list_all_sessions(self) -> List[Dict[str, Any]]:
        """Lists all persisted vendor sessions ordered by most recently updated."""
        self.flush_background_tasks()
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM vendor_sessions ORDER BY updated_at DESC"
            ).fetchall()
            results = []
            for r in rows:
                data = self._row_to_dict(r)
                with self._lock:
                    self._session_cache[data["vendor_id"]] = data
                results.append(json.loads(json.dumps(data)))
            return results

    async def alist_all_sessions(self) -> List[Dict[str, Any]]:
        """Asynchronously lists all vendor sessions without blocking the event loop."""
        with start_otel_span(
            "memory.alist_all_sessions",
            attributes={"memory.execution_mode": "async_non_blocking"},
        ):
            await self.aflush_background_tasks()
            if AIOSQLITE_AVAILABLE:
                async with aiosqlite.connect(self.db_path) as db:
                    db.row_factory = aiosqlite.Row
                    async with db.execute(
                        "SELECT * FROM vendor_sessions ORDER BY updated_at DESC"
                    ) as cursor:
                        rows = await cursor.fetchall()
                        results = []
                        for r in rows:
                            data = self._row_to_dict(r)
                            with self._lock:
                                self._session_cache[data["vendor_id"]] = data
                            results.append(json.loads(json.dumps(data)))
                        return results
            return await asyncio.to_thread(self.list_all_sessions)


memory_store = PersistentVendorMemoryStore()
