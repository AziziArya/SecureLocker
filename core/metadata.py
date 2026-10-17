"""
core/metadata.py

لایه‌ی دیتابیس (SQLite) برای Secure Locker.

مسئولیت این ماژول فقط ذخیره‌سازی است - نه رمزنگاری. فیلدهای حساس (مسیر اصلی فایل،
نام اصلی فایل و ...) از بیرون (توسط file_engine با کلیدهای key_manager) به‌صورت
از قبل رمزگذاری‌شده (blob) به این ماژول داده می‌شوند و همین‌طور خام دریافت می‌شوند.
این جداسازی concerns باعث می‌شود منطق SQL از منطق رمزنگاری کاملاً مستقل بماند.

هیچ‌کدام از این‌ها هرگز در این دیتابیس ذخیره نمی‌شوند:
    - Password (نه plaintext، نه هیچ فرم قابل بازگشت)
    - USB Secret
    - Master Key
    - File Key / HMAC Key (این‌ها هرگز ذخیره نمی‌شوند - همیشه on-the-fly از Master Key
      با HKDF مشتق می‌شوند)

چیزی که *ذخیره می‌شود*: verifier هش‌شده‌ی Password (برای auth سریع)، wrapped Master Key
(بی‌فایده بدون KEK)، fingerprint یک‌طرفه‌ی USB، و metadata رمزگذاری‌شده‌ی فایل‌ها.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Optional

SCHEMA_VERSION = 1


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id() -> str:
    return str(uuid.uuid4())


class MetadataError(Exception):
    """خطای عمومی لایه‌ی دیتابیس."""


# --------------------------------------------------------------------------- Schema
_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS db_meta (
    key TEXT PRIMARY KEY,
    value BLOB
);

CREATE TABLE IF NOT EXISTS locked_files (
    file_id TEXT PRIMARY KEY,
    enc_original_path BLOB NOT NULL,      -- مسیر نسبی اصلی، رمزگذاری‌شده (همیشه)
    enc_original_name BLOB NOT NULL,      -- نام اصلی فایل، رمزگذاری‌شده (همیشه)
    current_disk_path TEXT NOT NULL,      -- مسیر فعلی روی دیسک (لازم برای پیدا کردن فایل)
    name_protected INTEGER NOT NULL,      -- 0/1: آیا نام روی دیسک هم obfuscate شده
    structure_protected INTEGER NOT NULL, -- 0/1: آیا مسیر فولدر هم obfuscate شده
    size_original INTEGER NOT NULL,
    chunk_count INTEGER NOT NULL,
    algorithm_version TEXT NOT NULL,
    status TEXT NOT NULL,                 -- LOCKED / UNLOCKED / CORRUPTED / TX_PENDING
    backup_id TEXT,
    parent_group_id TEXT,                 -- برای گروه‌بندی فایل‌های یک عملیات Lock واحد
    locked_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    extra_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_locked_files_status ON locked_files(status);
CREATE INDEX IF NOT EXISTS idx_locked_files_group ON locked_files(parent_group_id);

CREATE TABLE IF NOT EXISTS backups (
    backup_id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    enc_manifest BLOB NOT NULL,   -- لیست فایل‌ها/مسیرهای اصلی، رمزگذاری‌شده
    total_size INTEGER NOT NULL,
    file_count INTEGER NOT NULL,
    encrypted INTEGER NOT NULL,   -- 0/1: آیا خودِ محتوای بکاپ رمزگذاری شده یا خام (تصمیم کاربر)
    verified INTEGER NOT NULL,    -- 0/1
    verification_detail TEXT,
    usb_relative_path TEXT NOT NULL,
    status TEXT NOT NULL          -- OK / CORRUPTED / DELETED
);

CREATE TABLE IF NOT EXISTS transactions (
    tx_id TEXT PRIMARY KEY,
    op_type TEXT NOT NULL,       -- LOCK / UNLOCK
    state TEXT NOT NULL,         -- PENDING/BACKUP_CREATED/ENCRYPTING/VERIFIED/COMMITTED/FAILED/ROLLBACK
    started_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    payload_json TEXT NOT NULL   -- snapshot لازم برای resume/rollback (بدون داده‌ی حساس خام)
);

CREATE TABLE IF NOT EXISTS logs (
    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,      -- INFO/WARNING/ERROR/CRITICAL
    message TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_logs_type ON logs(event_type);
"""


@dataclass
class LockedFileRecord:
    file_id: str
    enc_original_path: bytes
    enc_original_name: bytes
    current_disk_path: str
    name_protected: bool
    structure_protected: bool
    size_original: int
    chunk_count: int
    algorithm_version: str
    status: str
    backup_id: Optional[str]
    parent_group_id: Optional[str]
    locked_at: str
    updated_at: str
    extra: dict = field(default_factory=dict)

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> "LockedFileRecord":
        return LockedFileRecord(
            file_id=row["file_id"],
            enc_original_path=row["enc_original_path"],
            enc_original_name=row["enc_original_name"],
            current_disk_path=row["current_disk_path"],
            name_protected=bool(row["name_protected"]),
            structure_protected=bool(row["structure_protected"]),
            size_original=row["size_original"],
            chunk_count=row["chunk_count"],
            algorithm_version=row["algorithm_version"],
            status=row["status"],
            backup_id=row["backup_id"],
            parent_group_id=row["parent_group_id"],
            locked_at=row["locked_at"],
            updated_at=row["updated_at"],
            extra=json.loads(row["extra_json"]) if row["extra_json"] else {},
        )


@dataclass
class BackupRecord:
    backup_id: str
    created_at: str
    enc_manifest: bytes
    total_size: int
    file_count: int
    encrypted: bool
    verified: bool
    verification_detail: Optional[str]
    usb_relative_path: str
    status: str

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> "BackupRecord":
        return BackupRecord(
            backup_id=row["backup_id"],
            created_at=row["created_at"],
            enc_manifest=row["enc_manifest"],
            total_size=row["total_size"],
            file_count=row["file_count"],
            encrypted=bool(row["encrypted"]),
            verified=bool(row["verified"]),
            verification_detail=row["verification_detail"],
            usb_relative_path=row["usb_relative_path"],
            status=row["status"],
        )


class MetadataStore:
    """
    لایه‌ی اصلی دسترسی به دیتابیس. Thread-safe (با Lock داخلی) چون GUI عملیات سنگین
    را در Thread جدا اجرا می‌کند و ممکن است هم‌زمان با Main Thread به DB دسترسی پیدا کند.
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA synchronous=FULL;")  # اولویت با Durability، نه سرعت
        self._conn.execute("PRAGMA foreign_keys=ON;")
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.executescript(_SCHEMA_SQL)
            self._conn.commit()
            row = self._conn.execute(
                "SELECT value FROM db_meta WHERE key = 'schema_version'"
            ).fetchone()
            if row is None:
                self._conn.execute(
                    "INSERT INTO db_meta(key, value) VALUES (?, ?)",
                    ("schema_version", str(SCHEMA_VERSION)),
                )
                self._conn.commit()
            # در نسخه‌های بعدی: منطق migration بر اساس مقدار فعلی schema_version این‌جا اضافه می‌شود.

    @contextmanager
    def _cursor(self) -> Iterator[sqlite3.Cursor]:
        with self._lock:
            cur = self._conn.cursor()
            try:
                yield cur
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
            finally:
                cur.close()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ----------------------------------------------------------- db_meta (key-value عمومی)
    def set_meta(self, key: str, value) -> None:
        if isinstance(value, str):
            value = value.encode("utf-8")
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO db_meta(key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )

    def get_meta(self, key: str) -> Optional[bytes]:
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM db_meta WHERE key = ?", (key,)
            ).fetchone()
            return row["value"] if row else None

    def get_meta_str(self, key: str) -> Optional[str]:
        v = self.get_meta(key)
        return v.decode("utf-8") if v is not None else None

    # ----------------------------------------------------------- Key Store (JSON سریالایز شده)
    def _save_store_dict(self, meta_key: str, store: dict) -> None:
        """کمکی عمومی: ذخیره‌ی یک دیکشنری شامل bytes/str به‌صورت JSON+hex (برای key_store و recovery_store)."""
        serializable = {
            k: (v.hex() if isinstance(v, (bytes, bytearray)) else v)
            for k, v in store.items()
        }
        self.set_meta(meta_key, json.dumps(serializable))

    def _load_store_dict(self, meta_key: str) -> Optional[dict]:
        raw = self.get_meta_str(meta_key)
        if raw is None:
            return None
        d = json.loads(raw)
        out = {}
        for k, v in d.items():
            if isinstance(v, str) and _looks_like_hex(v):
                out[k] = bytes.fromhex(v)
            else:
                out[k] = v
        return out

    def save_key_store(self, key_store: dict) -> None:
        """ذخیره‌ی دیکشنری key_store (شامل salts, verifier, wrapped_mk و ...)."""
        self._save_store_dict("key_store", key_store)

    def load_key_store(self) -> Optional[dict]:
        return self._load_store_dict("key_store")

    def save_recovery_store(self, recovery_store: dict) -> None:
        """ذخیره‌ی دیکشنری recovery_store (salt_recovery, wrapped_mk_recovery)."""
        self._save_store_dict("recovery_store", recovery_store)

    def load_recovery_store(self) -> Optional[dict]:
        return self._load_store_dict("recovery_store")

    def save_security_question(self, question: str, salt: bytes, answer_hash: bytes) -> None:
        self.set_meta("security_question", question)
        self.set_meta("security_answer_salt", salt)
        self.set_meta("security_answer_hash", answer_hash)

    def load_security_question(self) -> Optional[dict]:
        q = self.get_meta_str("security_question")
        salt = self.get_meta("security_answer_salt")
        h = self.get_meta("security_answer_hash")
        if q is None or salt is None or h is None:
            return None
        return {"question": q, "answer_salt": salt, "answer_hash": h}

    def save_usb_fingerprint(self, fingerprint: bytes) -> None:
        self.set_meta("usb_fingerprint", fingerprint)

    def load_usb_fingerprint(self) -> Optional[bytes]:
        return self.get_meta("usb_fingerprint")

    def is_initialized(self) -> bool:
        """آیا Setup اولیه (Password + USB + Security Question) قبلاً انجام شده؟"""
        return self.get_meta("key_store") is not None

    # ----------------------------------------------------------- locked_files
    def add_locked_file(self, rec: LockedFileRecord) -> None:
        with self._cursor() as cur:
            cur.execute(
                """INSERT INTO locked_files (
                    file_id, enc_original_path, enc_original_name, current_disk_path,
                    name_protected, structure_protected, size_original, chunk_count,
                    algorithm_version, status, backup_id, parent_group_id,
                    locked_at, updated_at, extra_json
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    rec.file_id, rec.enc_original_path, rec.enc_original_name,
                    rec.current_disk_path, int(rec.name_protected), int(rec.structure_protected),
                    rec.size_original, rec.chunk_count, rec.algorithm_version, rec.status,
                    rec.backup_id, rec.parent_group_id, rec.locked_at, rec.updated_at,
                    json.dumps(rec.extra, ensure_ascii=False),
                ),
            )

    def update_locked_file_status(self, file_id: str, status: str) -> None:
        with self._cursor() as cur:
            cur.execute(
                "UPDATE locked_files SET status = ?, updated_at = ? WHERE file_id = ?",
                (status, now_iso(), file_id),
            )

    def update_locked_file_path(self, file_id: str, new_disk_path: str) -> None:
        with self._cursor() as cur:
            cur.execute(
                "UPDATE locked_files SET current_disk_path = ?, updated_at = ? WHERE file_id = ?",
                (new_disk_path, now_iso(), file_id),
            )

    def get_locked_file(self, file_id: str) -> Optional[LockedFileRecord]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM locked_files WHERE file_id = ?", (file_id,)
            ).fetchone()
            return LockedFileRecord._row_to_record(row) if row else None

    def get_locked_file_by_path(self, current_disk_path: str) -> Optional[LockedFileRecord]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM locked_files WHERE current_disk_path = ?", (current_disk_path,)
            ).fetchone()
            return LockedFileRecord._row_to_record(row) if row else None

    def list_locked_files(self, status: Optional[str] = None) -> list[LockedFileRecord]:
        with self._lock:
            if status:
                rows = self._conn.execute(
                    "SELECT * FROM locked_files WHERE status = ? ORDER BY locked_at DESC", (status,)
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM locked_files ORDER BY locked_at DESC"
                ).fetchall()
            return [LockedFileRecord._row_to_record(r) for r in rows]

    def list_locked_files_by_group(self, parent_group_id: str) -> list[LockedFileRecord]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM locked_files WHERE parent_group_id = ?", (parent_group_id,)
            ).fetchall()
            return [LockedFileRecord._row_to_record(r) for r in rows]

    def delete_locked_file(self, file_id: str) -> None:
        with self._cursor() as cur:
            cur.execute("DELETE FROM locked_files WHERE file_id = ?", (file_id,))

    # ----------------------------------------------------------- backups
    def add_backup(self, rec: BackupRecord) -> None:
        with self._cursor() as cur:
            cur.execute(
                """INSERT INTO backups (
                    backup_id, created_at, enc_manifest, total_size, file_count,
                    encrypted, verified, verification_detail, usb_relative_path, status
                ) VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (
                    rec.backup_id, rec.created_at, rec.enc_manifest, rec.total_size,
                    rec.file_count, int(rec.encrypted), int(rec.verified),
                    rec.verification_detail, rec.usb_relative_path, rec.status,
                ),
            )

    def get_backup(self, backup_id: str) -> Optional[BackupRecord]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM backups WHERE backup_id = ?", (backup_id,)
            ).fetchone()
            return BackupRecord._row_to_record(row) if row else None

    def list_backups(self) -> list[BackupRecord]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM backups ORDER BY created_at DESC"
            ).fetchall()
            return [BackupRecord._row_to_record(r) for r in rows]

    def update_backup_status(self, backup_id: str, status: str, verified: Optional[bool] = None,
                              verification_detail: Optional[str] = None) -> None:
        with self._cursor() as cur:
            if verified is not None:
                cur.execute(
                    "UPDATE backups SET status = ?, verified = ?, verification_detail = ? WHERE backup_id = ?",
                    (status, int(verified), verification_detail, backup_id),
                )
            else:
                cur.execute(
                    "UPDATE backups SET status = ? WHERE backup_id = ?", (status, backup_id)
                )

    def delete_backup_record(self, backup_id: str) -> None:
        with self._cursor() as cur:
            cur.execute("DELETE FROM backups WHERE backup_id = ?", (backup_id,))

    # ----------------------------------------------------------- transactions
    def create_transaction(self, tx_id: str, op_type: str, payload: dict) -> None:
        ts = now_iso()
        with self._cursor() as cur:
            cur.execute(
                """INSERT INTO transactions (tx_id, op_type, state, started_at, updated_at, payload_json)
                   VALUES (?,?,?,?,?,?)""",
                (tx_id, op_type, "PENDING", ts, ts, json.dumps(payload, ensure_ascii=False)),
            )

    def update_transaction_state(self, tx_id: str, state: str, payload: Optional[dict] = None) -> None:
        with self._cursor() as cur:
            if payload is not None:
                cur.execute(
                    "UPDATE transactions SET state = ?, updated_at = ?, payload_json = ? WHERE tx_id = ?",
                    (state, now_iso(), json.dumps(payload, ensure_ascii=False), tx_id),
                )
            else:
                cur.execute(
                    "UPDATE transactions SET state = ?, updated_at = ? WHERE tx_id = ?",
                    (state, now_iso(), tx_id),
                )

    def get_transaction(self, tx_id: str) -> Optional[dict]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM transactions WHERE tx_id = ?", (tx_id,)
            ).fetchone()
            if not row:
                return None
            return {
                "tx_id": row["tx_id"], "op_type": row["op_type"], "state": row["state"],
                "started_at": row["started_at"], "updated_at": row["updated_at"],
                "payload": json.loads(row["payload_json"]),
            }

    def get_unfinished_transactions(self) -> list[dict]:
        """تراکنش‌هایی که نه COMMITTED شده‌اند و نه ROLLBACK - برای Crash Recovery در Startup."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM transactions WHERE state NOT IN ('COMMITTED', 'ROLLBACK') "
                "ORDER BY started_at ASC"
            ).fetchall()
            return [
                {
                    "tx_id": r["tx_id"], "op_type": r["op_type"], "state": r["state"],
                    "started_at": r["started_at"], "updated_at": r["updated_at"],
                    "payload": json.loads(r["payload_json"]),
                }
                for r in rows
            ]

    # ----------------------------------------------------------- logs
    def add_log(self, event_type: str, message: str, severity: str = "INFO") -> None:
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO logs (timestamp, event_type, severity, message) VALUES (?,?,?,?)",
                (now_iso(), event_type, severity, message),
            )

    def query_logs(
        self,
        event_type: Optional[str] = None,
        severity: Optional[str] = None,
        search_text: Optional[str] = None,
        limit: int = 1000,
    ) -> list[dict]:
        query = "SELECT * FROM logs WHERE 1=1"
        params: list[Any] = []
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if search_text:
            query += " AND message LIKE ?"
            params.append(f"%{search_text}%")
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
            return [
                {
                    "log_id": r["log_id"], "timestamp": r["timestamp"],
                    "event_type": r["event_type"], "severity": r["severity"],
                    "message": r["message"],
                }
                for r in rows
            ]

    def clear_logs(self) -> None:
        with self._cursor() as cur:
            cur.execute("DELETE FROM logs")


def _looks_like_hex(s: str) -> bool:
    if len(s) == 0 or len(s) % 2 != 0:
        return False
    try:
        bytes.fromhex(s)
        return True
    except ValueError:
        return False
