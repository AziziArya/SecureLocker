"""
core/transaction.py

State Machine برای عملیات‌های حساس (Lock/Unlock) تا در صورت Crash، Force Close،
یا قطع برق، برنامه بتواند در اجرای بعدی دقیقاً بفهمد کجا متوقف شده است.

    PENDING -> BACKUP_CREATED -> ENCRYPTING -> VERIFIED -> COMMITTED
    (هر کدام از state های بالا) -> FAILED
    (FAILED/COMMITTED هر دو حالت پایانی‌اند؛ ROLLBACK برای مواردی که نیاز به
     پاک‌سازی صریح توسط منطق بازیابی دارند)

نکته‌ی حیاتی طراحی: خودِ این State Machine چیزی را روی دیسک تغییر نمی‌دهد.
امنیت واقعی فایل از این می‌آید که file_engine هرگز فایل اصلی را قبل از تایید کامل
(Verify) رمزگشایی/رمزگذاری جایگزین نمی‌کند. این ماژول فقط یک "دفترچه‌ی وضعیت"
است تا در startup بعدی بتوان فهمید فلان عملیات نیمه‌کاره مانده و چه فایل‌های
موقتی (temp) ممکن است باید پاک‌سازی شوند.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from core.metadata import MetadataStore, new_id


class TxState(str, Enum):
    PENDING = "PENDING"
    BACKUP_CREATED = "BACKUP_CREATED"
    ENCRYPTING = "ENCRYPTING"
    VERIFIED = "VERIFIED"
    COMMITTED = "COMMITTED"
    FAILED = "FAILED"
    ROLLBACK = "ROLLBACK"


_TERMINAL_STATES = {TxState.COMMITTED, TxState.FAILED, TxState.ROLLBACK}

# انتقال‌های مجاز - هر انتقال دیگر یعنی باگ منطقی در کد و باید فوراً fail شود
_ALLOWED_TRANSITIONS = {
    TxState.PENDING: {TxState.BACKUP_CREATED, TxState.ENCRYPTING, TxState.FAILED},
    TxState.BACKUP_CREATED: {TxState.ENCRYPTING, TxState.FAILED},
    TxState.ENCRYPTING: {TxState.VERIFIED, TxState.FAILED},
    TxState.VERIFIED: {TxState.COMMITTED, TxState.FAILED},
    TxState.COMMITTED: set(),
    TxState.FAILED: {TxState.ROLLBACK},
    TxState.ROLLBACK: set(),
}


class TransactionError(Exception):
    """خطای عمومی State Machine تراکنش."""


class InvalidTransitionError(TransactionError):
    """انتقال بین دو state غیرمجاز است - نشانه‌ی یک باگ منطقی."""


@dataclass
class TransactionHandle:
    tx_id: str
    op_type: str
    state: TxState
    payload: dict


class TransactionManager:
    """لایه‌ی نازک روی MetadataStore برای مدیریت type-safe از state machine."""

    def __init__(self, metadata: MetadataStore):
        self._metadata = metadata

    def start(self, op_type: str, payload: dict) -> TransactionHandle:
        tx_id = new_id()
        self._metadata.create_transaction(tx_id, op_type, payload)
        return TransactionHandle(tx_id=tx_id, op_type=op_type, state=TxState.PENDING, payload=payload)

    def advance(self, handle: TransactionHandle, new_state: TxState, payload: Optional[dict] = None) -> TransactionHandle:
        allowed = _ALLOWED_TRANSITIONS.get(handle.state, set())
        if new_state not in allowed:
            raise InvalidTransitionError(
                f"انتقال غیرمجاز: {handle.state} -> {new_state} (tx_id={handle.tx_id})"
            )
        merged_payload = payload if payload is not None else handle.payload
        self._metadata.update_transaction_state(handle.tx_id, new_state.value, merged_payload)
        handle.state = new_state
        handle.payload = merged_payload
        return handle

    def commit(self, handle: TransactionHandle) -> TransactionHandle:
        return self.advance(handle, TxState.COMMITTED)

    def fail(self, handle: TransactionHandle, reason: str) -> TransactionHandle:
        payload = dict(handle.payload)
        payload["failure_reason"] = reason
        if handle.state == TxState.COMMITTED:
            raise InvalidTransitionError("نمی‌توان یک تراکنش COMMITTED را FAILED کرد")
        self._metadata.update_transaction_state(handle.tx_id, TxState.FAILED.value, payload)
        handle.state = TxState.FAILED
        handle.payload = payload
        return handle

    def mark_rollback(self, handle: TransactionHandle) -> TransactionHandle:
        if handle.state != TxState.FAILED:
            raise InvalidTransitionError("فقط تراکنش FAILED می‌تواند ROLLBACK شود")
        self._metadata.update_transaction_state(handle.tx_id, TxState.ROLLBACK.value, handle.payload)
        handle.state = TxState.ROLLBACK
        return handle

    def get_unfinished(self) -> list[TransactionHandle]:
        """
        تراکنش‌های نیمه‌کاره از اجرای قبلی - برای Crash Recovery در startup.
        این تابع خودش هیچ پاک‌سازی‌ای انجام نمی‌دهد؛ فقط گزارش می‌دهد.
        منطق پاک‌سازی واقعی (حذف temp فایل‌های یتیم و ...) در core/recovery.py است.
        """
        rows = self._metadata.get_unfinished_transactions()
        return [
            TransactionHandle(tx_id=r["tx_id"], op_type=r["op_type"], state=TxState(r["state"]), payload=r["payload"])
            for r in rows
        ]

    @staticmethod
    def is_terminal(state: TxState) -> bool:
        return state in _TERMINAL_STATES
