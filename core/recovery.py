"""
core/recovery.py

دو مسئولیت کاملاً جدا:

۱. Password Recovery (فراموشی رمز عبور):
   از KeyHierarchy.unlock_via_recovery استفاده می‌کند که یک KEK کاملاً مستقل از
   Password (بر پایه‌ی Security Answer + USB) دارد. موفقیت این مسیر یعنی
   Master Key واقعاً (نه فقط یک هش مطابق) در دسترس قرار گرفته - این یک اثبات
   Cryptographic واقعی است، نه صرفاً تطبیق رشته.
   بعد از موفقیت، کاربر یک Password جدید تعیین می‌کند (KeyHierarchy.set_new_password)
   و هیچ فایلی نیازی به re-encrypt ندارد چون Master Key عوض نشده است.

۲. Crash Recovery (پاکسازی بعد از قطع ناگهانی برنامه):
   در startup بعدی، تراکنش‌های نیمه‌کاره (TransactionManager.get_unfinished) بررسی
   می‌شوند. طبق طراحی file_engine، فایل اصلی هرگز قبل از Verify کامل جایگزین
   نمی‌شود، بنابراین تنها اثر جانبی احتمالی یک Crash، وجود فایل‌های موقت یتیم
   (*.slf.tmp) است - این ماژول آن‌ها را شناسایی و پاک می‌کند و تراکنش را
   به ROLLBACK می‌برد (فایل‌هایی که قبل از Crash کامل commit شده بودند در
   دیتابیس LOCKED/UNLOCKED باقی می‌مانند و دست‌نخورده‌اند).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List, Optional

from core.key_manager import KeyHierarchy, AuthenticationFailedError, KeyManagerError
from core.metadata import MetadataStore
from core.transaction import TransactionManager, TxState
from core.file_engine import TEMP_SUFFIX


class RecoveryError(Exception):
    """خطای عمومی Recovery."""


# =========================================================================== Password Recovery
class PasswordRecoveryManager:
    """مدیریت مسیر «رمز عبور را فراموش کرده‌ام» بر پایه‌ی Security Question."""

    def __init__(self, metadata: MetadataStore, keys: KeyHierarchy):
        self.metadata = metadata
        self.keys = keys

    def has_recovery_configured(self) -> bool:
        q = self.metadata.load_security_question()
        ks = self.metadata.load_key_store()
        return q is not None and ks is not None and "wrapped_mk_recovery" in ks

    def get_question(self) -> Optional[str]:
        q = self.metadata.load_security_question()
        return q["question"] if q else None

    def attempt_recovery(self, security_answer: str, usb_secret: bytes) -> bool:
        """
        تلاش برای باز کردن Master Key از مسیر Recovery.
        در صورت موفقیت، Master Key در self.keys بارگذاری می‌شود (آماده برای
        set_new_password) و True برمی‌گردد. در صورت شکست، False (و لاگ ثبت می‌شود).
        """
        key_store = self.metadata.load_key_store()
        if key_store is None or "wrapped_mk_recovery" not in key_store:
            self.metadata.add_log("RECOVERY", "تلاش Recovery بدون پیکربندی موجود", "ERROR")
            return False
        try:
            self.keys.unlock_via_recovery(security_answer, usb_secret, key_store)
        except AuthenticationFailedError:
            self.metadata.add_log("RECOVERY", "تلاش Recovery ناموفق (پاسخ یا USB نادرست)", "WARNING")
            return False
        except KeyManagerError as e:
            self.metadata.add_log("RECOVERY", f"خطای Recovery: {e}", "ERROR")
            return False
        self.metadata.add_log("RECOVERY", "Recovery موفق - Master Key بازیابی شد")
        return True

    def complete_recovery_with_new_password(self, new_password: str, usb_secret: bytes) -> None:
        """
        بعد از attempt_recovery موفق، Password جدید تنظیم می‌شود.
        فایل‌های قفل‌شده‌ی قبلی دست‌نخورده و کاملاً قابل‌بازیابی باقی می‌مانند
        چون Master Key عوض نمی‌شود، فقط wrap آن با Password جدید بازنویسی می‌شود.
        """
        if not self.keys.is_unlocked():
            raise RecoveryError("ابتدا باید attempt_recovery با موفقیت انجام شود")
        key_store = self.metadata.load_key_store()
        new_key_store = self.keys.set_new_password(new_password, usb_secret, key_store)
        self.metadata.save_key_store(new_key_store)
        self.metadata.add_log("PASSWORD_CHANGE", "Password از طریق Recovery با موفقیت تغییر کرد")


# =========================================================================== Crash Recovery
@dataclass
class CrashRecoveryReport:
    unfinished_transactions: int = 0
    temp_files_cleaned: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


class CrashRecoveryManager:
    """
    اسکن و پاکسازی وضعیت بعد از یک Crash/Force-Close/قطع برق.
    باید یک‌بار در startup، بعد از Unlock موفق کاربر (چون برای خواندن مسیرهای
    اصلیِ رمزگذاری‌شده نیاز به Master Key داریم) فراخوانی شود.
    """

    def __init__(self, metadata: MetadataStore, keys: Optional[KeyHierarchy] = None):
        self.metadata = metadata
        self.keys = keys
        self.tx_manager = TransactionManager(metadata)

    def run_startup_scan(self) -> CrashRecoveryReport:
        report = CrashRecoveryReport()
        unfinished = self.tx_manager.get_unfinished()
        report.unfinished_transactions = len(unfinished)

        for tx in unfinished:
            try:
                cleaned = self._clean_transaction(tx)
                report.temp_files_cleaned.extend(cleaned)
            except Exception as e:
                report.warnings.append(f"پاکسازی تراکنش {tx.tx_id} با خطا مواجه شد: {e}")

            try:
                if tx.state != TxState.FAILED:
                    self.tx_manager.fail(tx, "crash_detected_on_startup")
                self.tx_manager.mark_rollback(tx)
            except Exception as e:
                report.warnings.append(f"انتقال state تراکنش {tx.tx_id} شکست خورد: {e}")

            self.metadata.add_log(
                "CRASH_RECOVERY",
                f"تراکنش ناتمام {tx.tx_id} ({tx.op_type}) شناسایی و پاکسازی شد",
                "WARNING",
            )

        return report

    def _clean_transaction(self, tx) -> List[str]:
        """پاک‌سازی فایل‌های موقت یتیم مرتبط با یک تراکنش نیمه‌کاره LOCK یا UNLOCK."""
        cleaned: List[str] = []

        if tx.op_type == "LOCK":
            files = tx.payload.get("files", [])
            dirs = {os.path.dirname(f) for f in files if f}
            for d in dirs:
                cleaned.extend(self._sweep_directory(d))

        elif tx.op_type == "UNLOCK":
            file_ids = tx.payload.get("file_ids", [])
            if self.keys is not None and self.keys.is_unlocked():
                from core.crypto import decrypt_blob, IntegrityError
                metadata_key = self.keys.derive_metadata_key()
                for file_id in file_ids:
                    rec = self.metadata.get_locked_file(file_id)
                    if rec is None or rec.status not in ("LOCKED", "TX_PENDING"):
                        continue  # قبلاً کامل شده - چیزی برای پاک‌سازی نیست
                    try:
                        original_dir = decrypt_blob(
                            metadata_key, rec.enc_original_path, aad=file_id.encode()
                        ).decode("utf-8")
                        cleaned.extend(self._sweep_directory(original_dir))
                    except IntegrityError:
                        continue

        return cleaned

    @staticmethod
    def _sweep_directory(directory: str) -> List[str]:
        """حذف هر فایلی در این پوشه که با الگوی temp لاک/آنلاک برنامه مطابقت دارد."""
        cleaned = []
        if not directory or not os.path.isdir(directory):
            return cleaned
        try:
            entries = os.listdir(directory)
        except OSError:
            return cleaned
        for fn in entries:
            if fn.endswith(TEMP_SUFFIX) or fn.endswith(".restore.tmp"):
                full_path = os.path.join(directory, fn)
                try:
                    os.remove(full_path)
                    cleaned.append(full_path)
                except OSError:
                    pass
        return cleaned
