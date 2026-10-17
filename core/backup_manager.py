"""
core/backup_manager.py

مدیریت کامل Backup روی USB.

طراحی مسیر ذخیره‌سازی روی USB:
    <usb_root>/SecureLockerVault/backups/<backup_id>/
        manifest.enc          -- لیست فایل‌ها (رمزگذاری‌شده با Backup Key)
        files/
            <entry_id>         -- محتوای هر فایل (رمزگذاری‌شده یا خام، بسته به تنظیم کاربر)

تصمیم «رمزگذاری بکاپ» (طبق توافق با کاربر):
    چون فلش فقط دست خودِ کاربر است، امکان غیرفعال‌کردن رمزگذاری Backup وجود دارد
    (سریع‌تر، فایل مستقیم قابل‌خواندن روی فلش). اما پیش‌فرض Encrypt Backup = ON است،
    چون در صورت گم‌شدن/سرقت فلش، بکاپ رمزنگاری‌نشده یعنی افشای کامل محتوا بدون نیاز
    به Password. این یک تصمیم آگاهانه‌ی کاربر است، نه رفتار پیش‌فرض برنامه.

Verification (بخش ۳۳ درخواست):
    Backup هرگز فقط یک copy ساده نیست. بعد از نوشتن هر فایل:
        - اگر Encrypted: با یک پاس decrypt کامل (AEAD authentication) به NullSink، صحت
          کامل تایید می‌شود (بدون نوشتن مجدد به دیسک).
        - اگر Plaintext: SHA-256 مبدا (حین کپی محاسبه می‌شود) با SHA-256 مقصد
          (با یک پاس خواندن مجدد) مقایسه می‌شود.
    اگر هر verification شکست بخورد، کل پوشه‌ی Backup پاک می‌شود و Lock (طبق قانون
    Backup-failed-abort-Lock) اصلاً انجام نمی‌شود.

اتصال Backup به فایل‌های قفل‌شده:
    در لحظه‌ی Backup، فایل هنوز رمزگذاری/قفل نشده (ترتیب workflow: Backup قبل از Lock)،
    بنابراین Backup بر اساس original_path ایندکس می‌شود. بعد از این‌که file_engine فایل
    را قفل کرد، backup_id در رکورد locked_files ذخیره می‌شود. برای پیدا کردن entry دقیق
    داخل یک Backup برای یک file_id مشخص، original_path رمزگشایی‌شده‌ی آن فایل با
    manifest مطابقت داده می‌شود.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional

from core.crypto import (
    make_cipher, encrypt_blob, decrypt_blob, IntegrityError, NullSink,
)
from core.key_manager import KeyHierarchy
from core.metadata import MetadataStore, BackupRecord, LockedFileRecord, new_id, now_iso
from core.usb_manager import UsbKeyInfo

COPY_CHUNK_SIZE = 4 * 1024 * 1024  # 4MB برای کپی streaming plaintext


class BackupManagerError(Exception):
    """خطای عمومی مدیریت Backup."""


class BackupNotAvailableError(BackupManagerError):
    """USB در دسترس نیست - Backup نمی‌تواند انجام شود."""


@dataclass
class BackupResult:
    success: bool
    verified: bool
    backup_id: Optional[str]
    error: Optional[str] = None
    file_count: int = 0
    total_size: int = 0


@dataclass
class BackupSummary:
    """خلاصه‌ی نمایشی یک Backup برای Backup Manager UI."""
    backup_id: str
    created_at: str
    total_size: int
    file_count: int
    encrypted: bool
    verified: bool
    status: str  # OK / CORRUPTED / DELETED / MISSING_ON_USB


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    """نوشتن atomic یک فایل کوچک (مثل manifest) - temp + fsync + replace."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


class BackupManager:
    """
    پیاده‌سازی BackupProvider (سازگار با core.file_engine.BackupProvider Protocol)
    به‌علاوه‌ی امکانات کامل مدیریت Backup برای UI (List/Delete/Restore/Verify).
    """

    def __init__(
        self,
        metadata: MetadataStore,
        keys: KeyHierarchy,
        get_usb: Callable[[], UsbKeyInfo],
        default_encrypt: bool = True,
        logger: Optional[object] = None,
    ):
        """
        get_usb: تابعی که UsbKeyInfo فعلی را برمی‌گرداند یا استثنا پرتاب می‌کند اگر
                 USB وصل نباشد. همیشه fresh فراخوانی می‌شود (هرگز cache نمی‌شود) تا
                 خروج فیزیکی USB فوراً تشخیص داده شود.
        """
        self.metadata = metadata
        self.keys = keys
        self.get_usb = get_usb
        self.default_encrypt = default_encrypt
        self.logger = logger

    def _log(self, event_type: str, message: str, severity: str = "INFO") -> None:
        self.metadata.add_log(event_type, message, severity)
        if self.logger is not None and hasattr(self.logger, "on_log"):
            self.logger.on_log(event_type, message, severity)

    def _require_usb(self) -> UsbKeyInfo:
        try:
            info = self.get_usb()
        except Exception as e:
            raise BackupNotAvailableError(f"USB در دسترس نیست: {e}") from e
        if info is None:
            raise BackupNotAvailableError("USB متصل نیست")
        return info

    # ===================================================================== CREATE (BackupProvider)
    def create_backup(
        self, file_paths: List[str], group_id: str, encrypt: Optional[bool] = None
    ) -> BackupResult:
        """
        ایجاد یک Backup کامل و تایید‌شده از لیست فایل‌ها.
        در صورت هرگونه شکست (USB نبودن، خطای دیسک، شکست Verification)، کل پوشه‌ی
        Backup نیمه‌کاره پاک می‌شود و success=False برگردانده می‌شود (که طبق قرارداد
        file_engine باعث Abort کامل عملیات Lock می‌شود).
        """
        do_encrypt = self.default_encrypt if encrypt is None else encrypt
        try:
            usb_info = self._require_usb()
        except BackupNotAvailableError as e:
            return BackupResult(success=False, verified=False, backup_id=None, error=str(e))

        backup_id = new_id()
        backup_root = Path(usb_info.backup_root()) / "backups" / backup_id
        files_dir = backup_root / "files"

        try:
            files_dir.mkdir(parents=True, exist_ok=False)
        except OSError as e:
            return BackupResult(success=False, verified=False, backup_id=None,
                                 error=f"ساخت پوشه‌ی Backup روی USB شکست خورد: {e}")

        manifest_entries = []
        total_size = 0
        try:
            for original_path in file_paths:
                entry_id = new_id()
                size = os.path.getsize(original_path)
                dest_path = files_dir / entry_id
                sha256_hex = self._copy_one_file(original_path, dest_path, entry_id, do_encrypt)
                manifest_entries.append({
                    "entry_id": entry_id,
                    "original_path": original_path,
                    "size": size,
                    "sha256": sha256_hex,
                })
                total_size += size

            manifest_json = json.dumps(manifest_entries, ensure_ascii=False).encode("utf-8")
            backup_key = self.keys.derive_backup_key()
            enc_manifest = encrypt_blob(backup_key, manifest_json, aad=backup_id.encode())
            _atomic_write_bytes(backup_root / "manifest.enc", enc_manifest)

        except Exception as e:
            shutil.rmtree(backup_root, ignore_errors=True)
            self._log("BACKUP", f"ایجاد Backup شکست خورد: {e}", "ERROR")
            return BackupResult(success=False, verified=False, backup_id=None, error=str(e))

        # ---------------------------------------------------------- Verification (اجباری)
        ok, detail = self._verify_entries(files_dir, manifest_entries, do_encrypt)
        if not ok:
            shutil.rmtree(backup_root, ignore_errors=True)
            self._log("BACKUP", f"Verification بکاپ شکست خورد - Backup حذف شد: {detail}", "ERROR")
            return BackupResult(success=False, verified=False, backup_id=None, error=detail)

        rec = BackupRecord(
            backup_id=backup_id,
            created_at=now_iso(),
            enc_manifest=enc_manifest,
            total_size=total_size,
            file_count=len(manifest_entries),
            encrypted=do_encrypt,
            verified=True,
            verification_detail="OK",
            usb_relative_path=str(backup_root.relative_to(usb_info.drive_root)),
            status="OK",
        )
        self.metadata.add_backup(rec)
        self._log("BACKUP", f"Backup ایجاد و تایید شد: {backup_id} ({len(manifest_entries)} فایل)")
        return BackupResult(
            success=True, verified=True, backup_id=backup_id,
            file_count=len(manifest_entries), total_size=total_size,
        )

    def _copy_one_file(self, src_path: str, dest_path: Path, entry_id: str, encrypt: bool) -> str:
        """کپی Streaming یک فایل (رمزگذاری‌شده یا خام) با محاسبه‌ی SHA-256 مبدا هم‌زمان."""
        sha = hashlib.sha256()
        size = os.path.getsize(src_path)

        if encrypt:
            file_key = self.keys.derive_file_key(f"backup:{entry_id}")
            hmac_key = self.keys.derive_file_hmac_key(f"backup:{entry_id}")
            cipher = make_cipher(file_key, hmac_key)

            class _HashingReader:
                """Wrapper خواندن که هم‌زمان با عبور داده از آن، SHA-256 مبدا را محاسبه می‌کند."""
                def __init__(self, f):
                    self._f = f
                def read(self, n=-1):
                    data = self._f.read(n)
                    if data:
                        sha.update(data)
                    return data

            with open(src_path, "rb") as raw_src, open(dest_path, "wb") as dst:
                hashing_src = _HashingReader(raw_src)
                cipher.encrypt_stream(hashing_src, dst, f"backup:{entry_id}", size, now_iso())
        else:
            with open(src_path, "rb") as src, open(dest_path, "wb") as dst:
                while True:
                    chunk = src.read(COPY_CHUNK_SIZE)
                    if not chunk:
                        break
                    dst.write(chunk)
                    sha.update(chunk)
                dst.flush()
                os.fsync(dst.fileno())

        return sha.hexdigest()

    def _verify_entries(self, files_dir: Path, manifest_entries: list[dict], encrypted: bool) -> tuple[bool, str]:
        for entry in manifest_entries:
            entry_id = entry["entry_id"]
            dest_path = files_dir / entry_id
            if not dest_path.exists():
                return False, f"فایل Backup یافت نشد: {entry_id}"
            if encrypted:
                try:
                    file_key = self.keys.derive_file_key(f"backup:{entry_id}")
                    hmac_key = self.keys.derive_file_hmac_key(f"backup:{entry_id}")
                    cipher = make_cipher(file_key, hmac_key)
                    with open(dest_path, "rb") as f:
                        cipher.decrypt_stream(f, NullSink(), expected_file_id=f"backup:{entry_id}")
                except IntegrityError as e:
                    return False, f"Authentication فایل {entry_id} شکست خورد: {e}"
            else:
                sha = hashlib.sha256()
                with open(dest_path, "rb") as f:
                    while True:
                        chunk = f.read(COPY_CHUNK_SIZE)
                        if not chunk:
                            break
                        sha.update(chunk)
                if sha.hexdigest() != entry["sha256"]:
                    return False, f"عدم تطابق SHA-256 فایل {entry_id}"
                if dest_path.stat().st_size != entry["size"]:
                    return False, f"عدم تطابق اندازه‌ی فایل {entry_id}"
        return True, "OK"

    # ===================================================================== MANIFEST ACCESS
    def _load_manifest(self, backup_id: str) -> list[dict]:
        rec = self.metadata.get_backup(backup_id)
        if rec is None:
            raise BackupManagerError(f"رکورد Backup یافت نشد: {backup_id}")
        backup_key = self.keys.derive_backup_key()
        try:
            manifest_json = decrypt_blob(backup_key, rec.enc_manifest, aad=backup_id.encode())
        except IntegrityError as e:
            raise BackupManagerError(f"رمزگشایی manifest شکست خورد (Backup خراب): {e}") from e
        return json.loads(manifest_json.decode("utf-8"))

    def get_backup_file_list(self, backup_id: str) -> list[dict]:
        """لیست فایل‌های داخل یک Backup (مسیر اصلی + اندازه) - برای نمایش در UI."""
        return self._load_manifest(backup_id)

    # ===================================================================== FIND / RESTORE (BackupProvider)
    def find_valid_backup_for_file(self, file_id: str) -> Optional[str]:
        """
        اگر یک Backup معتبر برای این file_id (بر اساس مسیر اصلی رمزگشایی‌شده) وجود دارد،
        backup_id آن را برمی‌گرداند؛ در غیر این صورت None.
        """
        rec = self.metadata.get_locked_file(file_id)
        if rec is None or rec.backup_id is None:
            return None
        backup_rec = self.metadata.get_backup(rec.backup_id)
        if backup_rec is None or backup_rec.status != "OK" or not backup_rec.verified:
            return None

        try:
            original_path = self._reconstruct_original_path(rec)
            manifest = self._load_manifest(rec.backup_id)
        except BackupManagerError:
            return None

        entry = next((e for e in manifest if e["original_path"] == original_path), None)
        if entry is None:
            return None
        return rec.backup_id

    def _reconstruct_original_path(self, rec: LockedFileRecord) -> str:
        name_key = self.keys.derive_name_map_key()
        metadata_key = self.keys.derive_metadata_key()
        original_name = decrypt_blob(name_key, rec.enc_original_name, aad=rec.file_id.encode()).decode("utf-8")
        original_dir = decrypt_blob(metadata_key, rec.enc_original_path, aad=rec.file_id.encode()).decode("utf-8")
        return os.path.join(original_dir, original_name)

    def get_original_path_for_file(self, file_id: str) -> Optional[str]:
        """نسخه‌ی عمومی _reconstruct_original_path - برای نمایش در UI (مثلاً هنگام پیشنهاد Restore)."""
        rec = self.metadata.get_locked_file(file_id)
        if rec is None:
            return None
        try:
            return self._reconstruct_original_path(rec)
        except IntegrityError:
            return None

    def restore_file_from_backup(self, backup_id: str, file_id: str, dest_path: str) -> bool:
        """
        بازیابی صریح یک فایل از Backup به dest_path. فقط با تایید کاربر (از UI) فراخوانی شود.
        هرگز مستقیم فایل مقصد را overwrite نمی‌کند (همان الگوی atomic replace).
        """
        rec = self.metadata.get_locked_file(file_id)
        if rec is None:
            return False
        try:
            original_path = self._reconstruct_original_path(rec)
            manifest = self._load_manifest(backup_id)
        except BackupManagerError as e:
            self._log("RESTORE", f"بازیابی از Backup شکست خورد: {e}", "ERROR")
            return False

        entry = next((e for e in manifest if e["original_path"] == original_path), None)
        if entry is None:
            self._log("RESTORE", f"entry متناظر در manifest یافت نشد: {file_id}", "ERROR")
            return False

        try:
            usb_info = self._require_usb()
        except BackupNotAvailableError as e:
            self._log("RESTORE", str(e), "ERROR")
            return False

        backup_rec = self.metadata.get_backup(backup_id)
        src_path = Path(usb_info.drive_root) / backup_rec.usb_relative_path / "files" / entry["entry_id"]
        if not src_path.exists():
            self._log("RESTORE", f"فایل Backup روی USB یافت نشد: {src_path}", "ERROR")
            return False

        temp_dest = dest_path + ".restore.tmp"
        try:
            if backup_rec.encrypted:
                entry_id = entry["entry_id"]
                file_key = self.keys.derive_file_key(f"backup:{entry_id}")
                hmac_key = self.keys.derive_file_hmac_key(f"backup:{entry_id}")
                cipher = make_cipher(file_key, hmac_key)
                with open(src_path, "rb") as s, open(temp_dest, "wb") as d:
                    cipher.decrypt_stream(s, d, expected_file_id=f"backup:{entry_id}")
            else:
                sha = hashlib.sha256()
                with open(src_path, "rb") as s, open(temp_dest, "wb") as d:
                    while True:
                        chunk = s.read(COPY_CHUNK_SIZE)
                        if not chunk:
                            break
                        d.write(chunk)
                        sha.update(chunk)
                    d.flush()
                    os.fsync(d.fileno())
                if sha.hexdigest() != entry["sha256"]:
                    raise BackupManagerError("عدم تطابق SHA-256 حین بازیابی")

            if os.path.getsize(temp_dest) != entry["size"]:
                raise BackupManagerError("اندازه‌ی فایل بازیابی‌شده مطابقت ندارد")

            os.replace(temp_dest, dest_path)
        except Exception as e:
            if os.path.exists(temp_dest):
                os.remove(temp_dest)
            self._log("RESTORE", f"بازیابی فایل شکست خورد: {e}", "ERROR")
            return False

        self._log("RESTORE", f"فایل با موفقیت از Backup بازیابی شد: {file_id} <- {backup_id}")
        return True

    # ===================================================================== UI-FACING: LIST / VERIFY / DELETE
    def list_backups(self) -> List[BackupSummary]:
        recs = self.metadata.list_backups()
        return [
            BackupSummary(
                backup_id=r.backup_id, created_at=r.created_at, total_size=r.total_size,
                file_count=r.file_count, encrypted=r.encrypted, verified=r.verified, status=r.status,
            )
            for r in recs
        ]

    def verify_backup(self, backup_id: str) -> tuple[bool, str]:
        """بررسی مجدد صحت یک Backup موجود (دکمه‌ی Verify در UI)."""
        rec = self.metadata.get_backup(backup_id)
        if rec is None:
            return False, "Backup یافت نشد"
        try:
            usb_info = self._require_usb()
        except BackupNotAvailableError as e:
            return False, str(e)

        backup_root = Path(usb_info.drive_root) / rec.usb_relative_path
        files_dir = backup_root / "files"
        if not files_dir.exists():
            self.metadata.update_backup_status(backup_id, "CORRUPTED", verified=False,
                                                verification_detail="پوشه‌ی Backup روی USB یافت نشد")
            return False, "پوشه‌ی Backup روی USB یافت نشد"

        try:
            manifest = self._load_manifest(backup_id)
        except BackupManagerError as e:
            self.metadata.update_backup_status(backup_id, "CORRUPTED", verified=False, verification_detail=str(e))
            return False, str(e)

        ok, detail = self._verify_entries(files_dir, manifest, rec.encrypted)
        self.metadata.update_backup_status(
            backup_id, "OK" if ok else "CORRUPTED", verified=ok, verification_detail=detail
        )
        self._log("BACKUP", f"Verify دستی Backup {backup_id}: {'موفق' if ok else 'ناموفق - ' + detail}")
        return ok, detail

    def refresh(self) -> dict:
        """
        هماهنگ‌سازی وضعیت بین دیتابیس لپ‌تاپ و آنچه واقعاً روی USB موجود است.
        بکاپ‌هایی که در DB هستند ولی روی دیسک USB نیستند MISSING علامت می‌خورند.
        """
        try:
            usb_info = self._require_usb()
        except BackupNotAvailableError:
            return {"error": "USB متصل نیست", "checked": 0, "missing": 0, "ok": 0}

        report = {"checked": 0, "missing": 0, "ok": 0}
        for rec in self.metadata.list_backups():
            report["checked"] += 1
            backup_root = Path(usb_info.drive_root) / rec.usb_relative_path
            if not backup_root.exists():
                self.metadata.update_backup_status(rec.backup_id, "MISSING_ON_USB", verified=False,
                                                    verification_detail="پوشه روی USB پیدا نشد")
                report["missing"] += 1
            else:
                report["ok"] += 1
        return report

    def delete_backup(self, backup_id: str) -> bool:
        """
        حذف یک Backup. توجه: تایید ("آیا مطمئن هستید؟") مسئولیت لایه‌ی UI است -
        این متد فقط پس از تایید کاربر فراخوانی شود.
        """
        rec = self.metadata.get_backup(backup_id)
        if rec is None:
            return False
        try:
            usb_info = self._require_usb()
            backup_root = Path(usb_info.drive_root) / rec.usb_relative_path
            if backup_root.exists():
                shutil.rmtree(backup_root)
        except BackupNotAvailableError:
            # اگر USB نیست، فقط رکورد DB حذف می‌شود؛ فایل فیزیکی دفعه‌ی بعد که USB
            # وصل شد به‌صورت یتیم باقی می‌ماند و می‌تواند دستی پاک شود.
            pass
        self.metadata.delete_backup_record(backup_id)
        self._log("BACKUP", f"Backup حذف شد: {backup_id}", "WARNING")
        return True

    def delete_old_backups(self, keep_latest_n: int) -> int:
        """حذف بکاپ‌های قدیمی‌تر، فقط N مورد آخر نگه داشته می‌شود."""
        backups = self.metadata.list_backups()  # از قبل مرتب‌شده بر اساس created_at DESC
        to_delete = backups[keep_latest_n:]
        count = 0
        for b in to_delete:
            if self.delete_backup(b.backup_id):
                count += 1
        return count

    def is_backup_referenced_by_active_files(self, backup_id: str) -> bool:
        """آیا فایل قفل‌شده‌ی فعالی هست که به این Backup متکی باشد (برای هشدار قبل از حذف)."""
        for rec in self.metadata.list_locked_files(status="LOCKED"):
            if rec.backup_id == backup_id:
                return True
        return False
