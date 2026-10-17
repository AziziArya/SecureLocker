"""
core/file_engine.py

موتور اصلی Lock/Unlock فایل‌ها.

اصل طلایی (بدون استثنا): فایل اصلی هرگز مستقیم overwrite نمی‌شود.
    original_file --(read stream)--> encrypt --> temp_file --(verify: full re-decrypt+auth)--> os.replace(temp, final_path)

اگر در هر نقطه‌ای قبل از os.replace خطا رخ دهد: temp حذف می‌شود، original دست‌نخورده می‌ماند.
اگر بعد از os.replace (که خودِ سیستم‌عامل atomic تضمین می‌کند) crash رخ دهد: final_path از قبل
کامل و verify شده است، فقط ممکن است original قدیمی (در صورت تغییر نام) هنوز حذف نشده باشد که
بی‌ضرر است (Crash Recovery در استارت بعدی آن را پاک می‌کند - نه یک وضعیت داده‌ی خراب).

این ماژول به یک "Backup Provider" وابسته است (Dependency Injection) که در core/backup_manager.py
پیاده‌سازی می‌شود. اینجا فقط قرارداد (Protocol) تعریف می‌شود تا file_engine از جزئیات USB/مسیر
بکاپ کاملاً مستقل بماند.
"""

from __future__ import annotations

import os
import shutil
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Callable, List, Optional, Protocol

from core.crypto import (
    make_cipher, encrypt_blob, decrypt_blob, filesystem_safe_name,
    from_filesystem_safe_name, IntegrityError, CryptoError, FormatError,
    DEFAULT_CHUNK_SIZE, NullSink,
)
from core.key_manager import KeyHierarchy
from core.metadata import MetadataStore, LockedFileRecord, new_id, now_iso
from core.transaction import TransactionManager, TxState, TransactionHandle

LOCK_MARKER_SUFFIX = ".slock"
TEMP_SUFFIX = ".slf.tmp"


class FileEngineError(Exception):
    """خطای عمومی موتور فایل."""


class ValidationError(FileEngineError):
    """فایل/مسیر ورودی نامعتبر است (وجود ندارد، دسترسی ندارد، symlink است و ...)."""


class ConflictError(FileEngineError):
    """مقصد از قبل وجود دارد و نیاز به تصمیم کاربر است."""


class CorruptedFileError(FileEngineError):
    """فایل قفل‌شده خراب/دستکاری‌شده است - نیازمند تصمیم کاربر درباره‌ی Backup."""
    def __init__(self, file_id: str, message: str):
        super().__init__(message)
        self.file_id = file_id


# --------------------------------------------------------------------------- Backup Provider Contract
@dataclass
class BackupResult:
    success: bool
    verified: bool
    backup_id: Optional[str]
    error: Optional[str] = None
    file_count: int = 0
    total_size: int = 0


class BackupProvider(Protocol):
    """
    قرارداد بین file_engine و core/backup_manager.py.
    پیاده‌سازی واقعی (که به USB، ساختار SecureLockerVault و verification کامل نیاز دارد)
    در core/backup_manager.py انجام می‌شود.
    """

    def create_backup(self, file_paths: List[str], group_id: str) -> BackupResult:
        ...

    def find_valid_backup_for_file(self, file_id: str) -> Optional[str]:
        """اگر یک بکاپ معتبر برای این file_id وجود دارد، backup_id آن را برمی‌گرداند."""
        ...

    def restore_file_from_backup(self, backup_id: str, file_id: str, dest_path: str) -> bool:
        ...


class NullBackupProvider:
    """
    پیاده‌سازی پیش‌فرض برای وقتی کاربر Backup را انتخاب نکرده است.
    هرگز نباید وقتی options.backup_requested=True است استفاده شود.
    """

    def create_backup(self, file_paths: List[str], group_id: str) -> BackupResult:
        return BackupResult(success=False, verified=False, backup_id=None,
                             error="Backup provider تنظیم نشده است")

    def find_valid_backup_for_file(self, file_id: str) -> Optional[str]:
        return None

    def restore_file_from_backup(self, backup_id: str, file_id: str, dest_path: str) -> bool:
        return False


# --------------------------------------------------------------------------- Options / Results
@dataclass
class LockOptions:
    backup_requested: bool
    protect_names: bool
    protect_structure: bool = False
    emergency_lock: bool = False
    chunk_size: int = DEFAULT_CHUNK_SIZE

    def __post_init__(self):
        # الزام معماری: محافظت ساختار فولدر بدون محافظت نام فایل معنا ندارد
        # (چون نام فایل داخل همان فولدر نمایان می‌ماند و اطلاعات لو می‌رود).
        if self.protect_structure and not self.protect_names:
            self.protect_names = True


@dataclass
class FileLockResult:
    original_path: str
    file_id: Optional[str]
    success: bool
    skipped: bool
    error: Optional[str] = None
    final_path: Optional[str] = None


@dataclass
class LockBatchResult:
    group_id: str
    results: List[FileLockResult] = field(default_factory=list)
    backup_id: Optional[str] = None
    backup_status: str = "NOT_REQUESTED"  # VERIFIED / NOT_REQUESTED / FAILED
    names_protected: bool = False
    structure_protected: bool = False
    skipped_reparse_points: List[str] = field(default_factory=list)
    aborted: bool = False
    abort_reason: Optional[str] = None

    @property
    def success_count(self) -> int:
        return sum(1 for r in self.results if r.success)

    @property
    def failed_count(self) -> int:
        return sum(1 for r in self.results if not r.success and not r.skipped)

    @property
    def skipped_count(self) -> int:
        return sum(1 for r in self.results if r.skipped) + len(self.skipped_reparse_points)


@dataclass
class FileUnlockResult:
    file_id: str
    success: bool
    restored_path: Optional[str]
    error: Optional[str] = None
    used_backup: bool = False


@dataclass
class UnlockBatchResult:
    results: List[FileUnlockResult] = field(default_factory=list)

    @property
    def success_count(self) -> int:
        return sum(1 for r in self.results if r.success)

    @property
    def failed_count(self) -> int:
        return sum(1 for r in self.results if not r.success)


ConflictAction = str  # "REPLACE" | "KEEP_BOTH" | "RENAME" | "SKIP" | "ABORT"
ConflictResolver = Callable[[str], ConflictAction]  # ورودی: مسیر مقصد در تعارض


class _NullWriter(NullSink):
    """نام قدیمی برای سازگاری داخلی - از core.crypto.NullSink استفاده می‌کند."""
    pass


def _safe_remove(path: str) -> None:
    try:
        if os.path.exists(path):
            os.remove(path)
    except OSError:
        pass


def _is_symlink_or_reparse(path: str) -> bool:
    """
    تشخیص symlink/junction. در ویندوز، junctionها هم از طریق os.path.islink قابل
    تشخیص کامل نیستند (Directory Junction با os.stat().st_reparse_tag نیاز دارد)،
    بنابراین از ترکیب چند بررسی استفاده می‌کنیم.
    """
    if os.path.islink(path):
        return True
    try:
        st = os.lstat(path)
        if hasattr(st, "st_file_attributes") and hasattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT"):
            if st.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                return True
    except (OSError, AttributeError):
        pass
    return False


class FileEngine:
    """موتور اصلی عملیات Lock/Unlock."""

    def __init__(
        self,
        metadata: MetadataStore,
        keys: KeyHierarchy,
        backup_provider: Optional[BackupProvider] = None,
        logger: Optional[object] = None,
        session: Optional[object] = None,
    ):
        self.metadata = metadata
        self.keys = keys
        self.backup_provider = backup_provider or NullBackupProvider()
        self.logger = logger
        self.session = session
        self.tx_manager = TransactionManager(metadata)

    def _log(self, event_type: str, message: str, severity: str = "INFO") -> None:
        self.metadata.add_log(event_type, message, severity)
        if self.logger is not None and hasattr(self.logger, "on_log"):
            self.logger.on_log(event_type, message, severity)

    # ===================================================================== VALIDATION / COLLECTION
    def collect_files_for_lock(self, paths: List[str]) -> tuple[List[str], List[str]]:
        """
        گسترش لیست مسیرهای انتخاب‌شده (فایل یا فولدر) به یک لیست تخت از فایل‌های واقعی.
        symlink/junction به‌صورت پیش‌فرض Skip می‌شوند (طبق سیاست امنیتی بخش ۳۱).
        خروجی: (files, skipped_reparse_points)
        """
        files: List[str] = []
        skipped: List[str] = []
        seen = set()

        def add_file(p: str):
            ap = os.path.abspath(p)
            if ap in seen:
                return
            if _is_symlink_or_reparse(p):
                skipped.append(ap)
                return
            if not os.path.isfile(p):
                return
            seen.add(ap)
            files.append(ap)

        for raw_path in paths:
            if not os.path.exists(raw_path):
                raise ValidationError(f"مسیر وجود ندارد: {raw_path}")
            if _is_symlink_or_reparse(raw_path):
                skipped.append(os.path.abspath(raw_path))
                continue
            if os.path.isfile(raw_path):
                add_file(raw_path)
            elif os.path.isdir(raw_path):
                for dirpath, dirnames, filenames in os.walk(raw_path, followlinks=False):
                    # فیلتر کردن زیرپوشه‌های symlink/junction قبل از نزول به آن‌ها
                    kept_dirs = []
                    for d in dirnames:
                        full_d = os.path.join(dirpath, d)
                        if _is_symlink_or_reparse(full_d):
                            skipped.append(os.path.abspath(full_d))
                        else:
                            kept_dirs.append(d)
                    dirnames[:] = kept_dirs
                    for fn in filenames:
                        add_file(os.path.join(dirpath, fn))
            else:
                raise ValidationError(f"نوع مسیر پشتیبانی نمی‌شود: {raw_path}")

        return files, skipped

    # ===================================================================== LOCK
    def lock_paths(
        self,
        paths: List[str],
        options: LockOptions,
        progress_cb: Optional[Callable[[str, int, int, int, int], None]] = None,
    ) -> LockBatchResult:
        """
        قفل کردن لیستی از مسیرها (فایل/فولدر).
        progress_cb(current_file_name, file_bytes_done, file_bytes_total, files_done, files_total)
        """
        group_id = new_id()
        result = LockBatchResult(
            group_id=group_id,
            names_protected=options.protect_names,
            structure_protected=options.protect_structure,
        )

        from core.security import OperationGuard
        with OperationGuard(self.session):
            return self._lock_paths_inner(paths, options, result, group_id, progress_cb)

    def _lock_paths_inner(
        self,
        paths: List[str],
        options: LockOptions,
        result: LockBatchResult,
        group_id: str,
        progress_cb: Optional[Callable[[str, int, int, int, int], None]] = None,
    ) -> LockBatchResult:

        try:
            files, skipped = self.collect_files_for_lock(paths)
        except ValidationError as e:
            result.aborted = True
            result.abort_reason = str(e)
            self._log("LOCK", f"اعتبارسنجی مسیرها شکست خورد: {e}", "ERROR")
            return result

        result.skipped_reparse_points = skipped
        if skipped:
            self._log("LOCK", f"{len(skipped)} مسیر symlink/junction نادیده گرفته شد", "WARNING")

        # حذف فایل‌هایی که از قبل قفل هستند
        already_locked = []
        remaining_files = []
        for f in files:
            if self.metadata.get_locked_file_by_path(f) is not None:
                already_locked.append(f)
            else:
                remaining_files.append(f)
        for f in already_locked:
            result.results.append(FileLockResult(f, None, False, True, "این فایل از قبل قفل شده است"))

        if not remaining_files:
            self._log("LOCK", "هیچ فایل جدیدی برای قفل کردن یافت نشد", "INFO")
            return result

        tx = self.tx_manager.start("LOCK", {
            "group_id": group_id, "files": remaining_files,
            "protect_names": options.protect_names, "protect_structure": options.protect_structure,
        })

        # ------------------------------------------------- Backup (اگر خواسته شده)
        backup_id = None
        if options.backup_requested:
            tx = self.tx_manager.advance(tx, TxState.BACKUP_CREATED)
            backup_result = self.backup_provider.create_backup(remaining_files, group_id)
            if not backup_result.success or not backup_result.verified:
                # قانون طلایی: Backup ناموفق => Lock انجام نشود (هیچ فایلی touch نشده)
                self.tx_manager.fail(tx, f"backup_failed: {backup_result.error}")
                result.aborted = True
                result.backup_status = "FAILED"
                result.abort_reason = f"Backup ناموفق بود، Lock انجام نشد: {backup_result.error}"
                self._log("BACKUP", f"Backup ناموفق - Lock کامل abort شد: {backup_result.error}", "ERROR")
                return result
            backup_id = backup_result.backup_id
            result.backup_id = backup_id
            result.backup_status = "VERIFIED"
            self._log("BACKUP", f"Backup تایید شد: {backup_id} ({backup_result.file_count} فایل)")
        else:
            result.backup_status = "NOT_REQUESTED"

        tx = self.tx_manager.advance(tx, TxState.ENCRYPTING)

        files_total = len(remaining_files)
        for idx, f in enumerate(remaining_files):
            def file_progress(done, total, _f=f, _idx=idx):
                if progress_cb:
                    progress_cb(_f, done, total, _idx, files_total)

            attempts = 2 if options.emergency_lock else 1
            last_error = None
            success = False
            file_result = None
            for attempt in range(attempts):
                try:
                    file_result = self._lock_single_file(
                        f, options, group_id, backup_id, progress_cb=file_progress
                    )
                    success = True
                    break
                except FileEngineError as e:
                    last_error = str(e)
                except OSError as e:
                    last_error = str(e)
                except Exception as e:
                    # شامل خطاهای دیتابیس (مثلاً sqlite3.OperationalError) که ممکن
                    # است اگر USB (که حالا دیتابیس هم رویش است) وسط کار جدا شود رخ دهد.
                    # به‌جای crash کل batch، این فایل failed گزارش می‌شود و بقیه ادامه می‌یابند.
                    last_error = f"خطای غیرمنتظره (احتمال قطع USB): {e}"
            if success:
                result.results.append(file_result)
            else:
                result.results.append(FileLockResult(f, None, False, False, last_error))
                self._log("LOCK", f"قفل فایل ناموفق: {f} - {last_error}", "ERROR")

        tx = self.tx_manager.advance(tx, TxState.VERIFIED)
        try:
            self.tx_manager.commit(tx)
        except Exception:
            pass  # فایل‌های موفق تا این‌جا سالم‌اند؛ فقط وضعیت تراکنش ثبت نشد (احتمال قطع USB)

        # ------------------------------------------------- Folder Structure Protection
        if options.protect_structure and result.success_count > 0:
            try:
                self._protect_folder_structure(paths, group_id)
            except Exception as e:
                # اگر محافظت ساختار فولدر شکست بخورد، فایل‌ها همچنان قفل و سالم‌اند
                # (این مرحله فقط ظاهر پوشه‌ها را تغییر می‌دهد، نه محتوای رمزگذاری‌شده)
                self._log("LOCK", f"محافظت ساختار فولدر با خطا مواجه شد: {e}", "WARNING")

        self._log(
            "LOCK",
            f"عملیات Lock تمام شد: {result.success_count} موفق, "
            f"{result.failed_count} ناموفق, {result.skipped_count} نادیده گرفته شد",
        )
        return result

    def _lock_single_file(
        self,
        original_path: str,
        options: LockOptions,
        group_id: str,
        backup_id: Optional[str],
        progress_cb: Optional[Callable[[int, int], None]] = None,
    ) -> FileLockResult:
        if not os.path.isfile(original_path):
            raise ValidationError(f"فایل وجود ندارد: {original_path}")

        file_id = new_id()
        size = os.path.getsize(original_path)
        created_at = now_iso()

        file_key = self.keys.derive_file_key(file_id)
        hmac_key = self.keys.derive_file_hmac_key(file_id)
        cipher = make_cipher(file_key, hmac_key, chunk_size=options.chunk_size)

        directory = os.path.dirname(original_path)
        original_name = os.path.basename(original_path)

        name_key = self.keys.derive_name_map_key()
        enc_name_blob = encrypt_blob(name_key, original_name.encode("utf-8"), aad=file_id.encode())

        if options.protect_names:
            safe_stub = filesystem_safe_name(enc_name_blob)
            # جلوگیری از نام‌های خیلی طولانی (محدودیت مسیر ویندوز)
            safe_name = safe_stub[:80] + LOCK_MARKER_SUFFIX
        else:
            safe_name = original_name + LOCK_MARKER_SUFFIX

        final_path = os.path.join(directory, safe_name)
        if os.path.abspath(final_path) != os.path.abspath(original_path) and os.path.exists(final_path):
            raise ValidationError(f"تعارض نام: مقصد از قبل وجود دارد: {final_path}")

        temp_path = os.path.join(directory, f".{file_id}{TEMP_SUFFIX}")

        try:
            with open(original_path, "rb") as src, open(temp_path, "wb") as dst:
                cipher.encrypt_stream(src, dst, file_id, size, created_at, progress_cb=progress_cb)

            # --- Verify: رمزگشایی کامل به یک sink دورریز، برای تایید صحت end-to-end
            verify_cipher = make_cipher(file_key, hmac_key, chunk_size=options.chunk_size)
            with open(temp_path, "rb") as vsrc:
                verify_cipher.decrypt_stream(vsrc, _NullWriter(), expected_file_id=file_id)
        except Exception as e:
            _safe_remove(temp_path)
            raise FileEngineError(f"رمزگذاری/تایید فایل شکست خورد: {e}") from e

        try:
            os.replace(temp_path, final_path)
        except OSError as e:
            _safe_remove(temp_path)
            raise FileEngineError(f"جایگزینی atomic شکست خورد: {e}") from e

        if os.path.abspath(final_path) != os.path.abspath(original_path):
            try:
                os.remove(original_path)
            except OSError as e:
                self._log(
                    "LOCK",
                    f"فایل اصلی بعد از قفل موفق حذف نشد (بی‌ضرر، محتوا امن است): {original_path} - {e}",
                    "WARNING",
                )

        metadata_key = self.keys.derive_metadata_key()
        enc_path_blob = encrypt_blob(metadata_key, directory.encode("utf-8"), aad=file_id.encode())

        chunk_count = (size + options.chunk_size - 1) // options.chunk_size if size > 0 else 0
        rec = LockedFileRecord(
            file_id=file_id,
            enc_original_path=enc_path_blob,
            enc_original_name=enc_name_blob,
            current_disk_path=final_path,
            name_protected=options.protect_names,
            structure_protected=False,  # بعداً توسط _protect_folder_structure به‌روزرسانی می‌شود
            size_original=size,
            chunk_count=chunk_count,
            algorithm_version="SLF1-AES256GCM",
            status="LOCKED",
            backup_id=backup_id,
            parent_group_id=group_id,
            locked_at=created_at,
            updated_at=created_at,
            extra={},
        )
        self.metadata.add_locked_file(rec)
        self._log("LOCK", f"فایل قفل شد: {file_id}")
        return FileLockResult(original_path, file_id, True, False, None, final_path)

    def _protect_folder_structure(self, root_paths: List[str], group_id: str) -> None:
        """
        محافظت ساختار فولدر: پوشه‌ها bottom-up به نام obfuscated تغییر نام می‌یابند.

        Trade-off مستندشده (طبق درخواست تحلیل قبل از پیاده‌سازی):
        در NTFS امکان "مخفی کردن کامل و همزمان قابل‌بازیابی" ساختار فولدر بدون منتقل
        کردن فایل‌ها از مسیر اصلی وجود ندارد؛ راه‌حل انتخاب‌شده این است که خودِ پوشه‌ها
        (نه فایل‌های داخلشان که قبلاً جدا پردازش شده‌اند) در همان مکان فیزیکی روی دیسک
        rename می‌شوند به یک نام Base32 مشتق از رمزگذاری AEAD نام اصلی + کلید Master.
        مسیر فیزیکی/عمق درخت حفظ می‌شود (فایل‌ها جابه‌جا نمی‌شوند)، فقط نام پوشه‌ها
        در Explorer دیگر قابل‌فهم نیست. Mapping هر پوشه در دیتابیس محلی (رمزگذاری‌شده)
        نگه داشته می‌شود تا در Unlock قابل بازگردانی دقیق باشد.
        """
        name_key = self.keys.derive_name_map_key()
        dirs_to_rename: List[str] = []
        for root in root_paths:
            if os.path.isdir(root):
                for dirpath, dirnames, _ in os.walk(root, followlinks=False):
                    dirs_to_rename.append(dirpath)
                dirs_to_rename.append(root) if root not in dirs_to_rename else None

        # bottom-up: عمیق‌ترین پوشه‌ها اول rename شوند تا مسیر والدین حین پیمایش خراب نشود
        dirs_to_rename = sorted(set(dirs_to_rename), key=lambda p: p.count(os.sep), reverse=True)

        for old_dir in dirs_to_rename:
            if not os.path.isdir(old_dir):
                continue  # ممکن است قبلاً rename شده باشد (والد یک دایرکتوری دیگر)
            parent = os.path.dirname(old_dir)
            original_name = os.path.basename(old_dir)
            folder_id = new_id()
            enc_name = encrypt_blob(name_key, original_name.encode("utf-8"), aad=folder_id.encode())
            safe_name = "d_" + filesystem_safe_name(enc_name)[:60]
            new_dir = os.path.join(parent, safe_name)
            if os.path.exists(new_dir):
                continue  # از تعارض صرف‌نظر می‌شود؛ پوشه با نام اصلی باقی می‌ماند (بی‌ضرر)
            try:
                os.rename(old_dir, new_dir)
            except OSError:
                continue

            self.metadata.set_meta(
                f"folder_map:{group_id}:{folder_id}",
                enc_name,
            )
            # به‌روزرسانی current_disk_path رکوردهای فایل‌های داخل این پوشه (چون مسیرشان تغییر کرد)
            for rec in self.metadata.list_locked_files_by_group(group_id):
                if rec.current_disk_path.startswith(old_dir + os.sep) or os.path.dirname(rec.current_disk_path) == old_dir:
                    new_path = rec.current_disk_path.replace(old_dir, new_dir, 1)
                    self.metadata.update_locked_file_path(rec.file_id, new_path)
            self._log("LOCK", f"ساختار پوشه محافظت شد: {folder_id}")

    # ===================================================================== UNLOCK
    def unlock_files(
        self,
        file_ids: List[str],
        conflict_resolver: Optional[ConflictResolver] = None,
        progress_cb: Optional[Callable[[str, int, int, int, int], None]] = None,
    ) -> UnlockBatchResult:
        """
        باز کردن قفل لیستی از فایل‌ها (بر اساس file_id).
        اگر رمزگشایی/Authentication یک فایل شکست بخورد، فایل رمزگذاری‌شده دست‌نخورده
        باقی می‌ماند و CorruptedFileError به‌صورت نتیجه‌ی failed ثبت می‌شود (فراخواننده/UI
        می‌تواند سپس با backup_provider گزینه‌ی Restore را به کاربر پیشنهاد دهد).
        """
        from core.security import OperationGuard
        with OperationGuard(self.session):
            return self._unlock_files_inner(file_ids, conflict_resolver, progress_cb)

    def _unlock_files_inner(
        self,
        file_ids: List[str],
        conflict_resolver: Optional[ConflictResolver] = None,
        progress_cb: Optional[Callable[[str, int, int, int, int], None]] = None,
    ) -> UnlockBatchResult:
        result = UnlockBatchResult()
        name_key = self.keys.derive_name_map_key()
        metadata_key = self.keys.derive_metadata_key()

        tx = self.tx_manager.start("UNLOCK", {"file_ids": file_ids})
        tx = self.tx_manager.advance(tx, TxState.ENCRYPTING)  # حالت مشترک "در حال پردازش رمزی"

        files_total = len(file_ids)
        for idx, file_id in enumerate(file_ids):
            def file_progress(done, total, _idx=idx):
                if progress_cb:
                    progress_cb(file_id, done, total, _idx, files_total)

            try:
                should_abort = self._unlock_one_file(
                    file_id, name_key, metadata_key, conflict_resolver, file_progress, result
                )
            except Exception as e:
                # شامل خطاهای دیتابیس (مثلاً sqlite3.OperationalError در صورت قطع
                # USB که حالا دیتابیس هم رویش است). فایل رمزگذاری‌شده دست‌نخورده
                # می‌ماند چون این خطا فقط بعد یا قبل از عملیات فایل رخ می‌دهد.
                result.results.append(
                    FileUnlockResult(file_id, False, None, f"خطای غیرمنتظره (احتمال قطع USB): {e}")
                )
                should_abort = False
            if should_abort:
                break

        tx = self.tx_manager.advance(tx, TxState.VERIFIED)
        try:
            self.tx_manager.commit(tx)
        except Exception:
            pass
        return result

    def _unlock_one_file(self, file_id, name_key, metadata_key, conflict_resolver, file_progress, result) -> bool:
        """
        پردازش Unlock یک فایل. خروجی True یعنی «کاربر کل عملیات را لغو کرد»
        (ABORT) و حلقه‌ی فراخواننده باید متوقف شود؛ در غیر این صورت False.
        """
        rec = self.metadata.get_locked_file(file_id)
        if rec is None or rec.status != "LOCKED":
            result.results.append(FileUnlockResult(file_id, False, None, "رکورد فایل قفل‌شده یافت نشد"))
            return False

        if not os.path.isfile(rec.current_disk_path):
            backup_id = self.backup_provider.find_valid_backup_for_file(file_id)
            result.results.append(FileUnlockResult(
                file_id, False, None,
                "فایل رمزگذاری‌شده روی دیسک یافت نشد" + (" (Backup موجود است)" if backup_id else ""),
            ))
            return False

        try:
            original_name = decrypt_blob(name_key, rec.enc_original_name, aad=file_id.encode()).decode("utf-8")
            original_dir = decrypt_blob(metadata_key, rec.enc_original_path, aad=file_id.encode()).decode("utf-8")
        except IntegrityError as e:
            result.results.append(FileUnlockResult(file_id, False, None, f"رمزگشایی متادیتا شکست خورد: {e}"))
            return False

        os.makedirs(original_dir, exist_ok=True)
        target_path = os.path.join(original_dir, original_name)

        if os.path.exists(target_path):
            action = conflict_resolver(target_path) if conflict_resolver else "SKIP"
            if action == "SKIP":
                result.results.append(FileUnlockResult(file_id, False, None, "رد شد (تعارض نام)"))
                return False
            if action == "ABORT":
                result.results.append(FileUnlockResult(file_id, False, None, "توسط کاربر لغو شد"))
                return True
            if action == "KEEP_BOTH" or action == "RENAME":
                target_path = self._generate_non_conflicting_name(target_path)
            # اگر REPLACE باشد: target_path همان می‌ماند و بعداً atomic جایگزین می‌شود

        try:
            file_key = self.keys.derive_file_key(file_id)
            hmac_key = self.keys.derive_file_hmac_key(file_id)
            cipher = make_cipher(file_key, hmac_key)

            temp_out = target_path + TEMP_SUFFIX
            with open(rec.current_disk_path, "rb") as src, open(temp_out, "wb") as dst:
                cipher.decrypt_stream(src, dst, expected_file_id=file_id, progress_cb=file_progress)

            if os.path.getsize(temp_out) != rec.size_original:
                raise FileEngineError("اندازه‌ی فایل بازیابی‌شده با متادیتا مطابقت ندارد")

        except (IntegrityError, FormatError, FileEngineError) as e:
            _safe_remove(target_path + TEMP_SUFFIX)
            backup_id = self.backup_provider.find_valid_backup_for_file(file_id)
            self.metadata.update_locked_file_status(file_id, "CORRUPTED")
            self._log("INTEGRITY_FAILURE", f"فایل خراب/دستکاری‌شده: {file_id} - {e}", "ERROR")
            result.results.append(FileUnlockResult(
                file_id, False, None,
                f"فایل آسیب دیده است: {e}" + (" - یک Backup معتبر پیدا شد" if backup_id else " - Backup معتبری یافت نشد"),
            ))
            return False
        except OSError as e:
            _safe_remove(target_path + TEMP_SUFFIX)
            result.results.append(FileUnlockResult(file_id, False, None, f"خطای سیستم فایل: {e}"))
            return False

        try:
            os.replace(temp_out, target_path)
        except OSError as e:
            _safe_remove(temp_out)
            result.results.append(FileUnlockResult(file_id, False, None, f"جایگزینی atomic شکست خورد: {e}"))
            return False

        if os.path.abspath(target_path) != os.path.abspath(rec.current_disk_path):
            _safe_remove(rec.current_disk_path)

        self.metadata.update_locked_file_status(file_id, "UNLOCKED")
        self._log("UNLOCK", f"فایل باز شد: {file_id} -> {target_path}")
        result.results.append(FileUnlockResult(file_id, True, target_path))
        return False

    def restore_corrupted_from_backup(self, file_id: str, backup_id: str, dest_path: str) -> bool:
        """
        بازیابی صریح یک فایل خراب از یک Backup مشخص - فقط با تایید صریح کاربر فراخوانی شود.
        هرگز به‌صورت خودکار (بدون تایید) فراخوانی نمی‌شود.
        """
        ok = self.backup_provider.restore_file_from_backup(backup_id, file_id, dest_path)
        if ok:
            self.metadata.update_locked_file_status(file_id, "UNLOCKED")
            self._log("RESTORE", f"فایل از Backup بازیابی شد: {file_id} از {backup_id}")
        else:
            self._log("RESTORE", f"بازیابی از Backup ناموفق: {file_id} از {backup_id}", "ERROR")
        return ok

    def get_original_path(self, file_id: str) -> Optional[str]:
        """بازسازی مسیر اصلی کامل (پوشه + نام) یک فایل قفل‌شده - برای UI (پیشنهاد Restore)."""
        rec = self.metadata.get_locked_file(file_id)
        if rec is None:
            return None
        try:
            name_key = self.keys.derive_name_map_key()
            metadata_key = self.keys.derive_metadata_key()
            original_name = decrypt_blob(name_key, rec.enc_original_name, aad=file_id.encode()).decode("utf-8")
            original_dir = decrypt_blob(metadata_key, rec.enc_original_path, aad=file_id.encode()).decode("utf-8")
            return os.path.join(original_dir, original_name)
        except IntegrityError:
            return None

    @staticmethod
    def _generate_non_conflicting_name(path: str) -> str:
        p = Path(path)
        stem, suffix = p.stem, p.suffix
        counter = 1
        candidate = p
        while candidate.exists():
            candidate = p.with_name(f"{stem} ({counter}){suffix}")
            counter += 1
        return str(candidate)
