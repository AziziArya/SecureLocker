"""
tests/test_scenarios.py

پیاده‌سازی دقیق ۲۸ سناریوی تست درخواستی (بخش ۴۵ مشخصات پروژه).
هر تست رفتار مورد انتظار را در docstring مستند می‌کند.
"""

from __future__ import annotations

import os
import shutil
import time

import pytest

from core.file_engine import (
    LockOptions, FileEngine, BackupResult, TEMP_SUFFIX,
)
from core.key_manager import KeyHierarchy, AuthenticationFailedError
from core.recovery import PasswordRecoveryManager, CrashRecoveryManager
from core.transaction import TransactionManager, TxState
from tests.conftest import make_file, make_binary_file


class _AlwaysSucceedBackup:
    def __init__(self):
        self.calls = 0

    def create_backup(self, file_paths, group_id):
        self.calls += 1
        return BackupResult(success=True, verified=True, backup_id=f"b{self.calls}", file_count=len(file_paths))

    def find_valid_backup_for_file(self, file_id):
        return None

    def restore_file_from_backup(self, backup_id, file_id, dest_path):
        return False


class _AlwaysFailBackup:
    def create_backup(self, file_paths, group_id):
        return BackupResult(success=False, verified=False, backup_id=None, error="simulated failure")

    def find_valid_backup_for_file(self, file_id):
        return None

    def restore_file_from_backup(self, backup_id, file_id, dest_path):
        return False


# ============================================================================= 1-2: Lock/Unlock small file
def test_01_lock_small_file(vault):
    """انتظار: فایل کوچک با موفقیت قفل می‌شود، در همان مسیر باقی می‌ماند، محتوا رمزگذاری می‌شود."""
    engine = FileEngine(vault["db"], vault["kh"], backup_provider=_AlwaysSucceedBackup())
    f = make_file(os.path.join(vault["work"], "small.txt"), "hello secure world")
    result = engine.lock_paths([f], LockOptions(backup_requested=False, protect_names=False))
    assert result.success_count == 1
    assert not os.path.exists(f)
    locked_path = result.results[0].final_path
    assert os.path.dirname(locked_path) == vault["work"]
    with open(locked_path, "rb") as fh:
        raw = fh.read()
    assert b"hello secure world" not in raw


def test_02_unlock_same_file(vault):
    """انتظار: بعد از Unlock، فایل دقیقاً با همان محتوا و نام به مسیر اصلی برمی‌گردد."""
    engine = FileEngine(vault["db"], vault["kh"], backup_provider=_AlwaysSucceedBackup())
    f = make_file(os.path.join(vault["work"], "small.txt"), "hello secure world")
    lock_res = engine.lock_paths([f], LockOptions(backup_requested=False, protect_names=False))
    file_id = lock_res.results[0].file_id
    unlock_res = engine.unlock_files([file_id])
    assert unlock_res.success_count == 1
    assert unlock_res.results[0].restored_path == f
    with open(f) as fh:
        assert fh.read() == "hello secure world"


# ============================================================================= 3: Large file
def test_03_lock_large_file(vault):
    """انتظار: فایل چند مگابایتی بدون خطا و بدون بارگذاری کامل در RAM قفل/باز می‌شود."""
    engine = FileEngine(vault["db"], vault["kh"], backup_provider=_AlwaysSucceedBackup())
    f = os.path.join(vault["work"], "large.bin")
    data = os.urandom(30 * 1024 * 1024 + 123)
    make_binary_file(f, data)
    lock_res = engine.lock_paths([f], LockOptions(backup_requested=False, protect_names=False))
    assert lock_res.success_count == 1
    unlock_res = engine.unlock_files([lock_res.results[0].file_id])
    assert unlock_res.success_count == 1
    with open(f, "rb") as fh:
        assert fh.read() == data


# ============================================================================= 4-5: Backup + Lock / Backup failure
def test_04_backup_and_lock(engine_with_backup):
    """انتظار: با انتخاب Backup&Lock، هم Backup واقعی روی USB ساخته و تایید می‌شود، هم فایل قفل می‌شود."""
    v = engine_with_backup
    f = make_file(os.path.join(v["work"], "doc.txt"), "important content")
    result = v["engine"].lock_paths([f], LockOptions(backup_requested=True, protect_names=False))
    assert result.success_count == 1
    assert result.backup_status == "VERIFIED"
    assert len(v["db"].list_backups()) == 1


def test_05_backup_failure_aborts_lock(vault):
    """انتظار (قانون طلایی): اگر Backup ناموفق شود، هیچ فایلی قفل نمی‌شود و اصلی دست‌نخورده می‌ماند."""
    engine = FileEngine(vault["db"], vault["kh"], backup_provider=_AlwaysFailBackup())
    f = make_file(os.path.join(vault["work"], "must_survive.txt"), "critical data")
    result = engine.lock_paths([f], LockOptions(backup_requested=True, protect_names=False))
    assert result.aborted is True
    assert os.path.exists(f)
    with open(f) as fh:
        assert fh.read() == "critical data"
    assert len(vault["db"].list_locked_files(status="LOCKED")) == 0


# ============================================================================= 6-8: Unlock auth failures
def test_06_unlock_wrong_password(vault):
    """انتظار: Password نادرست هرگز Master Key را باز نمی‌کند (حتی با USB درست)."""
    key_store = vault["db"].load_key_store()
    kh2 = KeyHierarchy()
    with pytest.raises(AuthenticationFailedError):
        kh2.unlock("TotallyWrongPassword!", vault["usb_info"].usb_secret, key_store)


def test_07_unlock_without_usb(vault):
    """انتظار: بدون USB (حتی با Password درست) Master Key باز نمی‌شود."""
    key_store = vault["db"].load_key_store()
    kh2 = KeyHierarchy()
    with pytest.raises(AuthenticationFailedError):
        kh2.unlock(vault["password"], os.urandom(32), key_store)  # usb_secret نادرست/نبود


def test_08_unlock_wrong_usb(vault):
    """انتظار: USB اشتباه (حتی با Password درست) رد می‌شود."""
    key_store = vault["db"].load_key_store()
    wrong_usb_secret = os.urandom(32)
    kh2 = KeyHierarchy()
    with pytest.raises(AuthenticationFailedError):
        kh2.unlock(vault["password"], wrong_usb_secret, key_store)


# ============================================================================= 9: Password change
def test_09_password_change(vault):
    """انتظار: بعد از تغییر Password، فایل‌های قبلاً قفل‌شده هنوز با Password جدید باز می‌شوند."""
    engine = FileEngine(vault["db"], vault["kh"], backup_provider=_AlwaysSucceedBackup())
    f = make_file(os.path.join(vault["work"], "a.txt"), "data")
    lock_res = engine.lock_paths([f], LockOptions(backup_requested=False, protect_names=False))
    file_id = lock_res.results[0].file_id

    key_store = vault["db"].load_key_store()
    new_key_store = vault["kh"].change_password(
        vault["password"], "NewPassword9!", vault["usb_info"].usb_secret, key_store
    )
    vault["db"].save_key_store(new_key_store)

    kh_new = KeyHierarchy()
    kh_new.unlock("NewPassword9!", vault["usb_info"].usb_secret, new_key_store)
    engine2 = FileEngine(vault["db"], kh_new, backup_provider=_AlwaysSucceedBackup())
    unlock_res = engine2.unlock_files([file_id])
    assert unlock_res.success_count == 1
    with open(f) as fh:
        assert fh.read() == "data"


# ============================================================================= 10: Recovery
def test_10_recovery(vault):
    """انتظار: فراموشی Password با Security Answer صحیح + USB صحیح قابل بازیابی است
    و فایل‌های قبلی همچنان قابل بازیابی می‌مانند."""
    engine = FileEngine(vault["db"], vault["kh"], backup_provider=_AlwaysSucceedBackup())
    f = make_file(os.path.join(vault["work"], "a.txt"), "recoverable data")
    lock_res = engine.lock_paths([f], LockOptions(backup_requested=False, protect_names=False))
    file_id = lock_res.results[0].file_id

    prm = PasswordRecoveryManager(vault["db"], KeyHierarchy())
    assert prm.attempt_recovery(vault["security_answer"], vault["usb_info"].usb_secret) is True
    prm.complete_recovery_with_new_password("RecoveredPass9!", vault["usb_info"].usb_secret)

    new_key_store = vault["db"].load_key_store()
    kh_new = KeyHierarchy()
    kh_new.unlock("RecoveredPass9!", vault["usb_info"].usb_secret, new_key_store)
    engine2 = FileEngine(vault["db"], kh_new, backup_provider=_AlwaysSucceedBackup())
    unlock_res = engine2.unlock_files([file_id])
    assert unlock_res.success_count == 1


# ============================================================================= 11: Corrupted encrypted file
def test_11_corrupted_encrypted_file(engine_with_backup):
    """انتظار: فایل رمزگذاری‌شده‌ی دستکاری‌شده هرگز رمزگشایی نمی‌شود؛ Unlock با خطا
    گزارش می‌شود و فایل خراب دست‌نخورده باقی می‌ماند."""
    v = engine_with_backup
    f = make_file(os.path.join(v["work"], "doc.txt"), "important")
    lock_res = v["engine"].lock_paths([f], LockOptions(backup_requested=True, protect_names=False))
    file_id = lock_res.results[0].file_id
    locked_path = lock_res.results[0].final_path

    with open(locked_path, "r+b") as fh:
        fh.seek(60)
        b = fh.read(1)
        fh.seek(60)
        fh.write(bytes([b[0] ^ 0xFF]) if b else b"\xff")

    unlock_res = v["engine"].unlock_files([file_id])
    assert unlock_res.success_count == 0
    assert v["db"].get_locked_file(file_id).status == "CORRUPTED"
    assert os.path.exists(locked_path)  # فایل خراب دست‌نخورده مانده، نه حذف/جایگزین‌شده

    backup_id = v["backup_manager"].find_valid_backup_for_file(file_id)
    assert backup_id is not None
    ok = v["engine"].restore_corrupted_from_backup(file_id, backup_id, f)
    assert ok
    with open(f) as fh:
        assert fh.read() == "important"


# ============================================================================= 12: Corrupted backup
def test_12_corrupted_backup_detected(engine_with_backup):
    """انتظار: دستکاری فایل Backup روی USB باید توسط verify_backup تشخیص داده شود."""
    v = engine_with_backup
    f = make_file(os.path.join(v["work"], "doc.txt"), "data")
    lock_res = v["engine"].lock_paths([f], LockOptions(backup_requested=True, protect_names=False))
    backup_id = lock_res.backup_id

    entries = v["backup_manager"].get_backup_file_list(backup_id)
    entry_id = entries[0]["entry_id"]
    backup_root = v["backup_manager"]._require_usb().backup_root()
    entry_path = os.path.join(backup_root, "backups", backup_id, "files", entry_id)
    with open(entry_path, "r+b") as fh:
        fh.seek(15)
        b = fh.read(1)
        fh.seek(15)
        fh.write(bytes([b[0] ^ 0xFF]) if b else b"\xff")

    ok, detail = v["backup_manager"].verify_backup(backup_id)
    assert ok is False
    assert v["db"].get_backup(backup_id).status == "CORRUPTED"


# ============================================================================= 13-14: Duplicate filename/destination
def test_13_duplicate_filename_conflict_on_lock(vault):
    """انتظار: اگر مقصد rename (نام obfuscate‌شده) از قبل وجود داشته باشد، فایل به‌جای
    overwrite کورکورانه، به‌عنوان failed گزارش می‌شود."""
    engine = FileEngine(vault["db"], vault["kh"], backup_provider=_AlwaysSucceedBackup())
    f = make_file(os.path.join(vault["work"], "dup.txt"), "content")
    # از قبل یک فایل با پسوند .slock دقیقاً با همون اسم می‌سازیم تا conflict شبیه‌سازی بشه
    make_file(f + ".slock", "pre-existing unrelated content")
    result = engine.lock_paths([f], LockOptions(backup_requested=False, protect_names=False))
    assert result.failed_count == 1
    with open(f + ".slock") as fh:
        assert fh.read() == "pre-existing unrelated content"  # دست‌نخورده مانده


def test_14_duplicate_destination_on_unlock(vault):
    """انتظار: اگر مقصد Unlock از قبل وجود داشته باشد، هرگز خودکار overwrite نمی‌شود؛
    conflict_resolver تصمیم می‌گیرد (اینجا SKIP پیش‌فرض بدون resolver)."""
    engine = FileEngine(vault["db"], vault["kh"], backup_provider=_AlwaysSucceedBackup())
    f = make_file(os.path.join(vault["work"], "x.txt"), "original")
    lock_res = engine.lock_paths([f], LockOptions(backup_requested=False, protect_names=False))
    file_id = lock_res.results[0].file_id

    make_file(f, "new content created after locking")  # تعارض
    unlock_res = engine.unlock_files([file_id])  # بدون conflict_resolver -> پیش‌فرض SKIP
    assert unlock_res.success_count == 0
    with open(f) as fh:
        assert fh.read() == "new content created after locking"  # دست‌نخورده مانده


# ============================================================================= 15: Crash simulation
def test_15_crash_simulation_leaves_original_intact(vault):
    """انتظار: اگر برنامه وسط Lock 'کرش' کند (شبیه‌سازی: فایل موقت یتیم + تراکنش
    نیمه‌کاره)، اجرای بعدی باید temp را پاک کند و اصلی را دست‌نخورده نگه دارد."""
    f = make_file(os.path.join(vault["work"], "crashed.txt"), "data being locked during crash")
    txm = TransactionManager(vault["db"])
    tx = txm.start("LOCK", {"files": [f]})
    txm.advance(tx, TxState.ENCRYPTING)
    fake_temp = os.path.join(vault["work"], f".fakeid{TEMP_SUFFIX}")
    make_file(fake_temp, "partial garbage")

    crm = CrashRecoveryManager(vault["db"], vault["kh"])
    report = crm.run_startup_scan()
    assert report.unfinished_transactions == 1
    assert not os.path.exists(fake_temp)
    assert os.path.exists(f)
    with open(f) as fh:
        assert fh.read() == "data being locked during crash"


# ============================================================================= 16: Disk full simulation
def test_16_disk_full_simulation_leaves_original_intact(vault, monkeypatch):
    """انتظار: اگر حین نوشتن temp فایل خطای فضای دیسک رخ دهد، فایل اصلی دست‌نخورده
    باقی بماند و temp حذف شود (نه نیمه‌نوشته رها شود)."""
    engine = FileEngine(vault["db"], vault["kh"], backup_provider=_AlwaysSucceedBackup())
    f = make_file(os.path.join(vault["work"], "diskfull.txt"), "must survive disk full")

    import core.crypto as crypto_module
    original_encrypt = crypto_module.ChunkedAEADCipher.encrypt_stream

    def failing_encrypt(self, *args, **kwargs):
        raise OSError(28, "No space left on device")  # ENOSPC

    monkeypatch.setattr(crypto_module.ChunkedAEADCipher, "encrypt_stream", failing_encrypt)
    result = engine.lock_paths([f], LockOptions(backup_requested=False, protect_names=False))
    monkeypatch.setattr(crypto_module.ChunkedAEADCipher, "encrypt_stream", original_encrypt)

    assert result.failed_count == 1
    assert os.path.exists(f)
    with open(f) as fh:
        assert fh.read() == "must survive disk full"
    leftover_temps = [p for p in os.listdir(vault["work"]) if p.endswith(TEMP_SUFFIX)]
    assert leftover_temps == []


# ============================================================================= 17: USB removal
def test_17_usb_removal_during_backup_stops_safely(vault):
    """انتظار: اگر USB حین نیاز به Backup در دسترس نباشد، عملیات جدید (Lock) شروع
    نمی‌شود و فایل اصلی دست‌نخورده می‌ماند (مشابه سناریوی backup failure)."""
    class _NoUsbBackup:
        def create_backup(self, file_paths, group_id):
            return BackupResult(success=False, verified=False, backup_id=None, error="USB removed")
        def find_valid_backup_for_file(self, file_id):
            return None
        def restore_file_from_backup(self, *a):
            return False

    engine = FileEngine(vault["db"], vault["kh"], backup_provider=_NoUsbBackup())
    f = make_file(os.path.join(vault["work"], "protected.txt"), "safe content")
    result = engine.lock_paths([f], LockOptions(backup_requested=True, protect_names=False))
    assert result.aborted is True
    assert os.path.exists(f)


# ============================================================================= 18: Multiple files
def test_18_multiple_files(vault):
    """انتظار: چند فایل هم‌زمان قفل/باز می‌شوند و هرکدام محتوای مستقل و صحیح خود را دارند."""
    engine = FileEngine(vault["db"], vault["kh"], backup_provider=_AlwaysSucceedBackup())
    files = []
    for i in range(5):
        f = make_file(os.path.join(vault["work"], f"multi_{i}.txt"), f"content-{i}")
        files.append(f)
    result = engine.lock_paths(files, LockOptions(backup_requested=False, protect_names=False))
    assert result.success_count == 5
    file_ids = [r.file_id for r in result.results]
    unlock_res = engine.unlock_files(file_ids)
    assert unlock_res.success_count == 5
    for i, f in enumerate(files):
        with open(f) as fh:
            assert fh.read() == f"content-{i}"


# ============================================================================= 19: Nested folders
def test_19_nested_folders(vault):
    """انتظار: فایل‌های داخل چند سطح پوشه‌ی تودرتو به‌درستی قفل/باز می‌شوند و
    (با protect_structure) ساختار قابل بازگردانی کامل است."""
    engine = FileEngine(vault["db"], vault["kh"], backup_provider=_AlwaysSucceedBackup())
    root = os.path.join(vault["work"], "proj")
    deep = os.path.join(root, "a", "b", "c")
    os.makedirs(deep)
    f = make_file(os.path.join(deep, "deep.txt"), "deep content")
    result = engine.lock_paths([root], LockOptions(backup_requested=False, protect_names=True, protect_structure=True))
    assert result.success_count == 1
    assert not os.path.isdir(os.path.join(root, "a"))  # نام پوشه obfuscate شده

    file_id = result.results[0].file_id
    unlock_res = engine.unlock_files([file_id])
    assert unlock_res.success_count == 1
    assert os.path.exists(f)
    with open(f) as fh:
        assert fh.read() == "deep content"


# ============================================================================= 20-21: Unicode / Persian filenames
def test_20_unicode_filenames(vault):
    """انتظار: نام فایل با کاراکترهای یونیکد (مثلاً امضای چینی/عربی) به‌درستی حفظ می‌شود."""
    engine = FileEngine(vault["db"], vault["kh"], backup_provider=_AlwaysSucceedBackup())
    f = make_file(os.path.join(vault["work"], "文件_ملف_αρχείο.txt"), "unicode name test")
    result = engine.lock_paths([f], LockOptions(backup_requested=False, protect_names=True))
    assert result.success_count == 1
    unlock_res = engine.unlock_files([result.results[0].file_id])
    assert unlock_res.success_count == 1
    assert unlock_res.results[0].restored_path == f
    assert os.path.exists(f)


def test_21_persian_filenames_and_content(vault):
    """انتظار: نام و محتوای فارسی هر دو دقیقاً حفظ می‌شوند."""
    engine = FileEngine(vault["db"], vault["kh"], backup_provider=_AlwaysSucceedBackup())
    f = make_file(os.path.join(vault["work"], "سند محرمانه.docx"), "این یک متن کاملاً فارسی است")
    result = engine.lock_paths([f], LockOptions(backup_requested=False, protect_names=True))
    assert result.success_count == 1
    unlock_res = engine.unlock_files([result.results[0].file_id])
    assert unlock_res.success_count == 1
    with open(f, encoding="utf-8") as fh:
        assert fh.read() == "این یک متن کاملاً فارسی است"


# ============================================================================= 22: Spaces in paths
def test_22_spaces_in_paths(vault):
    """انتظار: مسیرهای دارای فاصله (رایج در ویندوز) بدون مشکل پردازش می‌شوند."""
    engine = FileEngine(vault["db"], vault["kh"], backup_provider=_AlwaysSucceedBackup())
    dir_with_space = os.path.join(vault["work"], "My Documents Folder")
    os.makedirs(dir_with_space)
    f = make_file(os.path.join(dir_with_space, "my file name.txt"), "spaced path content")
    result = engine.lock_paths([f], LockOptions(backup_requested=False, protect_names=False))
    assert result.success_count == 1
    unlock_res = engine.unlock_files([result.results[0].file_id])
    assert unlock_res.success_count == 1
    with open(f) as fh:
        assert fh.read() == "spaced path content"


# ============================================================================= 23: Very long paths
def test_23_very_long_path(vault):
    """انتظار: نام فایل نسبتاً طولانی (نزدیک محدودیت‌های معمول) باید مدیریت شود؛
    نام‌های obfuscate شده عمداً به ۸۰ کاراکتر محدود می‌شوند تا از مشکلات طول مسیر جلوگیری شود."""
    engine = FileEngine(vault["db"], vault["kh"], backup_provider=_AlwaysSucceedBackup())
    long_name = "a" * 100 + ".txt"
    f = make_file(os.path.join(vault["work"], long_name), "long name content")
    result = engine.lock_paths([f], LockOptions(backup_requested=False, protect_names=True))
    assert result.success_count == 1
    locked_name = os.path.basename(result.results[0].final_path)
    assert len(locked_name) <= 90  # obfuscated + .slock، کوتاه‌تر از نام اصلی افراطی
    unlock_res = engine.unlock_files([result.results[0].file_id])
    assert unlock_res.success_count == 1


# ============================================================================= 24: Symlink/junction
def test_24_symlink_skipped(vault):
    """انتظار: Symlink دنبال (follow) نمی‌شود و به‌عنوان skipped گزارش می‌شود، نه قفل‌شده."""
    engine = FileEngine(vault["db"], vault["kh"], backup_provider=_AlwaysSucceedBackup())
    target = make_file(os.path.join(vault["work"], "target.txt"), "target data")
    link = os.path.join(vault["work"], "link.txt")
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlink not supported in this environment")
    result = engine.lock_paths([link], LockOptions(backup_requested=False, protect_names=False))
    assert os.path.abspath(link) in [os.path.abspath(p) for p in result.skipped_reparse_points]
    assert os.path.exists(target)  # فایل هدف دست‌نخورده


# ============================================================================= 25: Empty folder
def test_25_empty_folder(vault):
    """انتظار: قفل کردن یک پوشه‌ی خالی نباید خطا بدهد؛ صرفاً هیچ فایلی برای قفل کردن نیست."""
    engine = FileEngine(vault["db"], vault["kh"], backup_provider=_AlwaysSucceedBackup())
    empty_dir = os.path.join(vault["work"], "empty_folder")
    os.makedirs(empty_dir)
    result = engine.lock_paths([empty_dir], LockOptions(backup_requested=False, protect_names=False))
    assert result.success_count == 0
    assert result.failed_count == 0
    assert result.aborted is False


# ============================================================================= 26: Large folder
def test_26_large_folder_many_files(vault):
    """انتظار: پوشه‌ای با تعداد زیاد فایل کوچک باید همه را به‌درستی قفل/باز کند."""
    engine = FileEngine(vault["db"], vault["kh"], backup_provider=_AlwaysSucceedBackup())
    folder = os.path.join(vault["work"], "many_files")
    os.makedirs(folder)
    for i in range(40):
        make_file(os.path.join(folder, f"f{i}.txt"), f"data-{i}")
    result = engine.lock_paths([folder], LockOptions(backup_requested=False, protect_names=False))
    assert result.success_count == 40
    file_ids = [r.file_id for r in result.results]
    unlock_res = engine.unlock_files(file_ids)
    assert unlock_res.success_count == 40


# ============================================================================= 27: Existing locked file
def test_27_relocking_already_locked_file_is_skipped(vault):
    """انتظار: تلاش برای قفل کردن مجدد چیزی که از قبل قفل است، نباید دوباره پردازش شود."""
    engine = FileEngine(vault["db"], vault["kh"], backup_provider=_AlwaysSucceedBackup())
    folder = os.path.join(vault["work"], "relockfolder")
    os.makedirs(folder)
    f = make_file(os.path.join(folder, "a.txt"), "content")
    r1 = engine.lock_paths([folder], LockOptions(backup_requested=False, protect_names=False))
    assert r1.success_count == 1

    new_file = make_file(os.path.join(folder, "b.txt"), "new content")
    r2 = engine.lock_paths([folder], LockOptions(backup_requested=False, protect_names=False))
    assert r2.success_count == 1  # فقط b.txt جدید
    assert r2.skipped_count == 1  # a.slock از قبل قفل بوده


# ============================================================================= 28: Partial operation recovery
def test_28_partial_lock_batch_reports_success_and_failure_separately(vault):
    """انتظار: اگر در یک عملیات دسته‌ای (چند فایل)، یکی به هر دلیل شکست بخورد، بقیه
    باید موفق پردازش شوند و گزارش دقیقاً success/failed را جدا نشان دهد."""
    engine = FileEngine(vault["db"], vault["kh"], backup_provider=_AlwaysSucceedBackup())
    good1 = make_file(os.path.join(vault["work"], "good1.txt"), "ok1")
    good2 = make_file(os.path.join(vault["work"], "good2.txt"), "ok2")
    bad = os.path.join(vault["work"], "bad_target.txt")
    make_file(bad, "will conflict")
    make_file(bad + ".slock", "pre-existing blocker")  # باعث شکست قفل شدن bad می‌شود

    result = engine.lock_paths([good1, good2, bad], LockOptions(backup_requested=False, protect_names=False))
    assert result.success_count == 2
    assert result.failed_count == 1
    failed_paths = {r.original_path for r in result.results if not r.success and not r.skipped}
    assert os.path.abspath(bad) in failed_paths
    # فایل‌های موفق واقعاً قفل شده باشند
    assert not os.path.exists(good1)
    assert not os.path.exists(good2)
    # فایل ناموفق دست‌نخورده مانده باشد
    assert os.path.exists(bad)
