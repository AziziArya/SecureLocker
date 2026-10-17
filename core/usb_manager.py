"""
core/usb_manager.py

USB به‌عنوان «کلید فیزیکی» سیستم.

مشکل Drive Letter:
    حرف درایو (مثل E:\\) در ویندوز می‌تواند بین اتصال‌های مختلف تغییر کند (بسته به
    این‌که چه دستگاه‌های دیگری وصل باشند). بنابراین هرگز نباید صرفاً بر اساس
    "درایو E است پس همان USB است" تصمیم گرفت.

راه‌حل این ماژول:
    1. روی USB، یک فایل کلید (`.securelocker/key.bin`) نگه‌داری می‌شود که شامل:
         - یک USB ID تصادفی 16 بایتی (شناسه‌ی یکتای این فلش، نه سریال ویندوزی)
         - یک USB Secret تصادفی 32 بایتی (این‌همان "کلید" واقعی رمزنگاری است)
         - یک HMAC داخلی برای تشخیص خرابی/دستکاری فایل (Self-Integrity، نه محرمانگی)
    2. روی لپ‌تاپ (در دیتابیس)، فقط یک Fingerprint یک‌طرفه ذخیره می‌شود:
         fingerprint = SHA-256(usb_id || usb_secret)
       این fingerprint برای *تشخیص سریع* "این USB درست است یا نه" استفاده می‌شود،
       بدون این‌که به‌تنهایی برای بازسازی usb_secret کافی باشد (چون هش یک‌طرفه است).
    3. برای پیدا کردن USB، همه‌ی درایوهای Removable اسکن می‌شوند و فایل کلید در هرکدام
       بررسی می‌شود - مستقل از این‌که چه حرفی به آن‌ها اختصاص یافته.

چرا usb_secret را روی خود USB رمزگذاری نمی‌کنیم؟
    چون usb_secret خودش یکی از دو عامل احراز هویت است (فاکتور «چیزی که داری»).
    اگر آن را با چیزی که *فقط* روی USB است رمزگذاری کنیم، عملاً دایره‌ای (circular)
    می‌شود و امنیت واقعی اضافه نمی‌کند. امنیت واقعی این‌جا از این می‌آید که:
        - usb_secret به‌تنهایی برای Unlock کافی نیست (Password هم لازم است - key_manager).
        - اگر USB دزدیده شود، مهاجم بدون Password نمی‌تواند هیچ فایلی را باز کند.
    بنابراین طراحی «Secret شفاف روی کلید فیزیکی + نیاز اجباری به فاکتور دوم» دقیقاً
    همان مدلی است که Hardware Security Keys (مثل YubiKey) هم از آن استفاده می‌کنند:
    خود توکن secret را «مخفی» نگه نمی‌دارد به معنای رمزنگاری‌شده بودنش، بلکه سیستم
    طوری طراحی می‌شود که توکن به‌تنهایی کافی نباشد.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

KEY_DIR_NAME = ".securelocker"
KEY_FILE_NAME = "key.bin"
BACKUP_DIR_NAME = "SecureLockerVault"
VAULT_DB_NAME = "vault_metadata.db"
VAULT_CONFIG_NAME = "config.json"

USB_KEY_MAGIC = b"SLUSBK1\x00"
USB_ID_SIZE = 16
USB_SECRET_SIZE = 32
USB_HMAC_SIZE = 32


class UsbManagerError(Exception):
    """خطای عمومی مدیریت USB."""


class UsbKeyCorruptedError(UsbManagerError):
    """فایل کلید روی USB خراب یا دستکاری‌شده است (self-integrity شکست خورد)."""


class NoUsbFoundError(UsbManagerError):
    """هیچ درایو Removable حاوی فایل کلید معتبر پیدا نشد."""


class WrongUsbError(UsbManagerError):
    """USB متصل است اما fingerprint آن با USB ثبت‌شده مطابقت ندارد."""


@dataclass
class UsbKeyInfo:
    """اطلاعات یک USB کلید که روی سیستم پیدا شده است."""
    drive_root: str          # مثلاً "E:\\"
    usb_id: bytes            # 16 بایت شناسه‌ی یکتا
    usb_secret: bytes        # 32 بایت - فاکتور دوم احراز هویت
    key_file_path: str

    def fingerprint(self) -> bytes:
        """SHA-256(usb_id || usb_secret) - برای مقایسه‌ی سریع، یک‌طرفه."""
        return hashlib.sha256(self.usb_id + self.usb_secret).digest()

    def backup_root(self) -> str:
        """مسیر پوشه‌ی Backup روی همین USB."""
        return str(Path(self.drive_root) / BACKUP_DIR_NAME)

    def vault_dir(self) -> str:
        """پوشه‌ی داده‌ی برنامه روی این USB (کنار key.bin) - محل دیتابیس و تنظیمات."""
        return str(Path(self.drive_root) / KEY_DIR_NAME)

    def vault_db_path(self) -> str:
        """مسیر کامل فایل دیتابیس روی این USB (وقتی می‌خواهیم برنامه کاملاً روی
        فلش portable باشد - همراه با EXE، دیتابیس هم همین‌جا نگه‌داری می‌شود)."""
        return str(Path(self.drive_root) / KEY_DIR_NAME / VAULT_DB_NAME)

    def vault_config_path(self) -> str:
        """مسیر فایل تنظیمات (config.json) روی همین USB."""
        return str(Path(self.drive_root) / KEY_DIR_NAME / VAULT_CONFIG_NAME)

    def has_existing_vault_db(self) -> bool:
        """آیا این USB از قبل یک دیتابیس Vault کامل (Setup شده) روی خودش دارد؟"""
        return os.path.isfile(self.vault_db_path())


# --------------------------------------------------------------------------- Drive enumeration
def _list_removable_drives_windows() -> List[str]:
    """لیست درایوهای Removable در ویندوز، مستقل از این‌که کدام حرف به آن‌ها افتاده."""
    import ctypes
    kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    DRIVE_REMOVABLE = 2
    drives = []
    bitmask = kernel32.GetLogicalDrives()
    for i in range(26):
        if bitmask & (1 << i):
            drive = f"{chr(65 + i)}:\\"
            try:
                if kernel32.GetDriveTypeW(drive) == DRIVE_REMOVABLE:
                    drives.append(drive)
            except Exception:
                continue
    return drives


def list_removable_drives(test_override: Optional[List[str]] = None) -> List[str]:
    """
    لیست همه‌ی درایوهای Removable قابل‌بررسی.
    test_override برای تست روی غیر-ویندوز (Linux/Mac) استفاده می‌شود؛ در محیط واقعی
    نادیده گرفته می‌شود و اسکن واقعی ویندوز انجام می‌گیرد.
    """
    if test_override is not None:
        return test_override
    if sys.platform == "win32":
        return _list_removable_drives_windows()
    # محیط غیر-ویندوز (توسعه/تست): از متغیر محیطی برای شبیه‌سازی استفاده می‌شود.
    env = os.environ.get("SECURELOCKER_TEST_USB_PATHS", "")
    return [p for p in env.split(os.pathsep) if p.strip()]


# --------------------------------------------------------------------------- Key file IO
def _pack_key_file(usb_id: bytes, usb_secret: bytes) -> bytes:
    body = USB_KEY_MAGIC + usb_id + usb_secret
    tag = hmac.new(usb_secret, body, hashlib.sha256).digest()
    return body + tag


def _unpack_key_file(data: bytes) -> tuple[bytes, bytes]:
    expected_len = len(USB_KEY_MAGIC) + USB_ID_SIZE + USB_SECRET_SIZE + USB_HMAC_SIZE
    if len(data) != expected_len:
        raise UsbKeyCorruptedError("طول فایل کلید USB نامعتبر است")
    magic = data[: len(USB_KEY_MAGIC)]
    if magic != USB_KEY_MAGIC:
        raise UsbKeyCorruptedError("MAGIC فایل کلید USB مطابقت ندارد")
    offset = len(USB_KEY_MAGIC)
    usb_id = data[offset: offset + USB_ID_SIZE]
    offset += USB_ID_SIZE
    usb_secret = data[offset: offset + USB_SECRET_SIZE]
    offset += USB_SECRET_SIZE
    tag = data[offset: offset + USB_HMAC_SIZE]

    body = data[: len(USB_KEY_MAGIC) + USB_ID_SIZE + USB_SECRET_SIZE]
    expected_tag = hmac.new(usb_secret, body, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected_tag):
        raise UsbKeyCorruptedError(
            "بررسی صحت داخلی فایل کلید USB شکست خورد (فایل خراب یا دستکاری‌شده)"
        )
    return usb_id, usb_secret


def register_new_usb(drive_root: str) -> UsbKeyInfo:
    """
    راه‌اندازی یک فلش جدید به‌عنوان کلید Secure Locker.
    فقط در Setup اولیه یا هنگام افزودن آگاهانه‌ی USB جدید فراخوانی شود -
    این عملیات USB Secret جدید تولید می‌کند (اگر روی فلش قبلاً کلید دیگری بوده،
    این عملاً یک کلید کاملاً متفاوت می‌سازد).
    """
    key_dir = Path(drive_root) / KEY_DIR_NAME
    key_dir.mkdir(parents=True, exist_ok=True)
    key_path = key_dir / KEY_FILE_NAME

    usb_id = os.urandom(USB_ID_SIZE)
    usb_secret = os.urandom(USB_SECRET_SIZE)
    data = _pack_key_file(usb_id, usb_secret)

    # نوشتن atomic حتی برای این فایل کوچک (جلوگیری از نیمه‌نوشته ماندن روی قطع برق حین Setup)
    tmp_path = key_path.with_suffix(".tmp")
    with open(tmp_path, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, key_path)

    # ساخت پوشه‌ی Backup هم از همین ابتدا
    (Path(drive_root) / BACKUP_DIR_NAME).mkdir(parents=True, exist_ok=True)

    return UsbKeyInfo(
        drive_root=drive_root,
        usb_id=usb_id,
        usb_secret=usb_secret,
        key_file_path=str(key_path),
    )


def read_usb_key(drive_root: str) -> Optional[UsbKeyInfo]:
    """
    تلاش برای خواندن فایل کلید از یک درایو مشخص.
    اگر فایل کلید وجود نداشت، None برمی‌گرداند (یعنی این درایو کلید Secure Locker نیست).
    اگر فایل کلید وجود داشت ولی خراب بود، UsbKeyCorruptedError پرتاب می‌شود
    (تا با "اصلا کلید نیست" اشتباه گرفته نشود).
    """
    key_path = Path(drive_root) / KEY_DIR_NAME / KEY_FILE_NAME
    if not key_path.exists():
        return None
    try:
        data = key_path.read_bytes()
    except OSError as e:
        raise UsbManagerError(f"خطا در خواندن فایل کلید USB: {e}") from e

    usb_id, usb_secret = _unpack_key_file(data)  # ممکن است UsbKeyCorruptedError بدهد
    return UsbKeyInfo(
        drive_root=drive_root,
        usb_id=usb_id,
        usb_secret=usb_secret,
        key_file_path=str(key_path),
    )


def scan_all_usb_keys(test_override: Optional[List[str]] = None) -> List[UsbKeyInfo]:
    """اسکن همه‌ی درایوهای Removable و برگرداندن لیست همه‌ی کلیدهای معتبر پیدا‌شده."""
    found: List[UsbKeyInfo] = []
    for drive in list_removable_drives(test_override):
        try:
            info = read_usb_key(drive)
        except UsbKeyCorruptedError:
            # این درایو یک فایل کلید خراب دارد - نادیده گرفته می‌شود ولی گزارش می‌تواند
            # توسط فراخواننده لاگ شود (فراخواننده تصمیم می‌گیرد).
            continue
        if info is not None:
            found.append(info)
    return found


def find_existing_vault_usbs(test_override: Optional[List[str]] = None) -> List[UsbKeyInfo]:
    """
    در میان همه‌ی USBهای دارای فایل کلید، فقط آن‌هایی که یک Vault کامل (شامل
    دیتابیس Setup‌شده) روی خودشان دارند را برمی‌گرداند.

    این تابع برای حالت «برنامه‌ی کاملاً Portable روی فلش» استفاده می‌شود: main.py
    در startup این تابع را صدا می‌زند تا بفهمد آیا یک فلش با Vault آماده وصل است
    (که در آن صورت مستقیم به Login می‌رویم) یا نه (که در آن صورت به Setup Wizard
    می‌رویم و کاربر باید یک فلش را برای راه‌اندازی اولیه انتخاب کند).
    """
    return [info for info in scan_all_usb_keys(test_override) if info.has_existing_vault_db()]


def find_registered_usb(
    expected_fingerprint: bytes,
    test_override: Optional[List[str]] = None,
) -> "UsbDetectionResult":
    """
    تلاش برای پیدا کردن USB *ثبت‌شده* (که fingerprint اش با مقدار ذخیره‌شده در
    دیتابیس لپ‌تاپ مطابقت دارد) در میان همه‌ی درایوهای Removable متصل.

    این تابع تصمیم قطعی امنیتی نمی‌گیرد (آن کار key_manager.unlock است که واقعاً
    Master Key را unwrap می‌کند)؛ فقط برای UX سریع ("USB شما وصل است" / "این USB
    درست نیست") استفاده می‌شود.
    """
    all_found = scan_all_usb_keys(test_override)
    if not all_found:
        return UsbDetectionResult(status="NOT_FOUND", matched=None, others=[])

    matched = None
    others = []
    for info in all_found:
        if hmac.compare_digest(info.fingerprint(), expected_fingerprint):
            matched = info
        else:
            others.append(info)

    if matched is not None:
        return UsbDetectionResult(status="MATCHED", matched=matched, others=others)
    return UsbDetectionResult(status="WRONG_USB", matched=None, others=all_found)


@dataclass
class UsbDetectionResult:
    status: str  # "MATCHED" | "WRONG_USB" | "NOT_FOUND"
    matched: Optional[UsbKeyInfo]
    others: List[UsbKeyInfo]


def is_usb_still_present(info: UsbKeyInfo) -> bool:
    """
    بررسی این‌که آیا USB مشخص‌شده هنوز فیزیکی متصل و قابل‌خواندن است.
    برای بررسی مکرر حین عملیات‌های حساس (Lock/Unlock) استفاده می‌شود تا اگر کاربر
    وسط کار USB را بیرون بکشد، فوراً تشخیص داده شود.
    """
    try:
        current = read_usb_key(info.drive_root)
    except (UsbKeyCorruptedError, UsbManagerError):
        return False
    if current is None:
        return False
    return hmac.compare_digest(current.usb_id, info.usb_id) and hmac.compare_digest(
        current.usb_secret, info.usb_secret
    )
