"""
core/key_manager.py

سلسله‌مراتب کلید (Key Hierarchy) Secure Locker.

    Password + salt_p  --Argon2id-->                KEK_password (32B)
    USB_secret + salt_u --HKDF-SHA256-->             KEK_usb (32B)
    KEK_password || KEK_usb  --HKDF-Extract/Expand--> KEK_combined (32B)
    Master Key (تصادفی، تولید یک‌بار)  --AES-256-GCM wrap با KEK_combined-->  wrapped_MK (ذخیره در DB)

    Master Key --HKDF(info=file_id, "file-key")-->  File Key   (per-file, مشتق نه ذخیره‌شده)
    Master Key --HKDF(info=file_id, "hmac-key")-->  File HMAC Key
    Master Key --HKDF(info="name-map", ...)-->      Name/Path Encryption Key
    Master Key --HKDF(info="backup", ...)-->        Backup Encryption Key

چرا این معماری:
    - تغییر Password فقط یعنی: unwrap با KEK_combined قدیم -> wrap با KEK_combined جدید.
      Master Key هرگز عوض نمی‌شود، بنابراین هیچ فایلی نیاز به re-encrypt ندارد.
    - چون unwrap یک عملیات AEAD است، اگر Password یا USB Secret اشتباه باشد،
      GCM authentication شکست می‌خورد (نه این‌که یک Master Key نادرست اما "معتبر به نظر"
      تولید شود). یعنی غلط بودن هرکدام از دو فاکتور بلافاصله و قطعی تشخیص داده می‌شود.
    - چون هر دو KEK با HKDF ترکیب می‌شوند، نبود هرکدام (فقط Password یا فقط USB)
      کافی برای unwrap نیست: دو-عاملی واقعی (True 2FA)، نه فقط "دو تا رمز جدا".
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

from argon2.low_level import hash_secret_raw, Type as Argon2Type
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from cryptography.hazmat.primitives import hashes

from core.crypto import encrypt_blob, decrypt_blob, IntegrityError, CryptoError, KEY_SIZE

# --------------------------------------------------------------------------- Argon2 params
# پارامترهای Argon2id: تعادل بین امنیت و زمان قابل‌قبول روی لپ‌تاپ معمولی (~0.5-1.5s).
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST_KIB = 256 * 1024  # 256 MB
ARGON2_PARALLELISM = 2
ARGON2_HASH_LEN = 32
ARGON2_SALT_LEN = 16


class KeyManagerError(Exception):
    """خطای عمومی مدیریت کلید."""


class AuthenticationFailedError(KeyManagerError):
    """Password و/یا USB Secret نادرست است (unwrap شکست خورد)."""


def _argon2id(secret: bytes, salt: bytes, hash_len: int = ARGON2_HASH_LEN) -> bytes:
    """Argon2id KDF - برای Password و Security Answer استفاده می‌شود."""
    return hash_secret_raw(
        secret=secret,
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST_KIB,
        parallelism=ARGON2_PARALLELISM,
        hash_len=hash_len,
        type=Argon2Type.ID,
    )


def _hkdf(ikm: bytes, salt: Optional[bytes], info: bytes, length: int = 32) -> bytes:
    """HKDF-SHA256 استاندارد برای مشتق‌سازی subkeyها از Master Key یا ترکیب KEKها."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(ikm)


def new_random_salt(n: int = 16) -> bytes:
    return os.urandom(n)


def new_master_key() -> bytes:
    """تولید یک Master Key تصادفی 256-bit. فقط یک‌بار در Setup اول فراخوانی می‌شود."""
    return os.urandom(KEY_SIZE)


@dataclass
class PasswordRecord:
    """
    خروجی هش Password برای ذخیره در DB. hash خودش هرگز به‌تنهایی برای auth کافی نیست
    (چون در معماری ما، auth واقعی از طریق unwrap موفق Master Key اثبات می‌شود)،
    اما به‌عنوان یک لایه‌ی سریع‌تر برای رد کردن Passwordهای بدیهی اشتباه و برای
    شمارش تلاش‌های ناموفق (قبل از درگیر کردن USB) نگه داشته می‌شود.
    """
    salt: bytes
    verifier: bytes  # Argon2id(password, salt) - فقط برای verification سریع، نه مشتق‌سازی کلید نهایی


def normalize_answer(answer: str) -> str:
    """نرمال‌سازی Security Answer (کاهش خطای کاربر ناشی از فاصله/حروف بزرگ‌کوچک)."""
    return answer.strip().lower()


def derive_kek_from_secret(secret: str, salt: bytes) -> bytes:
    """Argon2id عمومی برای هر «چیزی که کاربر می‌داند» (Password یا Security Answer)."""
    return _argon2id(secret.encode("utf-8"), salt, hash_len=32)


def compute_password_verifier(password: str, salt: bytes) -> bytes:
    """هش verification سریع Password (جدا از KEK_password که subkey متفاوتی است)."""
    return _argon2id(password.encode("utf-8"), salt, hash_len=32)


def compute_security_answer_hash(answer: str, salt: bytes) -> bytes:
    """هش Security Answer با Argon2id (نرمال‌سازی: lower + strip برای کاهش خطای کاربر)."""
    normalized = answer.strip().lower().encode("utf-8")
    return _argon2id(normalized, salt, hash_len=32)


def derive_kek_password(password: str, salt_p: bytes) -> bytes:
    """KEK_password = Argon2id(password, salt_p) - subkey مجزا از verifier (info متفاوت via salt جدا)."""
    return derive_kek_from_secret(password, salt_p)


def derive_kek_usb(usb_secret: bytes, salt_u: bytes) -> bytes:
    """KEK_usb = HKDF-SHA256(usb_secret, salt_u)."""
    return _hkdf(usb_secret, salt_u, info=b"SecureLocker-USB-KEK", length=32)


def combine_keks(kek_password: bytes, kek_usb: bytes, combine_salt: bytes) -> bytes:
    """
    ترکیب دو KEK به یک KEK نهایی با HKDF (هر دو به عنوان input key material).
    ترتیب concatenation ثابت است: password || usb.
    """
    ikm = kek_password + kek_usb
    return _hkdf(ikm, combine_salt, info=b"SecureLocker-Combined-KEK", length=32)


def wrap_master_key(master_key: bytes, kek_combined: bytes) -> bytes:
    """رمزگذاری (wrap) Master Key با KEK_combined. خروجی قابل ذخیره در DB."""
    return encrypt_blob(kek_combined, master_key, aad=b"SecureLocker-MK-Wrap-v1")


def unwrap_master_key(wrapped_mk: bytes, kek_combined: bytes) -> bytes:
    """
    رمزگشایی (unwrap) Master Key. اگر Password یا USB Secret نادرست باشد،
    GCM authentication شکست می‌خورد و AuthenticationFailedError پرتاب می‌شود.
    """
    try:
        return decrypt_blob(kek_combined, wrapped_mk, aad=b"SecureLocker-MK-Wrap-v1")
    except IntegrityError as e:
        raise AuthenticationFailedError(
            "احراز هویت شکست خورد: Password یا USB Secret نادرست است"
        ) from e


class KeyHierarchy:
    """
    کلاس سطح‌بالا برای مدیریت کامل Key Hierarchy در طول اجرای برنامه.
    Master Key فقط در RAM و فقط برای مدت لازم نگه داشته می‌شود.
    """

    def __init__(self) -> None:
        self._master_key: Optional[bytearray] = None

    @classmethod
    def from_master_key(cls, master_key: bytes) -> "KeyHierarchy":
        """
        ساخت یک KeyHierarchy با Master Key از قبل مشخص - فقط برای جریان Setup اولیه
        استفاده می‌شود (بلافاصله بعد از setup_new، پیش از این‌که هنوز key_store کامل
        در DB ذخیره شده باشد، برای ساخت فیلدهای Recovery لازم است).
        """
        kh = cls()
        kh._master_key = bytearray(master_key)
        return kh

    # ----------------------------------------------------------- Setup اولیه
    @staticmethod
    def setup_new(
        password: str, usb_secret: bytes
    ) -> tuple[bytes, dict]:
        """
        راه‌اندازی اولیه: Master Key جدید تولید و wrap می‌شود.
        خروجی: (master_key, key_store_dict) که key_store_dict باید در DB ذخیره شود.
        """
        salt_p = new_random_salt()
        salt_u = new_random_salt()
        combine_salt = new_random_salt()
        verifier_salt = new_random_salt()

        master_key = new_master_key()
        kek_p = derive_kek_password(password, salt_p)
        kek_u = derive_kek_usb(usb_secret, salt_u)
        kek_combined = combine_keks(kek_p, kek_u, combine_salt)
        wrapped_mk = wrap_master_key(master_key, kek_combined)
        verifier = compute_password_verifier(password, verifier_salt)

        key_store = {
            "salt_p": salt_p,
            "salt_u": salt_u,
            "combine_salt": combine_salt,
            "verifier_salt": verifier_salt,
            "verifier": verifier,
            "wrapped_mk": wrapped_mk,
        }
        return master_key, key_store

    # ----------------------------------------------------------- Unlock عادی
    def unlock(self, password: str, usb_secret: bytes, key_store: dict) -> None:
        """
        بازکردن Master Key در RAM با Password + USB Secret.
        در صورت شکست، AuthenticationFailedError پرتاب می‌شود و هیچ کلیدی set نمی‌شود.
        """
        kek_p = derive_kek_password(password, key_store["salt_p"])
        kek_u = derive_kek_usb(usb_secret, key_store["salt_u"])
        kek_combined = combine_keks(kek_p, kek_u, key_store["combine_salt"])
        master_key = unwrap_master_key(key_store["wrapped_mk"], kek_combined)
        self._master_key = bytearray(master_key)

    def verify_password_only(self, password: str, key_store: dict) -> bool:
        """
        بررسی سریع Password (بدون نیاز به USB) - فقط برای UX (مثلاً قبل از پرسیدن
        USB بگوییم Password درست است یا نه) و شمارش تلاش ناموفق. این به‌تنهایی
        هرگز جایگزین unlock() واقعی (که USB را هم لازم دارد) نمی‌شود.
        """
        expected = key_store["verifier"]
        actual = compute_password_verifier(password, key_store["verifier_salt"])
        # مقایسه‌ی constant-time
        return len(expected) == len(actual) and _constant_time_eq(expected, actual)

    def is_unlocked(self) -> bool:
        return self._master_key is not None

    def lock(self) -> None:
        """پاک‌کردن Master Key از RAM (best-effort) - برای Auto Logout."""
        if self._master_key is not None:
            from core.crypto import secure_zero
            secure_zero(self._master_key)
            self._master_key = None

    def unlock_via_recovery(self, master_key: bytes) -> None:
        """
        تنظیم مستقیم Master Key بعد از یک بازیابی موفق (core/recovery.py).
        فقط باید بعد از unwrap موفق KEK_recovery فراخوانی شود - این متد خودش هیچ
        احراز هویتی انجام نمی‌دهد، فقط کلید از قبل تایید‌شده را در RAM قرار می‌دهد.
        """
        self._master_key = bytearray(master_key)

    def get_master_key_bytes(self) -> bytes:
        if self._master_key is None:
            raise KeyManagerError("Master Key در دسترس نیست - ابتدا unlock کنید")
        return bytes(self._master_key)

    # ----------------------------------------------------------- Password change
    def change_password(
        self,
        old_password: str,
        new_password: str,
        usb_secret: bytes,
        key_store: dict,
    ) -> dict:
        """
        تغییر Password بدون تغییر Master Key.
        نیازمند Password فعلی + USB معتبر برای unwrap موفق قبل از rewrap.
        خروجی: key_store جدید (باید جایگزین قبلی در DB شود).
        """
        kek_p_old = derive_kek_password(old_password, key_store["salt_p"])
        kek_u = derive_kek_usb(usb_secret, key_store["salt_u"])
        kek_combined_old = combine_keks(kek_p_old, kek_u, key_store["combine_salt"])
        master_key = unwrap_master_key(key_store["wrapped_mk"], kek_combined_old)
        self._master_key = bytearray(master_key)

        return self.set_new_password(new_password, usb_secret, key_store)

    # ----------------------------------------------------------- Subkey derivation
    def derive_file_key(self, file_id: str) -> bytes:
        mk = self.get_master_key_bytes()
        return _hkdf(mk, None, info=f"SecureLocker-FileKey-{file_id}".encode(), length=32)

    def derive_file_hmac_key(self, file_id: str) -> bytes:
        mk = self.get_master_key_bytes()
        return _hkdf(mk, None, info=f"SecureLocker-FileHMAC-{file_id}".encode(), length=32)

    def derive_name_map_key(self) -> bytes:
        """کلید مشترک برای رمزگذاری نام فایل‌ها/مسیرها (mapping) - نه محتوای فایل."""
        mk = self.get_master_key_bytes()
        return _hkdf(mk, None, info=b"SecureLocker-NameMapKey", length=32)

    def derive_backup_key(self) -> bytes:
        """کلید رمزگذاری بکاپ‌های داخل USB (وقتی گزینه‌ی Encrypt Backup فعال باشد)."""
        mk = self.get_master_key_bytes()
        return _hkdf(mk, None, info=b"SecureLocker-BackupKey", length=32)

    def derive_metadata_key(self) -> bytes:
        """کلید رمزگذاری فیلدهای حساس دیتابیس (مسیر اصلی فایل و ...)."""
        mk = self.get_master_key_bytes()
        return _hkdf(mk, None, info=b"SecureLocker-MetadataKey", length=32)


    # ----------------------------------------------------------- Recovery (Security Question path)
    def build_recovery_fields(self, usb_secret: bytes, security_answer: str, key_store: dict) -> dict:
        """
        ساخت فیلدهای Recovery: یک wrap دوم و کاملاً مستقل از Master Key، این‌بار با
        ترکیب (Security Answer + USB) به‌جای (Password + USB).
        نیازمند این است که Master Key از قبل در RAM باز باشد (یا بلافاصله بعد از
        setup_new، یا بعد از یک unlock عادی موفق - مثلاً وقتی کاربر از Settings
        می‌خواهد Security Question را عوض کند).
        این عملیات wrapped_mk اصلی (Password-based) را دست نمی‌زند.
        """
        mk = self.get_master_key_bytes()
        salt_answer_kek = new_random_salt()
        combine_salt_r = new_random_salt()
        kek_a = derive_kek_from_secret(normalize_answer(security_answer), salt_answer_kek)
        kek_u = derive_kek_usb(usb_secret, key_store["salt_u"])
        kek_combined_r = combine_keks(kek_a, kek_u, combine_salt_r)
        wrapped_mk_recovery = wrap_master_key(mk, kek_combined_r)
        return {
            "salt_answer_kek": salt_answer_kek,
            "combine_salt_r": combine_salt_r,
            "wrapped_mk_recovery": wrapped_mk_recovery,
        }

    def unlock_via_recovery(self, security_answer: str, usb_secret: bytes, key_store: dict) -> None:
        """
        باز کردن Master Key از مسیر Recovery (بدون نیاز به دانستن Password فعلی).
        نیازمند USB معتبر + پاسخ صحیح Security Question است (هر دو، طبق همان اصل
        دو-عاملی؛ تنها داشتن پاسخ سوال امنیتی بدون USB کافی نیست).
        در صورت شکست، AuthenticationFailedError پرتاب می‌شود.
        """
        if "wrapped_mk_recovery" not in key_store:
            raise KeyManagerError("این حساب هنوز Recovery راه‌اندازی نشده است")
        kek_a = derive_kek_from_secret(normalize_answer(security_answer), key_store["salt_answer_kek"])
        kek_u = derive_kek_usb(usb_secret, key_store["salt_u"])
        kek_combined_r = combine_keks(kek_a, kek_u, key_store["combine_salt_r"])
        master_key = unwrap_master_key(key_store["wrapped_mk_recovery"], kek_combined_r)
        self._master_key = bytearray(master_key)

    def set_new_password(self, new_password: str, usb_secret: bytes, key_store: dict) -> dict:
        """
        تنظیم یک Password جدید وقتی Master Key از قبل در RAM باز است (چه از طریق
        unlock عادی، چه از طریق unlock_via_recovery). فقط wrapped_mk (مسیر Password)
        بازنویسی می‌شود؛ wrapped_mk_recovery (مسیر Security Question) دست‌نخورده
        می‌ماند چون به MK وابسته است نه به Password قدیم/جدید.
        """
        mk = self.get_master_key_bytes()
        new_salt_p = new_random_salt()
        new_combine_salt = new_random_salt()
        new_verifier_salt = new_random_salt()

        kek_p_new = derive_kek_password(new_password, new_salt_p)
        kek_u = derive_kek_usb(usb_secret, key_store["salt_u"])
        kek_combined_new = combine_keks(kek_p_new, kek_u, new_combine_salt)
        new_wrapped_mk = wrap_master_key(mk, kek_combined_new)
        new_verifier = compute_password_verifier(new_password, new_verifier_salt)

        new_key_store = dict(key_store)
        new_key_store.update({
            "salt_p": new_salt_p,
            "combine_salt": new_combine_salt,
            "verifier_salt": new_verifier_salt,
            "verifier": new_verifier,
            "wrapped_mk": new_wrapped_mk,
        })
        return new_key_store


def _constant_time_eq(a: bytes, b: bytes) -> bool:
    import hmac as _hmac
    return _hmac.compare_digest(a, b)


# ----------------------------------------------------------- Security Question Recovery
def setup_security_question(answer: str) -> dict:
    """در Setup اولیه، برای Security Answer یک رکورد هش‌شده تولید می‌کند."""
    salt = new_random_salt()
    ans_hash = compute_security_answer_hash(answer, salt)
    return {"answer_salt": salt, "answer_hash": ans_hash}


def verify_security_answer(answer: str, record: dict) -> bool:
    expected = record["answer_hash"]
    actual = compute_security_answer_hash(answer, record["answer_salt"])
    return len(expected) == len(actual) and _constant_time_eq(expected, actual)



