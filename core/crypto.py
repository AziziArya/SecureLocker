"""
core/crypto.py

هسته‌ی رمزنگاری Secure Locker.

اصول طراحی:
- هرگز کل فایل در RAM خوانده نمی‌شود (Streaming / Chunk-based).
- AES-256-GCM (AEAD) برای هر chunk با nonce یکتا و Authentication Tag مستقل.
- فرمت خروجی نسخه‌دار است (SLF1) تا سازگاری آینده حفظ شود.
- هیچ کلیدی در این فایل هارد‌کد نشده؛ کلید همیشه از بیرون (key_manager) تزریق می‌شود.

فرمت فایل SLF1 (باینری):
    MAGIC(4B "SLF1") | FORMAT_VERSION(1B) | ALG_ID(1B)
    HEADER_LEN(4B uint32 BE) | HEADER_NONCE(12B) | HEADER_CIPHERTEXT(len=HEADER_LEN, شامل tag)
    NONCE_BASE(12B)
    CHUNK_COUNT(4B uint32 BE)
    برای هر chunk:
        CHUNK_NONCE(12B) | CHUNK_LEN(4B uint32 BE) | CHUNK_CIPHERTEXT(len=CHUNK_LEN, شامل tag)
    FOOTER_TAG(32B) = HMAC-SHA256(hmac_key, hash(nonce_base || همه nonceها/طول‌ها))

Nonce uniqueness:
    nonce_base یک‌بار در ابتدای فایل تصادفی تولید می‌شود. nonce هر chunk:
        prefix(4B) = nonce_base[0:4]  (ثابت برای این فایل)
        counter(8B) = (nonce_base[4:12] به عدد) XOR chunk_index
    این تضمین می‌کند nonce در طول یک فایل هرگز تکرار نشود.
    chunk_index هم‌چنین به‌عنوان AAD به GCM داده می‌شود تا حمله‌ی reorder/substitute
    بین chunkهای معتبر (که هرکدام به‌تنهایی authenticate می‌شوند) شناسایی شود.

Footer:
    برای جلوگیری از truncation attack (حذف chunkهای انتهایی توسط مهاجم بدون این‌که
    GCM per-chunk چیزی بفهمد)، یک HMAC روی توالی کامل (nonce_base + همه nonce/len ها)
    محاسبه و در انتهای فایل ذخیره می‌شود. این HMAC با یک subkey مجزا از کلید AES
    محاسبه می‌شود (domain separation) تا استفاده‌ی مجدد از یک کلید برای دو منظور رمزنگاری
    مختلف رخ ندهد.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
import struct
from dataclasses import dataclass, field
from typing import BinaryIO, Callable, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"SLF1"
FORMAT_VERSION = 1
ALG_AES256GCM = 1

NONCE_SIZE = 12
TAG_SIZE = 16
KEY_SIZE = 32  # AES-256

DEFAULT_CHUNK_SIZE = 8 * 1024 * 1024  # 8 MB - تعادل بین overhead و مصرف حافظه


class CryptoError(Exception):
    """خطای عمومی رمزنگاری."""


class IntegrityError(CryptoError):
    """شکست در تایید صحت/اصالت داده (Authentication/Integrity Failure).
    هر جا این خطا رخ دهد، فایل مقصد (temp) باید توسط فراخواننده دور ریخته شود
    و فایل اصلی هرگز نباید touch شود."""


class FormatError(CryptoError):
    """فرمت فایل نامعتبر یا ناسازگار است."""


def secure_zero(buf: bytearray) -> None:
    """
    تلاش best-effort برای صفر کردن حافظه‌ی حساس.
    محدودیت شناخته‌شده: در CPython zero-شدن تضمینی RAM ممکن نیست (GC، immutability
    نوع bytes، کپی‌های داخلی مفسر). این فقط سطح محافظت اضافی است، نه یک garantee.
    فقط روی bytearray عمل می‌کند (نوع mutable)؛ روی bytes معمولی کاری نمی‌کند.
    """
    if not isinstance(buf, bytearray):
        return
    for i in range(len(buf)):
        buf[i] = 0


def _flush_and_fsync(f: BinaryIO) -> None:
    """
    Flush و fsync استریم خروجی برای اطمینان از این‌که داده واقعاً روی دیسک نوشته شده
    (نه فقط در بافر OS) - حیاتی برای Crash Safety قبل از atomic replace.
    روی استریم‌های in-memory (مثل BytesIO در تست‌ها) fileno() موجود نیست؛
    در آن صورت این عملیات به‌آرامی نادیده گرفته می‌شود چون durability فقط برای
    فایل‌های واقعی روی دیسک معنا دارد.
    """
    f.flush()
    try:
        os.fsync(f.fileno())
    except (AttributeError, OSError, io.UnsupportedOperation):
        pass


def _derive_chunk_nonce(nonce_base: bytes, chunk_index: int) -> bytes:
    """ساخت nonce یکتا برای هر chunk بر پایه‌ی nonce_base فایل + شمارنده‌ی chunk."""
    if len(nonce_base) != NONCE_SIZE:
        raise CryptoError("nonce_base باید دقیقا 12 بایت باشد")
    prefix = nonce_base[:4]
    counter_val = int.from_bytes(nonce_base[4:12], "big") ^ chunk_index
    return prefix + counter_val.to_bytes(8, "big")


@dataclass
class FileHeaderMeta:
    """متادیتای داخل هدر رمزگذاری‌شده‌ی هر فایل SLF1 (این خودش AEAD-encrypted است)."""
    file_id: str
    original_size: int
    chunk_size: int
    chunk_count: int
    created_at: str
    algorithm: str = "AES-256-GCM"
    extra: dict = field(default_factory=dict)

    def to_json_bytes(self) -> bytes:
        return json.dumps(self.__dict__, ensure_ascii=False).encode("utf-8")

    @staticmethod
    def from_json_bytes(data: bytes) -> "FileHeaderMeta":
        d = json.loads(data.decode("utf-8"))
        return FileHeaderMeta(**d)


class ChunkedAEADCipher:
    """
    رمزگذاری/رمزگشایی Streaming با AES-256-GCM به‌صورت chunk-based.
    مستقیماً روی فایل‌ها (BinaryIO) کار می‌کند تا هرگز کل فایل به RAM خوانده نشود.

    این کلاس مستقیماً ساخته نمی‌شود؛ از تابع کمکی make_cipher() استفاده کنید تا
    subkey مجزای HMAC هم به‌درستی تزریق شود (domain separation).
    """

    def __init__(self, key: bytes, chunk_size: int = DEFAULT_CHUNK_SIZE):
        if len(key) != KEY_SIZE:
            raise CryptoError("طول کلید باید 32 بایت (256-bit) باشد")
        self._aesgcm = AESGCM(key)
        self.chunk_size = chunk_size
        self._hmac_key: Optional[bytes] = None

    def set_hmac_key(self, hmac_key: bytes) -> None:
        """تزریق subkey مجزا برای HMAC فوتر (باید قبل از encrypt/decrypt فراخوانی شود)."""
        self._hmac_key = hmac_key

    def _require_hmac_key(self) -> bytes:
        if self._hmac_key is None:
            raise CryptoError("hmac_key تنظیم نشده است - از make_cipher() استفاده کنید")
        return self._hmac_key

    # ---------------------------------------------------------------- ENCRYPT
    def encrypt_stream(
        self,
        src: BinaryIO,
        dst: BinaryIO,
        file_id: str,
        original_size: int,
        created_at: str,
        progress_cb: Optional[Callable[[int, int], None]] = None,
    ) -> None:
        """
        رمزگذاری کامل یک استریم ورودی به فرمت SLF1 در استریم خروجی.
        فراخواننده مسئول این است که dst یک فایل موقت باشد و بعد از موفقیت این متد
        (بدون exception)، آن را atomic جایگزین فایل اصلی کند - این متد خودش
        فایل اصلی را دستکاری نمی‌کند.
        """
        hmac_key = self._require_hmac_key()
        nonce_base = os.urandom(NONCE_SIZE)
        chunk_count = (
            (original_size + self.chunk_size - 1) // self.chunk_size
            if original_size > 0 else 0
        )

        header_meta = FileHeaderMeta(
            file_id=file_id,
            original_size=original_size,
            chunk_size=self.chunk_size,
            chunk_count=chunk_count,
            created_at=created_at,
        )
        header_plain = header_meta.to_json_bytes()
        header_nonce = os.urandom(NONCE_SIZE)
        header_ct = self._aesgcm.encrypt(header_nonce, header_plain, b"SLF1-HEADER")

        dst.write(MAGIC)
        dst.write(struct.pack(">B", FORMAT_VERSION))
        dst.write(struct.pack(">B", ALG_AES256GCM))
        dst.write(struct.pack(">I", len(header_ct)))
        dst.write(header_nonce)
        dst.write(header_ct)
        dst.write(nonce_base)
        dst.write(struct.pack(">I", chunk_count))

        footer_hasher = hashlib.sha256()
        footer_hasher.update(nonce_base)

        bytes_done = 0
        chunk_index = 0
        while True:
            chunk = src.read(self.chunk_size)
            if not chunk:
                break
            nonce = _derive_chunk_nonce(nonce_base, chunk_index)
            aad = struct.pack(">I", chunk_index) + file_id.encode("utf-8")
            ct = self._aesgcm.encrypt(nonce, chunk, aad)

            dst.write(nonce)
            dst.write(struct.pack(">I", len(ct)))
            dst.write(ct)

            footer_hasher.update(nonce)
            footer_hasher.update(struct.pack(">I", len(ct)))

            bytes_done += len(chunk)
            chunk_index += 1
            if progress_cb:
                progress_cb(bytes_done, original_size)

        if chunk_index != chunk_count:
            raise CryptoError(
                f"عدم تطابق تعداد chunk واقعی با محاسبه‌شده: انتظار {chunk_count}, واقعی {chunk_index} "
                "(اندازه‌ی فایل ممکن است حین عملیات تغییر کرده باشد)"
            )

        footer_tag = hmac.new(hmac_key, footer_hasher.digest(), hashlib.sha256).digest()
        dst.write(footer_tag)
        _flush_and_fsync(dst)

    # ---------------------------------------------------------------- DECRYPT
    def decrypt_stream(
        self,
        src: BinaryIO,
        dst: BinaryIO,
        expected_file_id: Optional[str] = None,
        progress_cb: Optional[Callable[[int, int], None]] = None,
    ) -> FileHeaderMeta:
        """
        رمزگشایی کامل یک فایل SLF1.
        در صورت هرگونه شکست Integrity/Authentication، IntegrityError پرتاب می‌شود.
        این تابع فایل مقصد نهایی را جایگزین نمی‌کند؛ dst باید یک فایل موقت باشد
        و مسئولیت atomic replace با فراخواننده (file_engine) است. اگر exception رخ دهد
        فراخواننده باید dst (temp) را حذف کند و به فایل اصلی دست نزند.
        """
        hmac_key = self._require_hmac_key()

        magic = src.read(4)
        if magic != MAGIC:
            raise FormatError("فرمت فایل نامعتبر است (MAGIC مطابقت ندارد)")
        version = struct.unpack(">B", src.read(1))[0]
        if version != FORMAT_VERSION:
            raise FormatError(f"نسخه‌ی فرمت پشتیبانی نمی‌شود: {version}")
        alg_id = struct.unpack(">B", src.read(1))[0]
        if alg_id != ALG_AES256GCM:
            raise FormatError(f"شناسه‌ی الگوریتم ناشناخته: {alg_id}")

        header_len = struct.unpack(">I", src.read(4))[0]
        header_nonce = src.read(NONCE_SIZE)
        header_ct = src.read(header_len)
        try:
            header_plain = self._aesgcm.decrypt(header_nonce, header_ct, b"SLF1-HEADER")
        except Exception as e:
            raise IntegrityError(
                "Authentication هدر فایل شکست خورد (کلید نادرست یا فایل خراب/دستکاری‌شده)"
            ) from e
        header_meta = FileHeaderMeta.from_json_bytes(header_plain)

        if expected_file_id and header_meta.file_id != expected_file_id:
            raise IntegrityError("شناسه‌ی فایل با متادیتای دیتابیس مطابقت ندارد")

        nonce_base = src.read(NONCE_SIZE)
        chunk_count = struct.unpack(">I", src.read(4))[0]

        footer_hasher = hashlib.sha256()
        footer_hasher.update(nonce_base)

        bytes_done = 0
        for chunk_index in range(chunk_count):
            nonce = src.read(NONCE_SIZE)
            if len(nonce) != NONCE_SIZE:
                raise IntegrityError("فایل ناقص است (nonce chunk کوتاه‌تر از حد انتظار)")
            ct_len_raw = src.read(4)
            if len(ct_len_raw) != 4:
                raise IntegrityError("فایل ناقص است (طول chunk خوانده نشد)")
            ct_len = struct.unpack(">I", ct_len_raw)[0]
            ct = src.read(ct_len)
            if len(ct) != ct_len:
                raise IntegrityError("فایل ناقص است (ciphertext chunk کوتاه‌تر از حد انتظار)")

            aad = struct.pack(">I", chunk_index) + header_meta.file_id.encode("utf-8")
            try:
                plain = self._aesgcm.decrypt(nonce, ct, aad)
            except Exception as e:
                raise IntegrityError(
                    f"Authentication chunk شماره {chunk_index} شکست خورد "
                    "(فایل خراب یا دستکاری‌شده - فایل اصلی دست‌نخورده باقی می‌ماند)"
                ) from e

            dst.write(plain)
            footer_hasher.update(nonce)
            footer_hasher.update(struct.pack(">I", len(ct)))

            bytes_done += len(plain)
            if progress_cb:
                progress_cb(bytes_done, header_meta.original_size)

        footer_tag_expected = hmac.new(hmac_key, footer_hasher.digest(), hashlib.sha256).digest()
        footer_tag_actual = src.read(32)
        if len(footer_tag_actual) != 32 or not hmac.compare_digest(
            footer_tag_expected, footer_tag_actual
        ):
            raise IntegrityError(
                "بررسی صحت Footer شکست خورد (احتمال truncation یا reorder توسط مهاجم)"
            )

        _flush_and_fsync(dst)
        return header_meta


def make_cipher(file_key: bytes, hmac_key: bytes, chunk_size: int = DEFAULT_CHUNK_SIZE) -> ChunkedAEADCipher:
    """
    سازنده‌ی کمکی: یک ChunkedAEADCipher آماده با کلید AES و subkey HMAC مجزا می‌سازد.
    file_key و hmac_key باید از key_manager (HKDF مشتق‌شده از Master Key) بیایند،
    هرگز مستقیماً از Password یا USB Secret.
    """
    cipher = ChunkedAEADCipher(file_key, chunk_size=chunk_size)
    cipher.set_hmac_key(hmac_key)
    return cipher


# ---------------------------------------------------------------- SMALL BLOB AEAD
def encrypt_blob(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """
    رمزگذاری یک بلاک کوچک (نام فایل، مسیر، متادیتای دیتابیس) با AES-256-GCM.
    خروجی: nonce(12B) || ciphertext_with_tag
    فقط برای دیتاهای کوچک - برای فایل‌های بزرگ از ChunkedAEADCipher استفاده شود.
    """
    if len(key) != KEY_SIZE:
        raise CryptoError("طول کلید باید 32 بایت باشد")
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)
    ct = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce + ct


def decrypt_blob(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    """رمزگشایی بلاک تولیدشده توسط encrypt_blob. در صورت شکست، IntegrityError."""
    if len(key) != KEY_SIZE:
        raise CryptoError("طول کلید باید 32 بایت باشد")
    if len(blob) < NONCE_SIZE + TAG_SIZE:
        raise IntegrityError("بلاک رمزگذاری‌شده خیلی کوتاه/نامعتبر است")
    aesgcm = AESGCM(key)
    nonce, ct = blob[:NONCE_SIZE], blob[NONCE_SIZE:]
    try:
        return aesgcm.decrypt(nonce, ct, aad)
    except Exception as e:
        raise IntegrityError("رمزگشایی/Authentication بلاک شکست خورد") from e


class NullSink:
    """یک BinaryIO جعلی که هرچه نوشته شود را دور می‌ریزد - برای Verify بدون I/O اضافه به دیسک."""
    def write(self, b: bytes) -> int:
        return len(b)

    def flush(self) -> None:
        pass

    def fileno(self) -> int:
        raise OSError("no fileno")  # باعث می‌شود _flush_and_fsync آن را نادیده بگیرد


def filesystem_safe_name(raw: bytes) -> str:
    """
    تبدیل bytes رمزگذاری‌شده به یک نام فایل امن برای NTFS/ویندوز.
    از Base32 استفاده می‌شود (بدون حساسیت به حروف بزرگ/کوچک، بدون کاراکتر ممنوعه).
    """
    import base64
    encoded = base64.b32encode(raw).decode("ascii").rstrip("=")
    return encoded.lower()


def from_filesystem_safe_name(name: str) -> bytes:
    """معکوس filesystem_safe_name."""
    import base64
    s = name.upper()
    padding = "=" * ((8 - len(s) % 8) % 8)
    return base64.b32decode(s + padding)
