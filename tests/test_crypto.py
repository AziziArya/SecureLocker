"""
tests/test_crypto.py

تست‌های واحد core/crypto.py: AEAD streaming، تشخیص دستکاری، truncation،
فایل‌های خالی/بزرگ، و بلاک‌های کوچک رمزگذاری‌شده (نام فایل و مسیر).
"""

from __future__ import annotations

import io
import os

import pytest

from core.crypto import (
    make_cipher, encrypt_blob, decrypt_blob, IntegrityError, FormatError,
)


def _cipher_pair():
    key = os.urandom(32)
    hmac_key = os.urandom(32)
    return make_cipher(key, hmac_key), make_cipher(key, hmac_key)


def test_roundtrip_small_file():
    """رمزگذاری/رمزگشایی یک فایل کوچک باید دقیقاً محتوای اصلی را برگرداند."""
    enc_cipher, dec_cipher = _cipher_pair()
    plaintext = "سلام دنیا - hello world 123".encode("utf-8")
    src, dst = io.BytesIO(plaintext), io.BytesIO()
    enc_cipher.encrypt_stream(src, dst, "f1", len(plaintext), "2026-01-01")
    dst.seek(0)
    out = io.BytesIO()
    dec_cipher.decrypt_stream(dst, out, expected_file_id="f1")
    assert out.getvalue() == plaintext


def test_roundtrip_large_file_streaming():
    """فایل بزرگ (>2 chunk) باید بدون خواندن کامل به RAM به‌درستی رفت‌وبرگشت شود."""
    enc_cipher, dec_cipher = _cipher_pair()
    plaintext = os.urandom(20 * 1024 * 1024 + 555)
    src, dst = io.BytesIO(plaintext), io.BytesIO()
    enc_cipher.encrypt_stream(src, dst, "big", len(plaintext), "2026-01-01")
    dst.seek(0)
    out = io.BytesIO()
    meta = dec_cipher.decrypt_stream(dst, out, expected_file_id="big")
    assert out.getvalue() == plaintext
    assert meta.chunk_count >= 2


def test_empty_file_roundtrip():
    """فایل با اندازه‌ی صفر نباید باعث خطا شود و باید صحیح رفت‌وبرگشت شود."""
    enc_cipher, dec_cipher = _cipher_pair()
    src, dst = io.BytesIO(b""), io.BytesIO()
    enc_cipher.encrypt_stream(src, dst, "empty", 0, "2026-01-01")
    dst.seek(0)
    out = io.BytesIO()
    dec_cipher.decrypt_stream(dst, out, expected_file_id="empty")
    assert out.getvalue() == b""


def test_tamper_detection_raises_integrity_error():
    """دستکاری حتی یک بایت از ciphertext باید IntegrityError بدهد، نه داده‌ی خراب ساکت."""
    enc_cipher, dec_cipher = _cipher_pair()
    plaintext = os.urandom(1024)
    src, dst = io.BytesIO(plaintext), io.BytesIO()
    enc_cipher.encrypt_stream(src, dst, "t1", len(plaintext), "2026-01-01")
    tampered = bytearray(dst.getvalue())
    tampered[100] ^= 0xFF
    with pytest.raises(IntegrityError):
        dec_cipher.decrypt_stream(io.BytesIO(bytes(tampered)), io.BytesIO(), expected_file_id="t1")


def test_truncation_detected():
    """حذف بخش انتهایی فایل رمزگذاری‌شده (truncation attack) باید تشخیص داده شود."""
    enc_cipher, dec_cipher = _cipher_pair()
    plaintext = os.urandom(9 * 1024 * 1024)
    src, dst = io.BytesIO(plaintext), io.BytesIO()
    enc_cipher.encrypt_stream(src, dst, "trunc", len(plaintext), "2026-01-01")
    truncated = dst.getvalue()[:-50]
    with pytest.raises((IntegrityError, FormatError)):
        dec_cipher.decrypt_stream(io.BytesIO(truncated), io.BytesIO(), expected_file_id="trunc")


def test_wrong_key_fails_authentication():
    """رمزگشایی با کلید نادرست باید همیشه شکست بخورد (نه یک نتیجه‌ی نادرست ساکت)."""
    enc_cipher = make_cipher(os.urandom(32), os.urandom(32))
    wrong_cipher = make_cipher(os.urandom(32), os.urandom(32))
    plaintext = b"secret data"
    src, dst = io.BytesIO(plaintext), io.BytesIO()
    enc_cipher.encrypt_stream(src, dst, "k1", len(plaintext), "2026-01-01")
    dst.seek(0)
    with pytest.raises(IntegrityError):
        wrong_cipher.decrypt_stream(dst, io.BytesIO(), expected_file_id="k1")


def test_blob_roundtrip_persian_filename():
    """رمزگذاری بلاک کوچک (نام فایل فارسی) باید دقیق رفت‌وبرگشت شود."""
    key = os.urandom(32)
    name = "گزارش محرمانه ۲۰۲۶.docx"
    blob = encrypt_blob(key, name.encode("utf-8"), aad=b"file-1")
    recovered = decrypt_blob(key, blob, aad=b"file-1").decode("utf-8")
    assert recovered == name


def test_blob_wrong_aad_fails():
    """AAD نادرست (مثلاً file_id اشتباه) باید Authentication را شکست دهد."""
    key = os.urandom(32)
    blob = encrypt_blob(key, b"data", aad=b"correct-id")
    with pytest.raises(IntegrityError):
        decrypt_blob(key, blob, aad=b"wrong-id")


def test_nonce_uniqueness_across_files():
    """دو فایل با محتوای یکسان اما nonce_base متفاوت باید ciphertext متفاوت تولید کنند."""
    key, hmac_key = os.urandom(32), os.urandom(32)
    c1 = make_cipher(key, hmac_key)
    c2 = make_cipher(key, hmac_key)
    plaintext = b"same content" * 1000
    out1, out2 = io.BytesIO(), io.BytesIO()
    c1.encrypt_stream(io.BytesIO(plaintext), out1, "same-id", len(plaintext), "t")
    c2.encrypt_stream(io.BytesIO(plaintext), out2, "same-id", len(plaintext), "t")
    assert out1.getvalue() != out2.getvalue()
