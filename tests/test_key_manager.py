"""
tests/test_key_manager.py

تست‌های واحد core/key_manager.py: سلسله‌مراتب کلید، دو-عاملی واقعی بودن
(Password + USB)، تغییر Password بدون دست‌زدن به Master Key، و مسیر Recovery.
"""

from __future__ import annotations

import os

import pytest

from core.key_manager import (
    KeyHierarchy, AuthenticationFailedError, setup_security_question, verify_security_answer,
)


def test_setup_and_unlock_roundtrip():
    """Setup اولیه باید یک Master Key تولید کند که با همان Password+USB باز شود."""
    password, usb_secret = "MyPass123!", os.urandom(32)
    mk, key_store = KeyHierarchy.setup_new(password, usb_secret)
    kh = KeyHierarchy()
    kh.unlock(password, usb_secret, key_store)
    assert kh.get_master_key_bytes() == mk


def test_wrong_password_rejected():
    """Password نادرست (حتی با USB درست) نباید Unlock را ممکن کند."""
    usb_secret = os.urandom(32)
    _, key_store = KeyHierarchy.setup_new("CorrectPass1!", usb_secret)
    kh = KeyHierarchy()
    with pytest.raises(AuthenticationFailedError):
        kh.unlock("WrongPass1!", usb_secret, key_store)


def test_wrong_usb_rejected():
    """USB نادرست (حتی با Password درست) نباید Unlock را ممکن کند."""
    password = "CorrectPass1!"
    _, key_store = KeyHierarchy.setup_new(password, os.urandom(32))
    kh = KeyHierarchy()
    with pytest.raises(AuthenticationFailedError):
        kh.unlock(password, os.urandom(32), key_store)


def test_password_change_preserves_master_key():
    """تغییر Password نباید Master Key فایل‌ها را عوض کند (بدون نیاز به re-encrypt)."""
    usb_secret = os.urandom(32)
    mk, key_store = KeyHierarchy.setup_new("OldPass1!", usb_secret)
    kh = KeyHierarchy()
    kh.unlock("OldPass1!", usb_secret, key_store)
    new_key_store = kh.change_password("OldPass1!", "NewPass2!", usb_secret, key_store)

    kh2 = KeyHierarchy()
    kh2.unlock("NewPass2!", usb_secret, new_key_store)
    assert kh2.get_master_key_bytes() == mk

    kh3 = KeyHierarchy()
    with pytest.raises(AuthenticationFailedError):
        kh3.unlock("OldPass1!", usb_secret, new_key_store)


def test_derived_subkeys_are_unique_per_file():
    """هر file_id باید File Key و HMAC Key کاملاً متفاوت (unique) داشته باشد."""
    kh = KeyHierarchy.from_master_key(os.urandom(32))
    k1 = kh.derive_file_key("file-a")
    k2 = kh.derive_file_key("file-b")
    assert k1 != k2
    assert kh.derive_file_key("file-a") == k1  # deterministic برای همان id


def test_recovery_requires_both_answer_and_usb():
    """Recovery فقط با ترکیب صحیح (Security Answer + USB) کار می‌کند، نه یکی به‌تنهایی."""
    usb_secret = os.urandom(32)
    mk, key_store = KeyHierarchy.setup_new("Pass1!", usb_secret)
    setup_kh = KeyHierarchy.from_master_key(mk)
    recovery_fields = setup_kh.build_recovery_fields(usb_secret, "MyAnswer", key_store)
    key_store.update(recovery_fields)

    # پاسخ درست + USB نادرست
    kh1 = KeyHierarchy()
    with pytest.raises(AuthenticationFailedError):
        kh1.unlock_via_recovery("MyAnswer", os.urandom(32), key_store)

    # پاسخ نادرست + USB درست
    kh2 = KeyHierarchy()
    with pytest.raises(AuthenticationFailedError):
        kh2.unlock_via_recovery("WrongAnswer", usb_secret, key_store)

    # هر دو درست
    kh3 = KeyHierarchy()
    kh3.unlock_via_recovery("MyAnswer", usb_secret, key_store)
    assert kh3.get_master_key_bytes() == mk


def test_recovery_answer_normalization():
    """پاسخ سوال امنیتی باید نسبت به فاصله و حروف بزرگ/کوچک نرمال شود."""
    usb_secret = os.urandom(32)
    mk, key_store = KeyHierarchy.setup_new("Pass1!", usb_secret)
    setup_kh = KeyHierarchy.from_master_key(mk)
    recovery_fields = setup_kh.build_recovery_fields(usb_secret, "Tehran", key_store)
    key_store.update(recovery_fields)

    kh = KeyHierarchy()
    kh.unlock_via_recovery("  tEHRAN  ", usb_secret, key_store)  # فاصله + حروف متفاوت
    assert kh.get_master_key_bytes() == mk


def test_set_new_password_after_recovery_does_not_touch_recovery_wrap():
    """تعیین Password جدید بعد از Recovery نباید wrapped_mk_recovery را خراب کند."""
    usb_secret = os.urandom(32)
    mk, key_store = KeyHierarchy.setup_new("Pass1!", usb_secret)
    setup_kh = KeyHierarchy.from_master_key(mk)
    recovery_fields = setup_kh.build_recovery_fields(usb_secret, "Answer1", key_store)
    key_store.update(recovery_fields)

    kh = KeyHierarchy()
    kh.unlock_via_recovery("Answer1", usb_secret, key_store)
    new_key_store = kh.set_new_password("BrandNewPass9!", usb_secret, key_store)

    # هم Password جدید کار کند
    kh2 = KeyHierarchy()
    kh2.unlock("BrandNewPass9!", usb_secret, new_key_store)
    assert kh2.get_master_key_bytes() == mk

    # هم مسیر Recovery قدیمی هنوز کار کند
    kh3 = KeyHierarchy()
    kh3.unlock_via_recovery("Answer1", usb_secret, new_key_store)
    assert kh3.get_master_key_bytes() == mk


def test_security_answer_hash_never_stores_plaintext():
    """رکورد هش‌شده‌ی پاسخ نباید حاوی پاسخ خام باشد."""
    record = setup_security_question("MySecretAnswer")
    assert b"MySecretAnswer" not in record["answer_hash"]
    assert verify_security_answer("MySecretAnswer", record) is True
    assert verify_security_answer("WrongAnswer", record) is False
