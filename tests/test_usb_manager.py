"""
tests/test_usb_manager.py

تست‌های واحد core/usb_manager.py: تشخیص USB مستقل از Drive Letter،
Fingerprint یک‌طرفه، و شرایط خرابی/عدم وجود.
"""

from __future__ import annotations

import os
import shutil

import pytest

from core.usb_manager import (
    register_new_usb, read_usb_key, find_registered_usb, is_usb_still_present,
    UsbKeyCorruptedError,
)


def test_register_and_read_back(tmp_path):
    usb_root = str(tmp_path / "usb1")
    os.makedirs(usb_root)
    info = register_new_usb(usb_root)
    info2 = read_usb_key(usb_root)
    assert info2.usb_id == info.usb_id
    assert info2.usb_secret == info.usb_secret


def test_find_registered_usb_matched(tmp_path):
    """USB درست باید در میان چند درایو متصل به‌درستی پیدا شود."""
    usb1 = str(tmp_path / "usb1")
    usb2 = str(tmp_path / "usb2")
    os.makedirs(usb1)
    os.makedirs(usb2)
    correct = register_new_usb(usb1)
    register_new_usb(usb2)  # یک USB کاملاً متفاوت (اشتباه)

    result = find_registered_usb(correct.fingerprint(), test_override=[usb1, usb2])
    assert result.status == "MATCHED"
    assert result.matched.drive_root == usb1


def test_find_registered_usb_wrong(tmp_path):
    """اگر فقط USB اشتباه وصل باشد، باید WRONG_USB برگردد نه یک match نادرست."""
    usb1 = str(tmp_path / "usb1")
    usb2 = str(tmp_path / "usb2")
    os.makedirs(usb1)
    os.makedirs(usb2)
    correct = register_new_usb(usb1)
    register_new_usb(usb2)

    result = find_registered_usb(correct.fingerprint(), test_override=[usb2])
    assert result.status == "WRONG_USB"


def test_find_registered_usb_not_found():
    result = find_registered_usb(os.urandom(32), test_override=[])
    assert result.status == "NOT_FOUND"


def test_usb_removal_detected(tmp_path):
    usb_root = str(tmp_path / "usb1")
    os.makedirs(usb_root)
    info = register_new_usb(usb_root)
    assert is_usb_still_present(info) is True
    shutil.rmtree(os.path.join(usb_root, ".securelocker"))
    assert is_usb_still_present(info) is False


def test_corrupted_key_file_detected(tmp_path):
    usb_root = str(tmp_path / "usb1")
    os.makedirs(usb_root)
    register_new_usb(usb_root)
    key_path = os.path.join(usb_root, ".securelocker", "key.bin")
    with open(key_path, "wb") as f:
        f.write(b"not a valid key file")
    with pytest.raises(UsbKeyCorruptedError):
        read_usb_key(usb_root)
