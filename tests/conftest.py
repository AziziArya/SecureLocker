"""
tests/conftest.py

فیکسچرهای مشترک pytest. هر تست یک محیط کاملاً ایزوله (پوشه‌ی کاری موقت،
"USB" شبیه‌سازی‌شده روی دیسک، دیتابیس تازه) دریافت می‌کند.
"""

from __future__ import annotations

import os
import sys
import shutil

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.metadata import MetadataStore
from core.key_manager import KeyHierarchy
from core.usb_manager import register_new_usb


@pytest.fixture
def tmp_dirs(tmp_path):
    """سه پوشه‌ی موقت مجزا: usb (شبیه‌سازی فلش)، work (فایل‌های کاربر)، db (دیتابیس)."""
    usb = tmp_path / "usb"
    work = tmp_path / "work"
    db_dir = tmp_path / "db"
    usb.mkdir()
    work.mkdir()
    db_dir.mkdir()
    old_env = os.environ.get("SECURELOCKER_TEST_USB_PATHS")
    os.environ["SECURELOCKER_TEST_USB_PATHS"] = str(usb)
    yield {"usb": str(usb), "work": str(work), "db": str(db_dir / "meta.db")}
    if old_env is None:
        os.environ.pop("SECURELOCKER_TEST_USB_PATHS", None)
    else:
        os.environ["SECURELOCKER_TEST_USB_PATHS"] = old_env


@pytest.fixture
def vault(tmp_dirs):
    """
    یک Vault کاملاً راه‌اندازی‌شده: USB ثبت‌شده + Password + Security Question،
    و KeyHierarchy از قبل unlock شده. برای اکثر تست‌های سطح‌بالا کافی است.
    """
    db = MetadataStore(tmp_dirs["db"])
    usb_info = register_new_usb(tmp_dirs["usb"])
    password = "TestPass123!"

    mk, key_store = KeyHierarchy.setup_new(password, usb_info.usb_secret)
    temp_kh = KeyHierarchy.from_master_key(mk)
    from core.key_manager import setup_security_question
    recovery_fields = temp_kh.build_recovery_fields(usb_info.usb_secret, "TestAnswer", key_store)
    key_store.update(recovery_fields)
    db.save_key_store(key_store)
    db.save_usb_fingerprint(usb_info.fingerprint())
    sq = setup_security_question("TestAnswer")
    db.save_security_question("سوال تست؟", sq["answer_salt"], sq["answer_hash"])

    kh = KeyHierarchy()
    kh.unlock(password, usb_info.usb_secret, key_store)

    yield {
        "db": db, "kh": kh, "usb_info": usb_info, "password": password,
        "work": tmp_dirs["work"], "usb_root": tmp_dirs["usb"],
        "security_answer": "TestAnswer",
    }
    db.close()


@pytest.fixture
def engine_with_backup(vault):
    """FileEngine کامل با BackupManager واقعی (نه Fake) - برای تست‌های End-to-End."""
    from core.backup_manager import BackupManager
    from core.file_engine import FileEngine

    bm = BackupManager(vault["db"], vault["kh"], lambda: vault["usb_info"], default_encrypt=True)
    engine = FileEngine(vault["db"], vault["kh"], backup_provider=bm)
    vault["backup_manager"] = bm
    vault["engine"] = engine
    return vault


def make_file(path: str, content: str = "test content") -> str:
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path


def make_binary_file(path: str, data: bytes) -> str:
    with open(path, "wb") as f:
        f.write(data)
    return path
