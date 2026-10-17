"""
config.py

تنظیمات سطح-برنامه (نه محرمانه) که باید حتی قبل از Login هم در دسترس باشند:
زبان، Auto Logout، حداکثر تلاش اشتباه، رفتار پیش‌فرض Backup و ...

این تنظیمات در یک فایل JSON ساده (config.json) در پوشه‌ی داده‌ی برنامه نگه‌داری
می‌شوند - کاملاً مجزا از core/metadata.py (که دیتابیس رمزنگاری‌شده‌ی Vault است).
هیچ داده‌ی حساسی (Password، USB Secret، Master Key) هرگز این‌جا ذخیره نمی‌شود.

مسیر داده‌ی برنامه:
    ویندوز:   %APPDATA%\\SecureLocker\\
    غیر ویندوز (توسعه/تست): ~/.securelocker/  یا  $SECURELOCKER_DATA_DIR اگر تنظیم شده باشد
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Optional


def get_app_data_dir() -> Path:
    override = os.environ.get("SECURELOCKER_DATA_DIR")
    if override:
        p = Path(override)
    elif sys.platform == "win32":
        base = os.environ.get("APPDATA", str(Path.home()))
        p = Path(base) / "SecureLocker"
    else:
        p = Path.home() / ".securelocker"
    p.mkdir(parents=True, exist_ok=True)
    return p


CONFIG_FILE_NAME = "config.json"
DB_FILE_NAME = "vault_metadata.db"

AUTO_LOGOUT_OPTIONS = ["30s", "1m", "5m", "10m", "never"]
AUTO_LOGOUT_SECONDS_MAP = {"30s": 30, "1m": 60, "5m": 300, "10m": 600, "never": None}


@dataclass
class AppConfig:
    language: str = "fa"
    auto_logout_choice: str = "5m"
    max_wrong_attempts: int = 5
    default_backup_requested: bool = True
    default_encrypt_backup: bool = True
    always_ask_protection_options: bool = True
    default_protect_names: bool = False
    default_protect_structure: bool = False
    emergency_lock_default: bool = False
    window_width: int = 1000
    window_height: int = 680

    def auto_logout_seconds(self) -> Optional[int]:
        return AUTO_LOGOUT_SECONDS_MAP.get(self.auto_logout_choice, 300)

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "AppConfig":
        known_fields = {f for f in AppConfig.__dataclass_fields__.keys()}
        filtered = {k: v for k, v in d.items() if k in known_fields}
        return AppConfig(**filtered)


def config_path(base_dir: Optional[Path] = None) -> Path:
    base = base_dir if base_dir is not None else get_app_data_dir()
    return Path(base) / CONFIG_FILE_NAME


def default_db_path() -> str:
    """
    مسیر پیش‌فرض دیتابیس روی لپ‌تاپ (%APPDATA%). این مسیر فقط زمانی استفاده
    می‌شود که هیچ USB با Vault آماده پیدا نشود و هنوز Setup انجام نشده باشد؛
    Setup Wizard به‌طور معمول دیتابیس را مستقیم روی خود USB می‌سازد (تا کل
    برنامه - EXE + دیتابیس + تنظیمات + Backup - کاملاً روی فلش portable بماند).
    """
    return str(get_app_data_dir() / DB_FILE_NAME)


def load_config(base_dir: Optional[Path] = None) -> AppConfig:
    path = config_path(base_dir)
    if not path.exists():
        cfg = AppConfig()
        save_config(cfg, base_dir)
        return cfg
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return AppConfig.from_dict(data)
    except (json.JSONDecodeError, OSError):
        # فایل تنظیمات خراب است - به‌جای کرش، به پیش‌فرض برمی‌گردیم (تنظیمات حیاتی نیستند)
        return AppConfig()


def save_config(cfg: AppConfig, base_dir: Optional[Path] = None) -> None:
    path = config_path(base_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(".tmp")
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(cfg.to_dict(), f, ensure_ascii=False, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, path)
