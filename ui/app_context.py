"""
ui/app_context.py

AppContext یک شیء مرکزی است که تمام سرویس‌های لایه‌ی core (دیتابیس، کلیدها،
موتور فایل، Backup Manager، Session) را نگه می‌دارد و بین صفحات مختلف UI
(Dashboard، Lock Dialog، Unlock Dialog، Settings و ...) به اشتراک می‌گذارد.

معماری Portable-on-USB:
    کل «مرکز کنترل» برنامه (دیتابیس + تنظیمات + Backup) روی خود USB نگه‌داری
    می‌شود تا با یک EXE مستقل، از هر لپ‌تاپی (حتی بدون Python) قابل اجرا باشد.
    به همین دلیل db_path/config_dir تا لحظه‌ی شناسایی/انتخاب USB نامشخص است:
        - اگر main.py یک USB با Vault آماده پیدا کند: db_path/config_dir از
          همان ابتدا مشخص است.
        - اگر هنوز هیچ Vault ای وجود نداشته باشد (اولین اجرا): AppContext با
          db_path=None ساخته می‌شود و Setup Wizard، بعد از انتخاب کاربر، متد
          bind_to_usb_vault() را صدا می‌زند تا دیتابیس/تنظیمات را روی همان USB بسازد.

توجه امنیتی مهم: چون حالا دیتابیس هم روی USB است (نه فقط روی لپ‌تاپ)، اگر کاربر
وسط استفاده از برنامه (نه فقط وسط Lock/Unlock که از قبل محافظت‌شده) فلش را بیرون
بکشد، عملیات‌های بعدی دیتابیس ممکن است با خطا مواجه شوند. این خطا در Dashboard
به‌صورت پیام واضح مدیریت می‌شود (نه crash خام) - به core/security و ui/dashboard مراجعه شود.

طول عمر کلیدها:
    قبل از Login: فقط config و metadata (بدون کلید) در دسترس است.
    بعد از Login موفق: keys باز می‌شود و file_engine/backup_manager ساخته می‌شوند.
    بعد از Logout/Auto-logout: کلیدها از RAM پاک می‌شوند (keys.lock())، UI به
    صفحه‌ی Login برمی‌گردد.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from config import AppConfig, load_config, save_config, default_db_path
from core.metadata import MetadataStore
from core.key_manager import KeyHierarchy
from core.usb_manager import UsbKeyInfo, find_registered_usb, UsbDetectionResult
from core.backup_manager import BackupManager, BackupNotAvailableError
from core.file_engine import FileEngine
from core.security import SessionManager, SecuritySettings
from core.recovery import PasswordRecoveryManager, CrashRecoveryManager
from localization.strings import set_language


class AppContext:
    def __init__(self, db_path: Optional[str] = None, config_dir: Optional[str] = None):
        """
        db_path=None یعنی «هنوز هیچ Vault ای شناسایی/ساخته نشده» (فقط در اولین
        اجرا، قبل از این‌که Setup Wizard یک USB انتخاب کند رخ می‌دهد).
        """
        self._config_dir: Optional[Path] = Path(config_dir) if config_dir else None
        self.config: AppConfig = load_config(self._config_dir)
        set_language(self.config.language)

        self.db_path: Optional[str] = db_path
        self.metadata: Optional[MetadataStore] = MetadataStore(db_path) if db_path else None

        self.keys = KeyHierarchy()
        self.session: Optional[SessionManager] = None
        if self.metadata is not None:
            self._init_session()

        self._current_usb: Optional[UsbKeyInfo] = None

        # این سرویس‌ها فقط بعد از Login موفق (وقتی keys باز است) کامل کار می‌کنند
        self.backup_manager: Optional[BackupManager] = None
        self.file_engine: Optional[FileEngine] = None
        self.recovery_manager: Optional[PasswordRecoveryManager] = None
        self.crash_recovery: Optional[CrashRecoveryManager] = None

    def _init_session(self) -> None:
        self.session = SessionManager(
            self.metadata,
            SecuritySettings(
                max_wrong_attempts=self.config.max_wrong_attempts,
                auto_logout_seconds=self.config.auto_logout_seconds(),
            ),
        )

    # ----------------------------------------------------------- USB Vault binding (Portable-on-USB)
    def bind_to_usb_vault(self, usb_info: UsbKeyInfo) -> None:
        """
        بعد از این‌که کاربر در Setup Wizard یک USB انتخاب/ثبت کرد، این متد دیتابیس
        و تنظیمات را مستقیم روی همان USB می‌سازد (نه روی لپ‌تاپ) تا کل برنامه
        Portable بماند. فقط یک‌بار (در اولین Setup) فراخوانی می‌شود.
        """
        if self.metadata is not None:
            raise RuntimeError("bind_to_usb_vault فقط زمانی مجاز است که هنوز Vault ای بسته نشده باشد")

        self.db_path = usb_info.vault_db_path()
        self.metadata = MetadataStore(self.db_path)
        self._config_dir = Path(usb_info.vault_dir())
        # اگر config.json روی لپ‌تاپ (پیش‌فرض قبل از انتخاب USB) تنظیماتی داشت،
        # همان مقادیر را روی USB هم persist می‌کنیم تا از دست نروند.
        save_config(self.config, self._config_dir)
        self._init_session()

    def is_bound(self) -> bool:
        return self.metadata is not None

    # ----------------------------------------------------------- USB detection (runtime)
    def set_current_usb(self, info: Optional[UsbKeyInfo]) -> None:
        self._current_usb = info

    def get_current_usb(self) -> UsbKeyInfo:
        if self._current_usb is None:
            raise BackupNotAvailableError("USB متصل نیست")
        return self._current_usb

    def detect_usb(self) -> UsbDetectionResult:
        """اسکن USBهای متصل و مقایسه با fingerprint ثبت‌شده."""
        if self.metadata is None:
            from core.usb_manager import scan_all_usb_keys
            found = scan_all_usb_keys()
            status = "SETUP_MODE" if found else "NOT_FOUND"
            return UsbDetectionResult(status=status, matched=found[0] if found else None,
                                       others=found[1:] if found else [])
        fingerprint = self.metadata.load_usb_fingerprint()
        if fingerprint is None:
            from core.usb_manager import scan_all_usb_keys
            found = scan_all_usb_keys()
            status = "SETUP_MODE" if found else "NOT_FOUND"
            return UsbDetectionResult(status=status, matched=found[0] if found else None,
                                       others=found[1:] if found else [])
        return find_registered_usb(fingerprint)

    # ----------------------------------------------------------- Lifecycle
    def is_first_run(self) -> bool:
        return self.metadata is None or not self.metadata.is_initialized()

    def wire_after_unlock(self) -> None:
        """بعد از Login/Recovery موفق فراخوانی شود تا سرویس‌های وابسته به کلید ساخته شوند."""
        self.backup_manager = BackupManager(
            self.metadata, self.keys, self.get_current_usb,
            default_encrypt=self.config.default_encrypt_backup,
        )
        self.file_engine = FileEngine(
            self.metadata, self.keys, backup_provider=self.backup_manager, session=self.session,
        )
        self.recovery_manager = PasswordRecoveryManager(self.metadata, self.keys)
        self.crash_recovery = CrashRecoveryManager(self.metadata, self.keys)

    def logout(self) -> None:
        self.metadata.add_log("LOGOUT", "کاربر خارج شد")
        self.keys.lock()
        self.backup_manager = None
        self.file_engine = None
        self.recovery_manager = None

    def apply_config(self) -> None:
        save_config(self.config, self._config_dir)
        if self.session is not None:
            self.session.update_settings(
                max_wrong_attempts=self.config.max_wrong_attempts,
                auto_logout_seconds=self.config.auto_logout_seconds(),
            )
        set_language(self.config.language)

    def shutdown(self) -> None:
        if self.metadata is not None:
            self.metadata.close()
