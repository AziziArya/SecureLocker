"""
core/security.py

مدیریت Session:
    - محدودیت تلاش اشتباه Password (قابل تنظیم: 3/5/10) + مسیر Recovery بعد از رسیدن به سقف
    - Auto Logout قابل تنظیم (30s/1m/5m/10m/Never) که هرگز وسط یک عملیات Lock/Unlock
      فعال نمی‌شود (بخش ۱۹ درخواست: منتظر پایان امن عملیات می‌ماند)

طراحی Auto Logout:
    این ماژول خودش تایمر GUI نیست (آن در ui/ با root.after() پیاده می‌شود). این‌جا فقط
    منطق "آیا الان زمان Logout رسیده؟" نگه‌داری می‌شود: SessionManager.should_auto_logout().
    UI هر چند ثانیه یک‌بار این متد را poll می‌کند و اگر True بود، خودش کلید را lock می‌کند
    و صفحه‌ی Login را نشان می‌دهد. مادامی‌که begin_operation()/end_operation() به‌درستی
    توسط FileEngine دور Lock/Unlock فراخوانی شود، should_auto_logout() هرگز وسط یک
    عملیات حساس True برنمی‌گردد (چون operation_in_progress را چک می‌کند).
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Optional

from core.metadata import MetadataStore

DEFAULT_MAX_ATTEMPTS = 5
AUTO_LOGOUT_CHOICES = {
    "30s": 30,
    "1m": 60,
    "5m": 300,
    "10m": 600,
    "never": None,
}


class SecurityError(Exception):
    """خطای عمومی امنیتی."""


class AttemptLimitExceededError(SecurityError):
    """تعداد تلاش‌های اشتباه Password از سقف مجاز عبور کرد."""


@dataclass
class SecuritySettings:
    max_wrong_attempts: int = DEFAULT_MAX_ATTEMPTS
    auto_logout_seconds: Optional[int] = 300  # None = Never


class SessionManager:
    """
    مدیریت وضعیت Session: تلاش‌های ناموفق Password و Auto Logout ایمن.
    Thread-safe (چون هم از Main Thread و هم از Worker Thread عملیات فایل دسترسی می‌شود).
    """

    def __init__(self, metadata: MetadataStore, settings: Optional[SecuritySettings] = None):
        self.metadata = metadata
        self.settings = settings or SecuritySettings()
        self._lock = threading.RLock()
        self._operation_depth = 0
        self._last_activity = time.monotonic()

    # ----------------------------------------------------------- Wrong-attempt limiting
    def _get_attempt_count(self) -> int:
        raw = self.metadata.get_meta_str("failed_attempt_count")
        return int(raw) if raw else 0

    def _set_attempt_count(self, n: int) -> None:
        self.metadata.set_meta("failed_attempt_count", str(n))

    def record_failed_attempt(self) -> int:
        with self._lock:
            count = self._get_attempt_count() + 1
            self._set_attempt_count(count)
            self.metadata.add_log("FAILED_LOGIN", f"تلاش ناموفق ورود (تعداد: {count})", "WARNING")
            return count

    def record_successful_attempt(self) -> None:
        with self._lock:
            self._set_attempt_count(0)
            self.metadata.add_log("LOGIN", "ورود موفق")
            self.touch_activity()

    def is_locked_out(self) -> bool:
        with self._lock:
            return self._get_attempt_count() >= self.settings.max_wrong_attempts

    def remaining_attempts(self) -> int:
        with self._lock:
            return max(0, self.settings.max_wrong_attempts - self._get_attempt_count())

    def reset_attempts(self) -> None:
        with self._lock:
            self._set_attempt_count(0)

    # ----------------------------------------------------------- Activity / Auto Logout
    def touch_activity(self) -> None:
        with self._lock:
            self._last_activity = time.monotonic()

    def seconds_since_activity(self) -> float:
        with self._lock:
            return time.monotonic() - self._last_activity

    def begin_operation(self) -> None:
        """قبل از شروع یک عملیات حساس (Lock/Unlock/Backup) فراخوانی شود."""
        with self._lock:
            self._operation_depth += 1

    def end_operation(self) -> None:
        """بعد از پایان (موفق یا ناموفق) عملیات حساس فراخوانی شود."""
        with self._lock:
            self._operation_depth = max(0, self._operation_depth - 1)
            self.touch_activity()

    def is_operation_in_progress(self) -> bool:
        with self._lock:
            return self._operation_depth > 0

    def should_auto_logout(self) -> bool:
        """
        آیا الان زمان Auto Logout رسیده؟
        هرگز وقتی عملیات حساسی در حال اجراست True برنمی‌گردد - این تضمین می‌کند
        Auto Logout هرگز وسط رمزگذاری/رمزگشایی فایل باعث خرابی نشود.
        """
        with self._lock:
            if self.settings.auto_logout_seconds is None:
                return False
            if self._operation_depth > 0:
                return False
            return self.seconds_since_activity() >= self.settings.auto_logout_seconds

    def update_settings(self, max_wrong_attempts: Optional[int] = None,
                         auto_logout_seconds: Optional[int] = "unset") -> None:  # type: ignore[assignment]
        with self._lock:
            if max_wrong_attempts is not None:
                self.settings.max_wrong_attempts = max_wrong_attempts
            if auto_logout_seconds != "unset":
                self.settings.auto_logout_seconds = auto_logout_seconds
            self.metadata.add_log("SECURITY_SETTINGS_CHANGE", "تنظیمات امنیتی تغییر کرد")


class OperationGuard:
    """Context manager کوچک برای دور کردن یک عملیات حساس با begin_operation/end_operation."""

    def __init__(self, session: Optional[SessionManager]):
        self.session = session

    def __enter__(self):
        if self.session:
            self.session.begin_operation()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            self.session.end_operation()
        return False
