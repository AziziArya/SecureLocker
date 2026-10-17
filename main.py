"""
main.py

نقطه‌ی ورود Secure Locker.

معماری Portable-on-USB:
    کل «مرکز کنترل» برنامه (دیتابیس + تنظیمات + Backup) روی خود USB نگه‌داری
    می‌شود، نه روی لپ‌تاپ. بنابراین قبل از هر چیز باید بفهمیم آیا یک USB با
    Vault آماده (Setup‌شده) همین الان وصل است یا نه:

        اگر بله -> مستقیم دیتابیس همان USB باز می‌شود -> صفحه‌ی Login
        اگر نه  -> AppContext بدون دیتابیس ساخته می‌شود -> Setup Wizard
                   (که بعد از انتخاب کاربر، دیتابیس را روی همان USB می‌سازد)

این یعنی با کپی کردن یک SecureLocker.exe به هر فلشی و اجرای آن روی هر لپ‌تاپ
ویندوزی (حتی بدون Python نصب‌شده)، برنامه کاملاً کار می‌کند و همه‌چیز (کلید،
دیتابیس، تنظیمات، Backup) همراه همان فلش باقی می‌ماند.
"""

from __future__ import annotations

import sys
import tkinter as tk
from tkinter import ttk, messagebox

from core.usb_manager import find_existing_vault_usbs, UsbKeyInfo
from ui.app_context import AppContext
from ui import theme
from ui.dnd_utils import HAS_DND, TkinterDnD
from localization.strings import tr


def _create_root() -> tk.Tk:
    """اگر tkinterdnd2 نصب باشد، از TkinterDnD.Tk() استفاده می‌شود تا Drag&Drop
    در کل برنامه کار کند؛ در غیر این صورت به tk.Tk() معمولی برمی‌گردیم
    (Lock/Unlock Dialog در آن صورت به‌صورت خودکار روی حالت Browse/Paste fallback می‌کنند)."""
    if HAS_DND:
        return TkinterDnD.Tk()
    return tk.Tk()


def _resolve_existing_vault(root: tk.Tk) -> UsbKeyInfo | None:
    """
    اسکن USBهای متصل برای پیدا کردن یک Vault آماده (از قبل Setup‌شده).
    اگر بیش از یکی پیدا شد، از کاربر می‌خواهیم انتخاب کند (نادر، ولی امن‌تر از
    حدس زدن خودکار).
    """
    candidates = find_existing_vault_usbs()
    if not candidates:
        return None
    if len(candidates) == 1:
        return candidates[0]

    # حالت نادر: چند فلش Secure Locker هم‌زمان وصل است
    choice = {"value": None}
    picker = tk.Toplevel(root)
    picker.title(tr("app.title"))
    picker.grab_set()
    ttk.Label(picker, text="چند Vault روی USBهای مختلف پیدا شد. یکی را انتخاب کنید:",
              padding=16).pack()
    for info in candidates:
        def _pick(i=info):
            choice["value"] = i
            picker.destroy()
        ttk.Button(picker, text=info.drive_root, command=_pick).pack(fill="x", padx=16, pady=4)
    picker.wait_window()
    return choice["value"] or candidates[0]


class SecureLockerApp:
    def __init__(self, db_path: str | None = None, config_dir: str | None = None,
                 _force_no_vault_scan: bool = False):
        self.root = _create_root()
        self.root.title(tr("app.title"))
        self.root.geometry("1000x680")
        self.root.minsize(860, 600)
        theme.apply_theme(self.root)

        if db_path is not None:
            # حالت صریح (مثلاً تست‌ها) - از منطق کشف خودکار صرف‌نظر می‌شود
            self.ctx = AppContext(db_path=db_path, config_dir=config_dir)
        elif _force_no_vault_scan:
            self.ctx = AppContext(db_path=None, config_dir=None)
        else:
            existing = _resolve_existing_vault(self.root)
            if existing is not None:
                self.ctx = AppContext(db_path=existing.vault_db_path(), config_dir=existing.vault_dir())
                self.ctx.set_current_usb(existing)
            else:
                self.ctx = AppContext(db_path=None, config_dir=None)

        self.container = ttk.Frame(self.root)
        self.container.pack(fill="both", expand=True)
        self.current_frame: ttk.Frame | None = None

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self._route_initial_screen()

    def _swap_frame(self, frame_cls, **kwargs):
        if self.current_frame is not None:
            self.current_frame.destroy()
        self.current_frame = frame_cls(self.container, self.ctx, **kwargs)
        self.current_frame.pack(fill="both", expand=True)

    def _route_initial_screen(self):
        if self.ctx.is_first_run():
            from ui.setup_wizard import SetupWizardFrame
            self._swap_frame(SetupWizardFrame, on_complete=self._show_dashboard)
        else:
            self._show_login()

    def _show_login(self):
        from ui.login import LoginFrame
        self._swap_frame(LoginFrame, on_success=self._show_dashboard)

    def _show_dashboard(self):
        from ui.dashboard import DashboardFrame
        self._swap_frame(DashboardFrame, on_logout=self._show_login)

    def _on_close(self):
        try:
            self.ctx.shutdown()
        finally:
            self.root.destroy()

    def run(self):
        self.root.mainloop()


def main():
    app = SecureLockerApp()
    app.run()


if __name__ == "__main__":
    main()
