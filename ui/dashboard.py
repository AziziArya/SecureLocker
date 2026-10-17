"""
ui/dashboard.py

صفحه‌ی اصلی بعد از Login. وضعیت USB، وضعیت سیستم، آمار فایل‌های محافظت‌شده،
و دسترسی به تمام عملیات (Lock/Unlock/Backup Manager/Logs/Settings).

همچنین بلافاصله بعد از ورود، یک اسکن Crash Recovery اجرا می‌کند (بخش ۲۲) و در
صورت پیدا شدن عملیات نیمه‌کاره‌ی قبلی، به کاربر اطلاع می‌دهد.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk, messagebox

from ui.app_context import AppContext
from ui.async_utils import periodic
from ui import theme
from localization.strings import tr


class DashboardFrame(ttk.Frame):
    def __init__(self, parent: tk.Widget, ctx: AppContext, on_logout):
        super().__init__(parent, padding=20)
        self.ctx = ctx
        self.on_logout = on_logout

        self._build_header()
        self._build_status_row()
        self._build_actions_row()
        self._build_files_list()

        self._db_lost = False
        self._stop_usb_poll = periodic(self, 1500, self._safe_refresh_usb_status)
        self._stop_logout_poll = periodic(self, 2000, self._safe_check_auto_logout)

        self._crash_check_after_id = self.after(200, self._run_crash_recovery_check)
        self.refresh_all()

    def destroy(self):
        if hasattr(self, "_stop_usb_poll"):
            self._stop_usb_poll()
        if hasattr(self, "_stop_logout_poll"):
            self._stop_logout_poll()
        if hasattr(self, "_crash_check_after_id"):
            try:
                self.after_cancel(self._crash_check_after_id)
            except (tk.TclError, ValueError):
                pass
        super().destroy()

    # ----------------------------------------------------------- Header
    def _build_header(self):
        row = ttk.Frame(self)
        row.pack(fill="x", pady=(0, 16))
        ttk.Label(row, text=tr("app.title"), style="Title.TLabel").pack(side="left")
        ttk.Button(row, text=tr("dashboard.btn_logout"), command=self._logout).pack(side="right")
        ttk.Button(row, text=tr("dashboard.btn_settings"), command=self._open_settings).pack(side="right", padx=8)
        ttk.Button(row, text=tr("dashboard.btn_logs"), command=self._open_logs).pack(side="right")

    # ----------------------------------------------------------- Status cards
    def _build_status_row(self):
        row = ttk.Frame(self)
        row.pack(fill="x", pady=(0, 16))

        self.usb_card, self.usb_card_inner = self._status_card(row, tr("dashboard.usb_key"))
        self.usb_value_label = ttk.Label(self.usb_card_inner, text="…", style="Heading.TLabel")
        self.usb_value_label.pack(anchor="w")

        self.status_card, self.status_card_inner = self._status_card(row, tr("dashboard.system_status"))
        self.status_value_label = ttk.Label(self.status_card_inner, text=tr("dashboard.status_ready"), style="Success.TLabel")
        self.status_value_label.pack(anchor="w")

        self.count_card, self.count_card_inner = self._status_card(row, tr("dashboard.protected_files"))
        self.count_value_label = ttk.Label(self.count_card_inner, text="0", style="Heading.TLabel")
        self.count_value_label.pack(anchor="w")

        self.backup_card, self.backup_card_inner = self._status_card(row, tr("dashboard.backup_status"))
        self.backup_value_label = ttk.Label(self.backup_card_inner, text="-", style="Heading.TLabel")
        self.backup_value_label.pack(anchor="w")

    def _status_card(self, parent, title):
        outer, inner = theme.make_card(parent, padding=14)
        outer.pack(side="left", fill="both", expand=True, padx=(0, 10))
        ttk.Label(inner, text=title, style="Muted.Card.TLabel").pack(anchor="w", pady=(0, 4))
        return outer, inner

    # ----------------------------------------------------------- Actions
    def _build_actions_row(self):
        row = ttk.Frame(self)
        row.pack(fill="x", pady=(0, 16))
        ttk.Button(row, text=tr("dashboard.btn_lock"), style="Accent.TButton", command=self._open_lock).pack(side="left", padx=(0, 8))
        ttk.Button(row, text=tr("dashboard.btn_unlock"), command=self._open_unlock).pack(side="left", padx=8)
        ttk.Button(row, text=tr("dashboard.btn_backup_manager"), command=self._open_backup_manager).pack(side="left", padx=8)

    # ----------------------------------------------------------- Files list
    def _build_files_list(self):
        ttk.Label(self, text=tr("dashboard.locked_files_list"), style="Heading.TLabel" if False else None).pack(anchor="w", pady=(4, 6))
        columns = ("name", "size", "date", "status")
        self.tree = ttk.Treeview(self, columns=columns, show="headings", height=12)
        for col, width in zip(columns, (300, 100, 160, 100)):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=width, anchor="w")
        self.tree.pack(fill="both", expand=True)

    # ----------------------------------------------------------- Refresh logic
    def refresh_all(self):
        try:
            self._refresh_usb_status()
            self._refresh_stats()
            self._refresh_files_list()
        except Exception as e:
            self._handle_db_lost(e)

    def _safe_refresh_usb_status(self):
        """نسخه‌ی محافظت‌شده برای periodic polling - چون حالا دیتابیس هم روی USB
        است، اگر فلش وسط کار بیرون کشیده شود، عملیات DB ممکن است خطا بدهد. این‌جا
        به‌جای crash خام، پیام واضح نشان داده و ادامه‌ی polling متوقف می‌شود."""
        if self._db_lost:
            return
        try:
            self._refresh_usb_status()
        except Exception as e:
            self._handle_db_lost(e)

    def _safe_check_auto_logout(self):
        if self._db_lost:
            return
        try:
            self._check_auto_logout()
        except Exception as e:
            self._handle_db_lost(e)

    def _handle_db_lost(self, error: Exception):
        if self._db_lost:
            return
        self._db_lost = True
        messagebox.showerror(
            tr("common.error"),
            "دسترسی به فلش (و دیتابیس روی آن) قطع شد. لطفاً فلش را دوباره وصل کرده و "
            "برنامه را ببندید و مجدد اجرا کنید تا وضعیت به‌درستی بازیابی شود.\n\n"
            f"جزئیات فنی: {error}",
        )

    def _refresh_usb_status(self):
        result = self.ctx.detect_usb()
        if result.status == "MATCHED":
            self.usb_value_label.configure(text=tr("login.usb_connected"), foreground=theme.status_color("CONNECTED"))
        elif result.status == "WRONG_USB":
            self.usb_value_label.configure(text=tr("login.usb_wrong"), foreground=theme.status_color("WRONG_USB"))
        else:
            self.usb_value_label.configure(text=tr("login.usb_not_connected"), foreground=theme.status_color("NOT_CONNECTED"))

    def _refresh_stats(self):
        locked = self.ctx.metadata.list_locked_files(status="LOCKED")
        self.count_value_label.configure(text=str(len(locked)))
        backups = self.ctx.metadata.list_backups()
        ok_backups = sum(1 for b in backups if b.status == "OK")
        self.backup_value_label.configure(text=f"{ok_backups}/{len(backups)}" if backups else "-")

    def _refresh_files_list(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        for rec in self.ctx.metadata.list_locked_files(status="LOCKED"):
            size_kb = f"{rec.size_original / 1024:.1f} KB"
            self.tree.insert("", "end", iid=rec.file_id, values=(
                rec.current_disk_path, size_kb, rec.locked_at[:19], rec.status,
            ))
        if not self.ctx.metadata.list_locked_files(status="LOCKED"):
            pass  # tree خالی می‌ماند؛ نمایش پیام خالی در نسخه‌ی تعاملی نهایی UI انجام می‌شود

    # ----------------------------------------------------------- Crash recovery notice
    def _run_crash_recovery_check(self):
        if self.ctx.crash_recovery is None:
            return
        report = self.ctx.crash_recovery.run_startup_scan()
        if report.temp_files_cleaned:
            messagebox.showwarning(
                tr("common.warning"),
                tr("dashboard.crash_recovery_notice", n=len(report.temp_files_cleaned)),
            )
            self.refresh_all()

    # ----------------------------------------------------------- Auto logout
    def _check_auto_logout(self):
        if self.ctx.session.should_auto_logout():
            self._logout(auto=True)

    def _on_activity(self, event=None):
        self.ctx.session.touch_activity()

    # ----------------------------------------------------------- Actions handlers
    def _open_lock(self):
        self.ctx.session.touch_activity()
        from ui.lock_dialog import LockDialog
        LockDialog(self, self.ctx, on_done=self.refresh_all)

    def _open_unlock(self):
        self.ctx.session.touch_activity()
        from ui.unlock_dialog import UnlockDialog
        UnlockDialog(self, self.ctx, on_done=self.refresh_all)

    def _open_backup_manager(self):
        self.ctx.session.touch_activity()
        from ui.backup_manager_ui import BackupManagerDialog
        BackupManagerDialog(self, self.ctx)

    def _open_settings(self):
        self.ctx.session.touch_activity()
        from ui.settings import SettingsDialog
        SettingsDialog(self, self.ctx, on_saved=self.refresh_all)

    def _open_logs(self):
        self.ctx.session.touch_activity()
        from ui.log_viewer import LogViewerDialog
        LogViewerDialog(self, self.ctx)

    def _logout(self, auto: bool = False):
        self.ctx.logout()
        if auto:
            messagebox.showinfo(tr("common.warning"), tr("login.title"))
        self.on_logout()
