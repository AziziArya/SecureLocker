"""
ui/login.py

صفحه‌ی Login: تشخیص USB (مستقل از Drive Letter) + Password.
هر دو باید هم‌زمان صحیح باشند - این‌جا واقعاً KeyHierarchy.unlock() فراخوانی
می‌شود که یک اثبات Cryptographic واقعی است، نه صرفاً بررسی رشته.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk, messagebox

from ui.app_context import AppContext
from ui.async_utils import periodic
from ui.recovery_dialog import RecoveryDialog
from ui import theme
from core.key_manager import AuthenticationFailedError
from localization.strings import tr


class LoginFrame(ttk.Frame):
    def __init__(self, parent: tk.Widget, ctx: AppContext, on_success):
        super().__init__(parent, padding=32)
        self.ctx = ctx
        self.on_success = on_success

        ttk.Label(self, text=tr("app.title"), style="Title.TLabel").pack(pady=(20, 4))
        ttk.Label(self, text=tr("app.tagline"), style="Muted.TLabel").pack(pady=(0, 24))

        card_outer, card = theme.make_card(self, padding=24)
        card_outer.pack(pady=8)

        usb_row = ttk.Frame(card, style="Card.TFrame")
        usb_row.pack(fill="x", pady=(0, 12))
        ttk.Label(usb_row, text=tr("login.usb_status"), style="Card.TLabel").pack(side="left")
        self.usb_status_label = ttk.Label(usb_row, text="…", style="Card.TLabel")
        self.usb_status_label.pack(side="left", padx=8)

        ttk.Label(card, text=tr("login.password_label"), style="Card.TLabel").pack(anchor="w")
        self.pw_entry = ttk.Entry(card, show="•", width=32)
        self.pw_entry.pack(anchor="w", pady=(4, 4))
        self.pw_entry.bind("<Return>", lambda e: self._submit())

        self.attempts_label = ttk.Label(card, text="", style="Muted.Card.TLabel")
        self.attempts_label.pack(anchor="w", pady=(0, 12))

        self.submit_btn = ttk.Button(card, text=tr("login.submit"), style="Accent.TButton", command=self._submit)
        self.submit_btn.pack(fill="x", pady=(4, 8))

        forgot_link = ttk.Label(card, text=tr("login.forgot_password"), style="Muted.Card.TLabel", cursor="hand2")
        forgot_link.pack(anchor="w")
        forgot_link.bind("<Button-1>", lambda e: self._open_recovery())

        self._stop_polling = periodic(self, 1000, self._refresh_usb_status)
        self._refresh_usb_status()
        self._update_attempts_label()

    def destroy(self):
        if hasattr(self, "_stop_polling"):
            self._stop_polling()
        super().destroy()

    def _refresh_usb_status(self):
        result = self.ctx.detect_usb()
        if result.status == "MATCHED":
            text, color = tr("login.usb_connected"), theme.status_color("CONNECTED")
        elif result.status == "WRONG_USB":
            text, color = tr("login.usb_wrong"), theme.status_color("WRONG_USB")
        else:
            text, color = tr("login.usb_not_connected"), theme.status_color("NOT_CONNECTED")
        self.usb_status_label.configure(text=text, foreground=color)
        self._last_usb_result = result

    def _update_attempts_label(self):
        remaining = self.ctx.session.remaining_attempts()
        if self.ctx.session.is_locked_out():
            self.attempts_label.configure(text=tr("login.locked_out"), foreground=theme.DANGER)
            self.submit_btn.configure(state="disabled")
        else:
            self.attempts_label.configure(text=tr("login.attempts_remaining", n=remaining))

    def _submit(self):
        if self.ctx.session.is_locked_out():
            return
        self._refresh_usb_status()
        if self._last_usb_result.status != "MATCHED":
            if self._last_usb_result.status == "WRONG_USB":
                messagebox.showerror(tr("common.error"), tr("login.error_wrong_usb"))
            else:
                messagebox.showerror(tr("common.error"), tr("login.error_no_usb"))
            return

        password = self.pw_entry.get()
        usb_info = self._last_usb_result.matched
        key_store = self.ctx.metadata.load_key_store()
        try:
            self.ctx.keys.unlock(password, usb_info.usb_secret, key_store)
        except AuthenticationFailedError:
            self.ctx.session.record_failed_attempt()
            self._update_attempts_label()
            messagebox.showerror(tr("common.error"), tr("login.error_wrong_password"))
            self.pw_entry.delete(0, tk.END)
            return

        self.ctx.set_current_usb(usb_info)
        self.ctx.session.record_successful_attempt()
        self.ctx.wire_after_unlock()
        self.on_success()

    def _open_recovery(self):
        RecoveryDialog(self, self.ctx, on_success=self.on_success)
