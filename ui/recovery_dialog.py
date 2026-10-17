"""
ui/recovery_dialog.py

مسیر «رمز عبور را فراموش کرده‌ام». نیازمند USB اصلی + پاسخ صحیح سوال امنیتی
(هر دو با هم). موفقیت یعنی Master Key واقعاً باز شده - سپس کاربر Password جدید
تعیین می‌کند و بلافاصله وارد Dashboard می‌شود.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk, messagebox

from core.key_manager import KeyHierarchy
from core.recovery import PasswordRecoveryManager
from ui.app_context import AppContext
from localization.strings import tr


class RecoveryDialog(tk.Toplevel):
    def __init__(self, parent: tk.Widget, ctx: AppContext, on_success):
        super().__init__(parent)
        self.ctx = ctx
        self.on_success = on_success
        self.title(tr("recovery.title"))
        self.configure(bg="#12161c")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        self._tmp_kh: KeyHierarchy | None = None
        self._usb_secret: bytes | None = None

        self.body = ttk.Frame(self, padding=24)
        self.body.pack(fill="both", expand=True)
        self._render_question_step()

    def _clear(self):
        for w in self.body.winfo_children():
            w.destroy()

    def _render_question_step(self):
        self._clear()
        prm = PasswordRecoveryManager(self.ctx.metadata, KeyHierarchy())
        question = prm.get_question()
        if not question:
            ttk.Label(self.body, text=tr("recovery.not_configured")).pack(pady=8)
            ttk.Button(self.body, text=tr("common.close"), command=self.destroy).pack(pady=8)
            return

        ttk.Label(self.body, text=tr("recovery.usb_required"), style="Muted.TLabel", wraplength=380).pack(anchor="w", pady=(0, 12))
        ttk.Label(self.body, text=question, style="Heading.TLabel" if False else None).pack(anchor="w", pady=(0, 4))
        ttk.Label(self.body, text=tr("recovery.answer_label")).pack(anchor="w")
        self.answer_entry = ttk.Entry(self.body, show="•", width=36)
        self.answer_entry.pack(anchor="w", pady=(2, 16))

        btn_row = ttk.Frame(self.body)
        btn_row.pack(fill="x")
        ttk.Button(btn_row, text=tr("common.cancel"), command=self.destroy).pack(side="left")
        ttk.Button(btn_row, text=tr("recovery.submit"), style="Accent.TButton", command=self._submit_answer).pack(side="right")

    def _submit_answer(self):
        answer = self.answer_entry.get()
        usb_result = self.ctx.detect_usb()
        if usb_result.status != "MATCHED":
            messagebox.showerror(tr("common.error"), tr("recovery.wrong_answer"))
            return

        tmp_kh = KeyHierarchy()
        prm = PasswordRecoveryManager(self.ctx.metadata, tmp_kh)
        ok = prm.attempt_recovery(answer, usb_result.matched.usb_secret)
        if not ok:
            messagebox.showerror(tr("common.error"), tr("recovery.wrong_answer"))
            return

        self._tmp_kh = tmp_kh
        self._usb_secret = usb_result.matched.usb_secret
        self._matched_usb = usb_result.matched
        self._render_new_password_step()

    def _render_new_password_step(self):
        self._clear()
        ttk.Label(self.body, text=tr("recovery.success"), style="Success.TLabel" if False else None, wraplength=380).pack(anchor="w", pady=(0, 12))
        ttk.Label(self.body, text=tr("recovery.new_password")).pack(anchor="w")
        self.pw_entry = ttk.Entry(self.body, show="•", width=36)
        self.pw_entry.pack(anchor="w", pady=(2, 12))
        ttk.Label(self.body, text=tr("recovery.new_password_confirm")).pack(anchor="w")
        self.pw2_entry = ttk.Entry(self.body, show="•", width=36)
        self.pw2_entry.pack(anchor="w", pady=(2, 16))

        btn_row = ttk.Frame(self.body)
        btn_row.pack(fill="x")
        ttk.Button(btn_row, text=tr("common.cancel"), command=self.destroy).pack(side="left")
        ttk.Button(btn_row, text=tr("common.finish"), style="Accent.TButton", command=self._submit_new_password).pack(side="right")

    def _submit_new_password(self):
        pw = self.pw_entry.get()
        pw2 = self.pw2_entry.get()
        if len(pw) < 8:
            messagebox.showerror(tr("common.error"), tr("setup.password_too_short"))
            return
        if pw != pw2:
            messagebox.showerror(tr("common.error"), tr("setup.password_mismatch"))
            return

        prm = PasswordRecoveryManager(self.ctx.metadata, self._tmp_kh)
        prm.complete_recovery_with_new_password(pw, self._usb_secret)

        # ورود عادی با Password جدید روی ctx.keys اصلی (تا وضعیت برنامه یکدست بماند)
        new_key_store = self.ctx.metadata.load_key_store()
        self.ctx.keys.unlock(pw, self._usb_secret, new_key_store)
        self.ctx.set_current_usb(self._matched_usb)
        self.ctx.session.record_successful_attempt()
        self.ctx.wire_after_unlock()

        messagebox.showinfo(tr("common.success"), tr("recovery.done"))
        self.destroy()
        self.on_success()
