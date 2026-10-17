"""
ui/settings.py

تنظیمات برنامه: زبان، Auto Logout، محدودیت تلاش اشتباه، رفتار پیش‌فرض Backup،
تغییر Password، تغییر Security Question.

نکته: تغییر زبان بلافاصله روی صفحات از قبل بازشده اعمال نمی‌شود (چون متن ویجت‌های
Tkinter در لحظه‌ی ساخت تنظیم می‌شود)؛ صفحات بعدی (Dashboard/Dialogها) که دوباره
باز شوند زبان جدید را نشان می‌دهند. این محدودیت در خود دیالوگ به کاربر گفته می‌شود.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk, messagebox

from core.key_manager import AuthenticationFailedError, setup_security_question
from config import AUTO_LOGOUT_OPTIONS
from ui.app_context import AppContext
from ui import theme
from localization.strings import tr, set_language


class SettingsDialog(tk.Toplevel):
    def __init__(self, parent: tk.Widget, ctx: AppContext, on_saved):
        super().__init__(parent)
        self.ctx = ctx
        self.on_saved = on_saved
        self.title(tr("settings.title"))
        self.geometry("560x520")
        self.configure(bg=theme.BG_PRIMARY)
        self.transient(parent)
        self.grab_set()

        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=16, pady=16)

        self.tab_general = ttk.Frame(notebook, padding=16)
        self.tab_security = ttk.Frame(notebook, padding=16)
        self.tab_backup = ttk.Frame(notebook, padding=16)
        notebook.add(self.tab_general, text=tr("settings.tab_general"))
        notebook.add(self.tab_security, text=tr("settings.tab_security"))
        notebook.add(self.tab_backup, text=tr("settings.tab_backup"))

        self._build_general_tab()
        self._build_security_tab()
        self._build_backup_tab()

        btn_row = ttk.Frame(self, padding=(16, 0, 16, 16))
        btn_row.pack(fill="x")
        ttk.Button(btn_row, text=tr("common.cancel"), command=self.destroy).pack(side="left")
        ttk.Button(btn_row, text=tr("common.save"), style="Accent.TButton", command=self._save).pack(side="right")

    # ----------------------------------------------------------- General
    def _build_general_tab(self):
        cfg = self.ctx.config
        ttk.Label(self.tab_general, text=tr("settings.language")).grid(row=0, column=0, sticky="w", pady=6)
        self.lang_var = tk.StringVar(value=cfg.language)
        lang_combo = ttk.Combobox(self.tab_general, textvariable=self.lang_var, state="readonly",
                                   values=["fa", "en"], width=10)
        lang_combo.grid(row=0, column=1, sticky="w", padx=8)

        ttk.Label(self.tab_general, text=tr("settings.auto_logout")).grid(row=1, column=0, sticky="w", pady=6)
        self.logout_var = tk.StringVar(value=cfg.auto_logout_choice)
        logout_combo = ttk.Combobox(self.tab_general, textvariable=self.logout_var, state="readonly",
                                     values=AUTO_LOGOUT_OPTIONS, width=10)
        logout_combo.grid(row=1, column=1, sticky="w", padx=8)

        ttk.Label(self.tab_general, text=tr("settings.max_attempts")).grid(row=2, column=0, sticky="w", pady=6)
        self.attempts_var = tk.IntVar(value=cfg.max_wrong_attempts)
        ttk.Spinbox(self.tab_general, from_=1, to=20, textvariable=self.attempts_var, width=8).grid(
            row=2, column=1, sticky="w", padx=8
        )

        ttk.Label(self.tab_general, text=tr("settings.default_backup_behavior")).grid(row=3, column=0, sticky="w", pady=(14, 4))
        self.always_ask_var = tk.BooleanVar(value=cfg.always_ask_protection_options)
        ttk.Checkbutton(self.tab_general, text=tr("settings.ask_backup_names"), variable=self.always_ask_var).grid(
            row=4, column=0, columnspan=2, sticky="w"
        )

    # ----------------------------------------------------------- Security
    def _build_security_tab(self):
        ttk.Button(self.tab_security, text=tr("settings.change_password"), command=self._open_change_password).pack(
            fill="x", pady=6
        )
        ttk.Button(self.tab_security, text=tr("settings.change_security_question"),
                   command=self._open_change_security_question).pack(fill="x", pady=6)

    def _open_change_password(self):
        ChangePasswordDialog(self, self.ctx)

    def _open_change_security_question(self):
        ChangeSecurityQuestionDialog(self, self.ctx)

    # ----------------------------------------------------------- Backup
    def _build_backup_tab(self):
        cfg = self.ctx.config
        self.backup_requested_var = tk.BooleanVar(value=cfg.default_backup_requested)
        ttk.Checkbutton(self.tab_backup, text=tr("lock.backup_and_lock"), variable=self.backup_requested_var).pack(
            anchor="w", pady=6
        )
        self.encrypt_backup_var = tk.BooleanVar(value=cfg.default_encrypt_backup)
        ttk.Checkbutton(self.tab_backup, text=tr("backup.encrypt_setting"), variable=self.encrypt_backup_var).pack(
            anchor="w", pady=6
        )

    # ----------------------------------------------------------- Save
    def _save(self):
        cfg = self.ctx.config
        cfg.language = self.lang_var.get()
        cfg.auto_logout_choice = self.logout_var.get()
        cfg.max_wrong_attempts = self.attempts_var.get()
        cfg.always_ask_protection_options = self.always_ask_var.get()
        cfg.default_backup_requested = self.backup_requested_var.get()
        cfg.default_encrypt_backup = self.encrypt_backup_var.get()

        self.ctx.apply_config()
        messagebox.showinfo(tr("common.success"), tr("settings.saved"))
        self.destroy()
        self.on_saved()


class ChangePasswordDialog(tk.Toplevel):
    def __init__(self, parent: tk.Widget, ctx: AppContext):
        super().__init__(parent)
        self.ctx = ctx
        self.title(tr("pwchange.title"))
        self.configure(bg=theme.BG_PRIMARY)
        self.transient(parent)
        self.grab_set()
        self.resizable(False, False)

        body = ttk.Frame(self, padding=20)
        body.pack(fill="both", expand=True)

        ttk.Label(body, text=tr("pwchange.current")).pack(anchor="w")
        self.current_entry = ttk.Entry(body, show="•", width=32)
        self.current_entry.pack(anchor="w", pady=(2, 10))

        ttk.Label(body, text=tr("pwchange.new")).pack(anchor="w")
        self.new_entry = ttk.Entry(body, show="•", width=32)
        self.new_entry.pack(anchor="w", pady=(2, 10))

        ttk.Label(body, text=tr("pwchange.confirm")).pack(anchor="w")
        self.confirm_entry = ttk.Entry(body, show="•", width=32)
        self.confirm_entry.pack(anchor="w", pady=(2, 16))

        btn_row = ttk.Frame(body)
        btn_row.pack(fill="x")
        ttk.Button(btn_row, text=tr("common.cancel"), command=self.destroy).pack(side="left")
        ttk.Button(btn_row, text=tr("common.save"), style="Accent.TButton", command=self._submit).pack(side="right")

    def _submit(self):
        current = self.current_entry.get()
        new = self.new_entry.get()
        confirm = self.confirm_entry.get()
        if len(new) < 8:
            messagebox.showerror(tr("common.error"), tr("setup.password_too_short"))
            return
        if new != confirm:
            messagebox.showerror(tr("common.error"), tr("setup.password_mismatch"))
            return

        try:
            usb_info = self.ctx.get_current_usb()
        except Exception:
            messagebox.showerror(tr("common.error"), tr("pwchange.usb_required"))
            return

        key_store = self.ctx.metadata.load_key_store()
        try:
            new_key_store = self.ctx.keys.change_password(current, new, usb_info.usb_secret, key_store)
        except AuthenticationFailedError:
            messagebox.showerror(tr("common.error"), tr("pwchange.wrong_current"))
            return

        self.ctx.metadata.save_key_store(new_key_store)
        self.ctx.metadata.add_log("PASSWORD_CHANGE", "کاربر رمز عبور را از Settings تغییر داد")
        messagebox.showinfo(tr("common.success"), tr("pwchange.success"))
        self.destroy()


class ChangeSecurityQuestionDialog(tk.Toplevel):
    def __init__(self, parent: tk.Widget, ctx: AppContext):
        super().__init__(parent)
        self.ctx = ctx
        self.title(tr("settings.change_security_question"))
        self.configure(bg=theme.BG_PRIMARY)
        self.transient(parent)
        self.grab_set()
        self.resizable(False, False)

        body = ttk.Frame(self, padding=20)
        body.pack(fill="both", expand=True)

        ttk.Label(body, text=tr("setup.security_question_label")).pack(anchor="w")
        self.q_entry = ttk.Entry(body, width=40)
        self.q_entry.pack(anchor="w", pady=(2, 10))

        ttk.Label(body, text=tr("setup.security_answer_label")).pack(anchor="w")
        self.a_entry = ttk.Entry(body, show="•", width=32)
        self.a_entry.pack(anchor="w", pady=(2, 10))

        ttk.Label(body, text=tr("setup.security_answer_confirm")).pack(anchor="w")
        self.a2_entry = ttk.Entry(body, show="•", width=32)
        self.a2_entry.pack(anchor="w", pady=(2, 16))

        btn_row = ttk.Frame(body)
        btn_row.pack(fill="x")
        ttk.Button(btn_row, text=tr("common.cancel"), command=self.destroy).pack(side="left")
        ttk.Button(btn_row, text=tr("common.save"), style="Accent.TButton", command=self._submit).pack(side="right")

    def _submit(self):
        q = self.q_entry.get().strip()
        a = self.a_entry.get()
        a2 = self.a2_entry.get()
        if not q or not a:
            messagebox.showerror(tr("common.error"), tr("common.error"))
            return
        if a != a2:
            messagebox.showerror(tr("common.error"), tr("setup.password_mismatch"))
            return

        try:
            usb_info = self.ctx.get_current_usb()
        except Exception:
            messagebox.showerror(tr("common.error"), tr("pwchange.usb_required"))
            return

        key_store = self.ctx.metadata.load_key_store()
        recovery_fields = self.ctx.keys.build_recovery_fields(usb_info.usb_secret, a, key_store)
        key_store.update(recovery_fields)
        self.ctx.metadata.save_key_store(key_store)

        sq = setup_security_question(a)
        self.ctx.metadata.save_security_question(q, sq["answer_salt"], sq["answer_hash"])
        self.ctx.metadata.add_log("SECURITY_SETTINGS_CHANGE", "سوال امنیتی تغییر کرد")

        messagebox.showinfo(tr("common.success"), tr("pwchange.success"))
        self.destroy()
