"""
ui/setup_wizard.py

راه‌اندازی اولیه (اجرا می‌شود فقط اگر برنامه هنوز Setup نشده باشد):
    مرحله ۱: انتخاب/ثبت USB
    مرحله ۲: تعیین Password اصلی
    مرحله ۳: تعیین Security Question + Answer
    مرحله ۴: بازبینی و تایید نهایی

هیچ‌چیزی روی دیسک نوشته نمی‌شود مگر در لحظه‌ی «تایید نهایی» (مرحله ۴) - اگر کاربر
وسط راه Cancel کند، هیچ فایل/کلیدی روی سیستم یا USB ایجاد نشده است.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk, messagebox

from core.usb_manager import list_removable_drives, register_new_usb, UsbManagerError
from core.key_manager import KeyHierarchy, setup_security_question
from ui.app_context import AppContext
from ui import theme
from localization.strings import tr


class SetupWizardFrame(ttk.Frame):
    def __init__(self, parent: tk.Widget, ctx: AppContext, on_complete):
        super().__init__(parent, style="TFrame", padding=24)
        self.ctx = ctx
        self.on_complete = on_complete

        # داده‌ی جمع‌آوری‌شده در طول مراحل (چیزی روی دیسک نمی‌رود تا مرحله‌ی آخر)
        self.selected_drive: str | None = None
        self.password: str = ""
        self.question: str = ""
        self.answer: str = ""

        self.step = 0
        self.steps = [self._build_step_usb, self._build_step_password,
                      self._build_step_question, self._build_step_review]

        self.header = ttk.Label(self, text=tr("setup.welcome_title"), style="Title.TLabel")
        self.header.pack(anchor="w", pady=(0, 4))
        self.subheader = ttk.Label(self, text=tr("setup.welcome_body"), style="Muted.TLabel", wraplength=560)
        self.subheader.pack(anchor="w", pady=(0, 20))

        self.body_container = ttk.Frame(self)
        self.body_container.pack(fill="both", expand=True)

        self.nav_frame = ttk.Frame(self)
        self.nav_frame.pack(fill="x", pady=(20, 0))
        self.btn_back = ttk.Button(self.nav_frame, text=tr("common.back"), command=self._go_back)
        self.btn_back.pack(side="left")
        self.btn_next = ttk.Button(self.nav_frame, text=tr("common.next"), style="Accent.TButton", command=self._go_next)
        self.btn_next.pack(side="right")

        self._render_step()

    # ----------------------------------------------------------- Navigation
    def _clear_body(self):
        for w in self.body_container.winfo_children():
            w.destroy()

    def _render_step(self):
        self._clear_body()
        self.btn_back.configure(state="normal" if self.step > 0 else "disabled")
        is_last = self.step == len(self.steps) - 1
        self.btn_next.configure(text=tr("common.finish") if is_last else tr("common.next"))
        self.steps[self.step]()

    def _go_back(self):
        if self.step > 0:
            self.step -= 1
            self._render_step()

    def _go_next(self):
        if not self._validate_current_step():
            return
        if self.step == len(self.steps) - 1:
            self._finish()
            return
        self.step += 1
        self._render_step()

    def _validate_current_step(self) -> bool:
        if self.step == 0:  # USB
            if not self.selected_drive:
                messagebox.showerror(tr("common.error"), tr("setup.usb_no_drives"))
                return False
            return True
        if self.step == 1:  # Password
            pw = self.pw_entry.get()
            pw2 = self.pw2_entry.get()
            if len(pw) < 8:
                messagebox.showerror(tr("common.error"), tr("setup.password_too_short"))
                return False
            if pw != pw2:
                messagebox.showerror(tr("common.error"), tr("setup.password_mismatch"))
                return False
            self.password = pw
            return True
        if self.step == 2:  # Security question
            q = self.q_entry.get().strip()
            a = self.a_entry.get()
            a2 = self.a2_entry.get()
            if not q or not a:
                messagebox.showerror(tr("common.error"), tr("common.error"))
                return False
            if a != a2:
                messagebox.showerror(tr("common.error"), tr("setup.password_mismatch"))
                return False
            self.question = q
            self.answer = a
            return True
        return True

    # ----------------------------------------------------------- Step 1: USB
    def _build_step_usb(self):
        ttk.Label(self.body_container, text=tr("setup.step_usb"), style="Heading.TLabel" if False else "Title.TLabel").pack(anchor="w")
        ttk.Label(self.body_container, text=tr("setup.usb_instruction"), style="Muted.TLabel", wraplength=560).pack(anchor="w", pady=(4, 16))

        row = ttk.Frame(self.body_container)
        row.pack(fill="x", pady=4)
        ttk.Label(row, text=tr("setup.usb_select_drive")).pack(side="left")
        self.drive_var = tk.StringVar(value=self.selected_drive or "")
        self.drive_combo = ttk.Combobox(row, textvariable=self.drive_var, state="readonly", width=30)
        self.drive_combo.pack(side="left", padx=8)
        self.drive_combo.bind("<<ComboboxSelected>>", lambda e: setattr(self, "selected_drive", self.drive_var.get()))

        ttk.Button(row, text=tr("setup.usb_scan"), command=self._scan_drives).pack(side="left", padx=8)
        self._scan_drives()

    def _scan_drives(self):
        drives = list_removable_drives()
        self.drive_combo["values"] = drives
        if drives and not self.selected_drive:
            self.selected_drive = drives[0]
            self.drive_var.set(drives[0])
        elif not drives:
            self.drive_var.set("")
            messagebox.showinfo(tr("common.warning"), tr("setup.usb_no_drives"))

    # ----------------------------------------------------------- Step 2: Password
    def _build_step_password(self):
        ttk.Label(self.body_container, text=tr("setup.step_password"), style="Title.TLabel").pack(anchor="w")
        ttk.Label(self.body_container, text=tr("setup.password_too_short"), style="Muted.TLabel").pack(anchor="w", pady=(4, 16))

        ttk.Label(self.body_container, text=tr("setup.password_new")).pack(anchor="w")
        self.pw_entry = ttk.Entry(self.body_container, show="•", width=40)
        self.pw_entry.pack(anchor="w", pady=(2, 12))
        if self.password:
            self.pw_entry.insert(0, self.password)

        ttk.Label(self.body_container, text=tr("setup.password_confirm")).pack(anchor="w")
        self.pw2_entry = ttk.Entry(self.body_container, show="•", width=40)
        self.pw2_entry.pack(anchor="w", pady=2)
        if self.password:
            self.pw2_entry.insert(0, self.password)

    # ----------------------------------------------------------- Step 3: Security Question
    def _build_step_question(self):
        ttk.Label(self.body_container, text=tr("setup.step_security_question"), style="Title.TLabel").pack(anchor="w")
        ttk.Label(self.body_container, text=tr("setup.security_hint"), style="Muted.TLabel", wraplength=560).pack(anchor="w", pady=(4, 16))

        ttk.Label(self.body_container, text=tr("setup.security_question_label")).pack(anchor="w")
        self.q_entry = ttk.Entry(self.body_container, width=50)
        self.q_entry.pack(anchor="w", pady=(2, 12))
        if self.question:
            self.q_entry.insert(0, self.question)

        ttk.Label(self.body_container, text=tr("setup.security_answer_label")).pack(anchor="w")
        self.a_entry = ttk.Entry(self.body_container, show="•", width=40)
        self.a_entry.pack(anchor="w", pady=(2, 12))

        ttk.Label(self.body_container, text=tr("setup.security_answer_confirm")).pack(anchor="w")
        self.a2_entry = ttk.Entry(self.body_container, show="•", width=40)
        self.a2_entry.pack(anchor="w", pady=2)

    # ----------------------------------------------------------- Step 4: Review
    def _build_step_review(self):
        ttk.Label(self.body_container, text=tr("setup.review_title"), style="Title.TLabel").pack(anchor="w")
        card_outer, card = theme.make_card(self.body_container)
        card_outer.pack(fill="x", pady=16)
        ttk.Label(card, text=tr("setup.review_usb", drive=self.selected_drive), style="Card.TLabel").pack(anchor="w", pady=4)
        ttk.Label(card, text=f"{tr('setup.security_question_label')} {self.question}", style="Card.TLabel").pack(anchor="w", pady=4)

        warn = ttk.Label(self.body_container, text=tr("setup.review_warning"), style="Warning.TLabel", wraplength=560)
        warn.pack(anchor="w", pady=(8, 0))

    # ----------------------------------------------------------- Finish
    def _finish(self):
        try:
            usb_info = register_new_usb(self.selected_drive)
        except (UsbManagerError, OSError) as e:
            messagebox.showerror(tr("common.error"), tr("error.unexpected", detail=str(e)))
            return

        # دیتابیس و تنظیمات را مستقیم روی همین USB می‌سازیم (نه روی لپ‌تاپ) تا کل
        # برنامه - EXE + دیتابیس + تنظیمات + Backup - کاملاً Portable روی فلش بماند.
        self.ctx.bind_to_usb_vault(usb_info)

        mk, key_store = KeyHierarchy.setup_new(self.password, usb_info.usb_secret)
        temp_kh = KeyHierarchy.from_master_key(mk)
        recovery_fields = temp_kh.build_recovery_fields(usb_info.usb_secret, self.answer, key_store)
        key_store.update(recovery_fields)

        self.ctx.metadata.save_key_store(key_store)
        self.ctx.metadata.save_usb_fingerprint(usb_info.fingerprint())
        sq = setup_security_question(self.answer)
        self.ctx.metadata.save_security_question(self.question, sq["answer_salt"], sq["answer_hash"])
        self.ctx.metadata.add_log("SETUP", "راه‌اندازی اولیه با موفقیت انجام شد")

        # بلافاصله کاربر را وارد می‌کنیم (نیازی به Login مجدد نیست)
        self.ctx.keys.unlock(self.password, usb_info.usb_secret, key_store)
        self.ctx.set_current_usb(usb_info)
        self.ctx.session.record_successful_attempt()
        self.ctx.wire_after_unlock()

        messagebox.showinfo(tr("setup.complete_title"), tr("setup.complete_body"))
        self.on_complete()
