"""
ui/unlock_dialog.py

جریان کامل تعاملی Unlock:
    انتخاب فایل‌های قفل‌شده (لیست از دیتابیس) -> تایید -> Progress (با پرسش
    تعاملی Conflict در صورت وجود فایل مقصد قبلی) -> نتیجه (با پیشنهاد Restore
    از Backup برای فایل‌های خراب/دستکاری‌شده در صورت وجود نسخه‌ی معتبر).

نکته‌ی فنی مهم: core.file_engine.unlock_files در یک Thread پس‌زمینه اجرا می‌شود
اما conflict_resolver باید از همان Thread، همزمان با پردازش، به کاربر (روی
Main Thread) سوال بپرسد و منتظر پاسخ بماند. این با یک Event همگام‌سازی می‌شود:
Worker Thread پیام "conflict" را از طریق صف پیشرفت می‌فرستد و منتظر می‌ماند؛
Main Thread دیالوگ را نمایش می‌دهد و بعد از پاسخ کاربر، Event را آزاد می‌کند.
"""

from __future__ import annotations

import os
import threading
import tkinter as tk
from tkinter import ttk, messagebox

from ui.app_context import AppContext
from ui.async_utils import run_in_background
from ui import theme
from localization.strings import tr


class ConflictDialog(tk.Toplevel):
    """دیالوگ مودال کوچک برای تصمیم‌گیری درباره‌ی تعارض نام هنگام Unlock."""

    def __init__(self, parent: tk.Widget, target_path: str):
        super().__init__(parent)
        self.title(tr("unlock.conflict_title"))
        self.configure(bg=theme.BG_PRIMARY)
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        self.result: str = "SKIP"
        self.remember = tk.BooleanVar(value=False)

        body = ttk.Frame(self, padding=20)
        body.pack(fill="both", expand=True)
        ttk.Label(body, text=tr("unlock.conflict_body", path=target_path), wraplength=420).pack(anchor="w", pady=(0, 16))

        for label_key, action in [
            ("unlock.conflict_replace", "REPLACE"),
            ("unlock.conflict_keep_both", "KEEP_BOTH"),
            ("unlock.conflict_rename", "RENAME"),
            ("unlock.conflict_skip", "SKIP"),
        ]:
            ttk.Button(body, text=tr(label_key), command=lambda a=action: self._choose(a)).pack(fill="x", pady=3)

        ttk.Checkbutton(body, text=tr("unlock.apply_to_all"), variable=self.remember).pack(anchor="w", pady=(10, 6))
        ttk.Button(body, text=tr("unlock.conflict_abort"), style="Danger.TButton",
                   command=lambda: self._choose("ABORT")).pack(fill="x", pady=(6, 0))

        self.protocol("WM_DELETE_WINDOW", lambda: self._choose("SKIP"))

    def _choose(self, action: str):
        self.result = action
        self.destroy()


class UnlockDialog(tk.Toplevel):
    def __init__(self, parent: tk.Widget, ctx: AppContext, on_done):
        super().__init__(parent)
        self.ctx = ctx
        self.on_done = on_done
        self.title(tr("unlock.title"))
        self.geometry("680x520")
        self.configure(bg=theme.BG_PRIMARY)
        self.transient(parent)
        self.grab_set()

        self._remembered_action: str | None = None
        self.body = ttk.Frame(self, padding=20)
        self.body.pack(fill="both", expand=True)
        self._render_select()

    def _clear(self):
        for w in self.body.winfo_children():
            w.destroy()

    # ============================================================= Step 0: Select
    def _render_select(self):
        ttk.Label(self.body, text=tr("unlock.select_locked"), style="Title.TLabel").pack(anchor="w", pady=(0, 12))

        columns = ("path", "size", "date")
        self.tree = ttk.Treeview(self.body, columns=columns, show="headings", selectmode="extended", height=14)
        for col, width in zip(columns, (380, 100, 160)):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=width)
        self.tree.pack(fill="both", expand=True)

        self.locked_records = self.ctx.metadata.list_locked_files(status="LOCKED")
        for rec in self.locked_records:
            size_kb = f"{rec.size_original / 1024:.1f} KB"
            self.tree.insert("", "end", iid=rec.file_id, values=(rec.current_disk_path, size_kb, rec.locked_at[:19]))

        btn_row = ttk.Frame(self.body)
        btn_row.pack(fill="x", pady=8)
        ttk.Button(btn_row, text=tr("unlock.select_all"), command=self._select_all).pack(side="left")
        ttk.Button(btn_row, text=tr("unlock.deselect_all"), command=self._deselect_all).pack(side="left", padx=8)

        nav_row = ttk.Frame(self.body)
        nav_row.pack(fill="x", pady=(12, 0))
        ttk.Button(nav_row, text=tr("common.cancel"), command=self.destroy).pack(side="left")
        ttk.Button(nav_row, text=tr("common.next"), style="Accent.TButton", command=self._confirm_selection).pack(side="right")

    def _select_all(self):
        self.tree.selection_set(self.tree.get_children())

    def _deselect_all(self):
        self.tree.selection_remove(self.tree.get_children())

    def _confirm_selection(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showerror(tr("common.error"), tr("unlock.no_items_selected"))
            return
        self.selected_file_ids = list(selected)
        self._render_confirm()

    # ============================================================= Step 1: Confirm
    def _render_confirm(self):
        self._clear()
        ttk.Label(self.body, text=tr("unlock.confirm_title"), style="Title.TLabel").pack(anchor="w", pady=(0, 12))
        ttk.Label(self.body, text=tr("unlock.confirm_body", n=len(self.selected_file_ids)), wraplength=560).pack(anchor="w")

        nav_row = ttk.Frame(self.body)
        nav_row.pack(fill="x", pady=(24, 0))
        ttk.Button(nav_row, text=tr("common.back"), command=self._render_select).pack(side="left")
        ttk.Button(nav_row, text=tr("dashboard.btn_unlock"), style="Accent.TButton", command=self._start_unlock).pack(side="right")

    # ============================================================= Execution
    def _start_unlock(self):
        self._render_progress()
        self._remembered_action = None

        def conflict_resolver(target_path: str) -> str:
            if self._remembered_action is not None:
                return self._remembered_action
            event = threading.Event()
            answer_box = {"action": "SKIP", "remember": False}

            def ask_on_main_thread():
                dlg = ConflictDialog(self, target_path)
                self.wait_window(dlg)
                answer_box["action"] = dlg.result
                answer_box["remember"] = dlg.remember.get()
                event.set()

            self._pending_ui_calls.append(ask_on_main_thread)
            event.wait()
            if answer_box["remember"]:
                self._remembered_action = answer_box["action"]
            return answer_box["action"]

        self._pending_ui_calls: list = []

        def task(progress_cb):
            def cb(file_id, done, total, idx, total_files):
                progress_cb({"file_id": file_id, "done": done, "total": total, "idx": idx, "total_files": total_files})
            return self.ctx.file_engine.unlock_files(
                self.selected_file_ids, conflict_resolver=conflict_resolver, progress_cb=cb,
            )

        start = run_in_background(
            self, task,
            on_success=self._on_unlock_success,
            on_error=self._on_unlock_error,
            on_progress=self._on_unlock_progress,
        )
        start()
        self._poll_pending_ui_calls()

    def _poll_pending_ui_calls(self):
        """
        بررسی دوره‌ای برای درخواست‌های نمایش دیالوگ Conflict که از Worker Thread
        رسیده‌اند (چون آن Thread نمی‌تواند مستقیم ویجت بسازد). این‌ها روی Main
        Thread (همین حلقه‌ی after) واقعاً اجرا می‌شوند.
        """
        if hasattr(self, "_pending_ui_calls"):
            while self._pending_ui_calls:
                call = self._pending_ui_calls.pop(0)
                call()
        if self.winfo_exists():
            self.after(100, self._poll_pending_ui_calls)

    def _render_progress(self):
        self._clear()
        ttk.Label(self.body, text=tr("unlock.progress_title"), style="Title.TLabel").pack(anchor="w", pady=(0, 16))
        self.progress_label = ttk.Label(self.body, text="", style="Muted.TLabel")
        self.progress_label.pack(anchor="w")
        self.progress_bar = ttk.Progressbar(self.body, mode="determinate", maximum=100)
        self.progress_bar.pack(fill="x", pady=(8, 0))

    def _on_unlock_progress(self, payload):
        self.progress_label.configure(
            text=tr("lock.progress_count", done=payload["idx"] + 1, total=payload["total_files"])
        )
        if payload["total"] > 0:
            self.progress_bar["value"] = (payload["done"] / payload["total"]) * 100

    def _on_unlock_error(self, exc: Exception):
        messagebox.showerror(tr("common.error"), tr("error.unexpected", detail=str(exc)))
        self.destroy()

    def _on_unlock_success(self, result):
        self._last_result = result
        self._render_result(result)

    # ============================================================= Result
    def _render_result(self, result):
        self._clear()
        ttk.Label(self.body, text=tr("unlock.result_title"), style="Title.TLabel").pack(anchor="w", pady=(0, 12))

        card_outer, card = theme.make_card(self.body)
        card_outer.pack(fill="x", pady=8)
        ttk.Label(card, text=tr("unlock.result_success", n=result.success_count), style="Card.TLabel").pack(anchor="w", pady=2)
        ttk.Label(card, text=tr("unlock.result_failed", n=result.failed_count), style="Card.TLabel").pack(anchor="w", pady=2)

        failed = [r for r in result.results if not r.success]
        if failed:
            scroll_frame = ttk.Frame(self.body)
            scroll_frame.pack(fill="both", expand=True, pady=(12, 0))
            for r in failed:
                self._render_failed_row(scroll_frame, r)

        ttk.Button(self.body, text=tr("common.close"), style="Accent.TButton", command=self._finish).pack(anchor="e", pady=(16, 0))

    def _render_failed_row(self, parent, r):
        row_outer, row = theme.make_card(parent, padding=10)
        row_outer.pack(fill="x", pady=4)
        ttk.Label(row, text=f"{r.file_id[:8]}...: {r.error}", style="Card.TLabel", wraplength=480).pack(anchor="w")

        backup_id = self.ctx.backup_manager.find_valid_backup_for_file(r.file_id) if self.ctx.backup_manager else None
        if backup_id:
            btn_row = ttk.Frame(row, style="Card.TFrame")
            btn_row.pack(anchor="w", pady=(6, 0))
            ttk.Label(btn_row, text=tr("unlock.corrupted_body", name=r.file_id[:8]), style="Muted.Card.TLabel",
                      wraplength=420).pack(anchor="w", pady=(0, 4))
            ttk.Button(btn_row, text=tr("unlock.restore_from_backup"),
                       command=lambda: self._restore_from_backup(r.file_id, backup_id, row)).pack(anchor="w")
        else:
            ttk.Label(row, text=tr("unlock.corrupted_no_backup", name=r.file_id[:8]), style="Muted.Card.TLabel",
                      wraplength=420).pack(anchor="w", pady=(6, 0))

    def _restore_from_backup(self, file_id: str, backup_id: str, row_widget):
        dest_path = self.ctx.backup_manager.get_original_path_for_file(file_id)
        if not dest_path:
            messagebox.showerror(tr("common.error"), tr("error.unexpected", detail="path not found"))
            return
        ok = self.ctx.file_engine.restore_corrupted_from_backup(file_id, backup_id, dest_path)
        if ok:
            messagebox.showinfo(tr("common.success"), tr("recovery.done") if False else tr("common.success"))
            for w in row_widget.winfo_children():
                w.destroy()
            ttk.Label(row_widget, text=f"✓ {dest_path}", style="Success.TLabel" if False else "Card.TLabel").pack(anchor="w")
        else:
            messagebox.showerror(tr("common.error"), tr("error.unexpected", detail="restore failed"))

    def _finish(self):
        self.destroy()
        self.on_done()
