"""
ui/lock_dialog.py

جریان کامل تعاملی Lock:
    انتخاب فایل/فولدر (Browse/Drag&Drop/Paste) -> سوال Backup -> سوال محافظت
    نام فایل -> سوال محافظت ساختار فولدر -> تایید نهایی (+ Emergency Lock) ->
    Progress -> نتیجه (LOCK COMPLETED)

طبق قانون طلایی بخش ۷ درخواست: اگر کاربر Backup را انتخاب کند و Backup ناموفق
شود، هیچ فایلی قفل نمی‌شود - این‌جا صرفاً UI است؛ تصمیم واقعی و Fail-Safe در
core/file_engine.py + core/backup_manager.py گرفته می‌شود.
"""

from __future__ import annotations

import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from core.file_engine import LockOptions
from ui.app_context import AppContext
from ui.async_utils import run_in_background
from ui.dnd_utils import HAS_DND, DND_FILES, parse_dnd_paths
from ui import theme
from localization.strings import tr


class LockDialog(tk.Toplevel):
    def __init__(self, parent: tk.Widget, ctx: AppContext, on_done):
        super().__init__(parent)
        self.ctx = ctx
        self.on_done = on_done
        self.title(tr("lock.title"))
        self.geometry("640x520")
        self.configure(bg=theme.BG_PRIMARY)
        self.transient(parent)
        self.grab_set()

        self.selected_paths: list[str] = []
        self.backup_requested: bool = self.ctx.config.default_backup_requested
        self.protect_names: bool = self.ctx.config.default_protect_names
        self.protect_structure: bool = self.ctx.config.default_protect_structure
        self.emergency_lock: bool = self.ctx.config.emergency_lock_default

        self.step = 0
        self.body = ttk.Frame(self, padding=20)
        self.body.pack(fill="both", expand=True)
        self._render_step()

    # ----------------------------------------------------------- Navigation helpers
    def _clear(self):
        for w in self.body.winfo_children():
            w.destroy()

    def _render_step(self):
        self._clear()
        renderers = {
            0: self._render_select_items,
            1: self._render_ask_backup,
            2: self._render_ask_names,
            3: self._render_ask_structure,
            4: self._render_confirm,
        }
        renderers[self.step]()

    # ============================================================= Step 0: Select items
    def _render_select_items(self):
        ttk.Label(self.body, text=tr("lock.select_items"), style="Title.TLabel").pack(anchor="w", pady=(0, 12))

        btn_row = ttk.Frame(self.body)
        btn_row.pack(fill="x", pady=(0, 8))
        ttk.Button(btn_row, text=tr("lock.add_files"), command=self._add_files).pack(side="left", padx=(0, 8))
        ttk.Button(btn_row, text=tr("lock.add_folder"), command=self._add_folder).pack(side="left")

        drop_outer, drop_inner = theme.make_card(self.body, padding=20)
        drop_outer.pack(fill="x", pady=8)
        drop_text = tr("lock.drop_hint") if HAS_DND else tr("lock.select_items")
        ttk.Label(drop_inner, text=drop_text, style="Muted.Card.TLabel").pack()
        if HAS_DND:
            try:
                drop_inner.drop_target_register(DND_FILES)
                drop_inner.dnd_bind("<<Drop>>", self._on_drop)
            except tk.TclError:
                pass  # اگر root از نوع TkinterDnD.Tk نباشد، DnD بی‌صدا غیرفعال می‌ماند

        list_frame = ttk.Frame(self.body)
        list_frame.pack(fill="both", expand=True, pady=8)
        self.listbox = tk.Listbox(
            list_frame, bg=theme.BG_TERTIARY, fg=theme.TEXT_PRIMARY,
            selectbackground=theme.ACCENT, borderwidth=0, highlightthickness=0,
        )
        self.listbox.pack(side="left", fill="both", expand=True)
        scrollbar = ttk.Scrollbar(list_frame, command=self.listbox.yview)
        scrollbar.pack(side="right", fill="y")
        self.listbox.configure(yscrollcommand=scrollbar.set)
        self._refresh_listbox()

        remove_row = ttk.Frame(self.body)
        remove_row.pack(fill="x")
        ttk.Button(remove_row, text=tr("common.remove"), command=self._remove_selected).pack(side="left")
        self.count_label = ttk.Label(remove_row, text="", style="Muted.TLabel")
        self.count_label.pack(side="right")
        self._update_count_label()

        nav_row = ttk.Frame(self.body)
        nav_row.pack(fill="x", pady=(12, 0))
        ttk.Button(nav_row, text=tr("common.cancel"), command=self.destroy).pack(side="left")
        ttk.Button(nav_row, text=tr("common.next"), style="Accent.TButton", command=self._next_from_select).pack(side="right")

    def _add_files(self):
        paths = filedialog.askopenfilenames(parent=self)
        self._add_paths(paths)

    def _add_folder(self):
        path = filedialog.askdirectory(parent=self)
        if path:
            self._add_paths([path])

    def _on_drop(self, event):
        paths = parse_dnd_paths(event.data)
        self._add_paths(paths)

    def _add_paths(self, paths):
        for p in paths:
            if p and os.path.exists(p) and p not in self.selected_paths:
                self.selected_paths.append(p)
        self._refresh_listbox()
        self._update_count_label()

    def _remove_selected(self):
        sel = list(self.listbox.curselection())
        for idx in reversed(sel):
            del self.selected_paths[idx]
        self._refresh_listbox()
        self._update_count_label()

    def _refresh_listbox(self):
        self.listbox.delete(0, tk.END)
        for p in self.selected_paths:
            self.listbox.insert(tk.END, p)

    def _update_count_label(self):
        self.count_label.configure(text=tr("lock.selected_items", n=len(self.selected_paths)))

    def _next_from_select(self):
        if not self.selected_paths:
            messagebox.showerror(tr("common.error"), tr("unlock.no_items_selected"))
            return
        self.step = 1
        self._render_step()

    def _skip_protection_questions_if_configured(self):
        """
        اگر کاربر در Settings گفته «همیشه سوال نشود»، مستقیماً از مقادیر پیش‌فرض
        Settings استفاده می‌کنیم و کاربر را مستقیم به تایید نهایی می‌بریم.
        سوال Backup همیشه پرسیده می‌شود (ایمنی مهم‌تر از راحتی است) - این تنظیم
        فقط روی سوالات نام/ساختار اثر دارد.
        """
        if not self.ctx.config.always_ask_protection_options:
            self.protect_names = self.ctx.config.default_protect_names
            self.protect_structure = self.ctx.config.default_protect_structure
            if self.protect_structure:
                self.protect_names = True
            self.step = 4
            self._render_step()
            return True
        return False

    # ============================================================= Step 1: Backup?
    def _render_ask_backup(self):
        ttk.Label(self.body, text=tr("lock.ask_backup_title"), style="Title.TLabel").pack(anchor="w", pady=(0, 8))
        ttk.Label(self.body, text=tr("lock.ask_backup_body"), style="Muted.TLabel", wraplength=560).pack(anchor="w", pady=(0, 24))

        ttk.Button(self.body, text=tr("lock.backup_and_lock"), style="Accent.TButton",
                   command=lambda: self._choose_backup(True)).pack(fill="x", pady=6)
        ttk.Button(self.body, text=tr("lock.lock_without_backup"),
                   command=lambda: self._choose_backup(False)).pack(fill="x", pady=6)

        ttk.Button(self.body, text=tr("common.back"), command=self._go_back).pack(anchor="w", pady=(24, 0))

    def _choose_backup(self, backup: bool):
        if not backup:
            if not messagebox.askyesno(tr("common.warning"), tr("lock.confirm_no_backup")):
                return
        self.backup_requested = backup
        if self._skip_protection_questions_if_configured():
            return
        self.step = 2
        self._render_step()

    # ============================================================= Step 2: Protect names?
    def _render_ask_names(self):
        ttk.Label(self.body, text=tr("lock.ask_protect_names"), style="Title.TLabel").pack(anchor="w", pady=(0, 8))
        ttk.Label(self.body, text=tr("lock.protect_names_hint"), style="Muted.TLabel", wraplength=560).pack(anchor="w", pady=(0, 24))

        row = ttk.Frame(self.body)
        row.pack(fill="x")
        ttk.Button(row, text=tr("common.yes"), style="Accent.TButton",
                   command=lambda: self._choose_names(True)).pack(side="left", fill="x", expand=True, padx=(0, 6))
        ttk.Button(row, text=tr("common.no"),
                   command=lambda: self._choose_names(False)).pack(side="left", fill="x", expand=True, padx=(6, 0))

        ttk.Button(self.body, text=tr("common.back"), command=self._go_back).pack(anchor="w", pady=(24, 0))

    def _choose_names(self, protect: bool):
        self.protect_names = protect
        self.step = 3
        self._render_step()

    # ============================================================= Step 3: Protect structure?
    def _render_ask_structure(self):
        ttk.Label(self.body, text=tr("lock.ask_protect_structure"), style="Title.TLabel").pack(anchor="w", pady=(0, 8))
        ttk.Label(self.body, text=tr("lock.protect_structure_hint"), style="Muted.TLabel", wraplength=560).pack(anchor="w", pady=(0, 24))

        row = ttk.Frame(self.body)
        row.pack(fill="x")
        ttk.Button(row, text=tr("common.yes"), style="Accent.TButton",
                   command=lambda: self._choose_structure(True)).pack(side="left", fill="x", expand=True, padx=(0, 6))
        ttk.Button(row, text=tr("common.no"),
                   command=lambda: self._choose_structure(False)).pack(side="left", fill="x", expand=True, padx=(6, 0))

        ttk.Button(self.body, text=tr("common.back"), command=self._go_back).pack(anchor="w", pady=(24, 0))

    def _choose_structure(self, protect: bool):
        self.protect_structure = protect
        if protect:
            self.protect_names = True  # الزام معماری - هماهنگ با LockOptions.__post_init__
        self.step = 4
        self._render_step()

    # ============================================================= Step 4: Confirm
    def _render_confirm(self):
        ttk.Label(self.body, text=tr("lock.confirm_title"), style="Title.TLabel").pack(anchor="w", pady=(0, 12))
        ttk.Label(self.body, text=tr("lock.confirm_body", n=len(self.selected_paths)), wraplength=560).pack(anchor="w", pady=(0, 16))

        card_outer, card = theme.make_card(self.body)
        card_outer.pack(fill="x", pady=8)
        backup_txt = tr("lock.backup_and_lock") if self.backup_requested else tr("lock.lock_without_backup")
        names_txt = tr("lock.status_protected") if self.protect_names else tr("lock.status_original")
        struct_txt = tr("lock.status_protected") if self.protect_structure else tr("lock.status_original")
        ttk.Label(card, text=f"Backup: {backup_txt}", style="Card.TLabel").pack(anchor="w", pady=2)
        ttk.Label(card, text=f"{tr('lock.ask_protect_names')} {names_txt}", style="Card.TLabel").pack(anchor="w", pady=2)
        ttk.Label(card, text=f"{tr('lock.ask_protect_structure')} {struct_txt}", style="Card.TLabel").pack(anchor="w", pady=2)

        self.emergency_var = tk.BooleanVar(value=self.emergency_lock)
        ttk.Checkbutton(self.body, text=tr("lock.emergency_lock_option"), variable=self.emergency_var).pack(anchor="w", pady=(12, 0))

        nav_row = ttk.Frame(self.body)
        nav_row.pack(fill="x", pady=(24, 0))
        ttk.Button(nav_row, text=tr("common.back"), command=self._go_back).pack(side="left")
        ttk.Button(nav_row, text=tr("dashboard.btn_lock"), style="Accent.TButton", command=self._start_lock).pack(side="right")

    def _go_back(self):
        self.step -= 1
        self._render_step()

    # ============================================================= Execution
    def _start_lock(self):
        self.emergency_lock = self.emergency_var.get()
        options = LockOptions(
            backup_requested=self.backup_requested,
            protect_names=self.protect_names,
            protect_structure=self.protect_structure,
            emergency_lock=self.emergency_lock,
        )
        self._render_progress()

        def task(progress_cb):
            def cb(name, done, total, idx, total_files):
                progress_cb({"name": name, "done": done, "total": total, "idx": idx, "total_files": total_files})
            return self.ctx.file_engine.lock_paths(self.selected_paths, options, progress_cb=cb)

        start = run_in_background(
            self, task,
            on_success=self._on_lock_success,
            on_error=self._on_lock_error,
            on_progress=self._on_lock_progress,
        )
        start()

    def _render_progress(self):
        self._clear()
        ttk.Label(self.body, text=tr("lock.progress_title"), style="Title.TLabel").pack(anchor="w", pady=(0, 16))
        self.progress_file_label = ttk.Label(self.body, text="", style="Muted.TLabel")
        self.progress_file_label.pack(anchor="w")
        self.progress_count_label = ttk.Label(self.body, text="", style="Muted.TLabel")
        self.progress_count_label.pack(anchor="w", pady=(0, 12))
        self.progress_bar = ttk.Progressbar(self.body, mode="determinate", maximum=100)
        self.progress_bar.pack(fill="x")

    def _on_lock_progress(self, payload):
        name = os.path.basename(payload["name"])
        self.progress_file_label.configure(text=tr("lock.progress_current_file", name=name))
        self.progress_count_label.configure(
            text=tr("lock.progress_count", done=payload["idx"] + 1, total=payload["total_files"])
        )
        if payload["total"] > 0:
            pct = (payload["done"] / payload["total"]) * 100
            self.progress_bar["value"] = pct

    def _on_lock_error(self, exc: Exception):
        messagebox.showerror(tr("common.error"), tr("error.unexpected", detail=str(exc)))
        self.destroy()

    def _on_lock_success(self, result):
        self._render_result(result)

    # ============================================================= Result
    def _render_result(self, result):
        self._clear()
        if result.aborted:
            ttk.Label(self.body, text=tr("lock.aborted_title"), style="Danger.TLabel").pack(anchor="w", pady=(0, 12))
            reason = result.abort_reason or tr("lock.aborted_backup_failed")
            ttk.Label(self.body, text=reason, wraplength=560).pack(anchor="w", pady=(0, 16))
            if result.results:
                ttk.Label(self.body, text=tr("lock.already_locked_hint"), style="Muted.TLabel").pack(anchor="w")
                for r in result.results:
                    ttk.Label(self.body, text=f"  • {os.path.basename(r.original_path)}", style="Muted.TLabel").pack(anchor="w")
            ttk.Button(self.body, text=tr("common.close"), style="Accent.TButton", command=self._finish).pack(anchor="e", pady=(24, 0))
            return

        ttk.Label(self.body, text=tr("lock.result_title"), style="Success.TLabel" if False else "Title.TLabel").pack(anchor="w", pady=(0, 12))

        card_outer, card = theme.make_card(self.body)
        card_outer.pack(fill="x", pady=8)
        ttk.Label(card, text=tr("lock.result_success", n=result.success_count), style="Card.TLabel").pack(anchor="w", pady=2)
        ttk.Label(card, text=tr("lock.result_failed", n=result.failed_count), style="Card.TLabel").pack(anchor="w", pady=2)
        ttk.Label(card, text=tr("lock.result_skipped", n=result.skipped_count), style="Card.TLabel").pack(anchor="w", pady=2)

        backup_status_key = {
            "VERIFIED": "lock.status_verified", "NOT_REQUESTED": "lock.status_not_requested",
            "FAILED": "lock.status_failed",
        }.get(result.backup_status, "lock.status_not_requested")
        ttk.Label(card, text=tr("lock.result_backup", status=tr(backup_status_key)), style="Card.TLabel").pack(anchor="w", pady=(8, 2))
        names_txt = tr("lock.status_protected") if result.names_protected else tr("lock.status_original")
        struct_txt = tr("lock.status_protected") if result.structure_protected else tr("lock.status_original")
        ttk.Label(card, text=tr("lock.result_names", status=names_txt), style="Card.TLabel").pack(anchor="w", pady=2)
        ttk.Label(card, text=tr("lock.result_structure", status=struct_txt), style="Card.TLabel").pack(anchor="w", pady=2)

        failed_items = [r for r in result.results if not r.success and not r.skipped]
        if failed_items:
            ttk.Label(self.body, text=tr("lock.result_failed", n=len(failed_items)), style="Danger.TLabel").pack(anchor="w", pady=(12, 4))
            for r in failed_items:
                ttk.Label(self.body, text=f"  • {os.path.basename(r.original_path)}: {r.error}", style="Muted.TLabel", wraplength=560).pack(anchor="w")

        ttk.Button(self.body, text=tr("common.close"), style="Accent.TButton", command=self._finish).pack(anchor="e", pady=(24, 0))

    def _finish(self):
        self.destroy()
        self.on_done()
