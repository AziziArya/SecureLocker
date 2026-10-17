"""
ui/backup_manager_ui.py

مدیریت کامل Backup ها: لیست، Verify، حذف (با هشدار)، مشاهده‌ی فایل‌های داخل
هر Backup، حذف Backup های قدیمی، Refresh (هماهنگ‌سازی با آنچه واقعاً روی USB است).
"""

from __future__ import annotations

import os
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog

from ui.app_context import AppContext
from ui import theme
from localization.strings import tr


def _format_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


class BackupManagerDialog(tk.Toplevel):
    def __init__(self, parent: tk.Widget, ctx: AppContext):
        super().__init__(parent)
        self.ctx = ctx
        self.title(tr("backup.title"))
        self.geometry("760x520")
        self.configure(bg=theme.BG_PRIMARY)
        self.transient(parent)
        self.grab_set()

        body = ttk.Frame(self, padding=20)
        body.pack(fill="both", expand=True)

        ttk.Label(body, text=tr("backup.list_header"), style="Title.TLabel").pack(anchor="w", pady=(0, 12))

        columns = ("date", "size", "files", "encrypted", "status")
        self.tree = ttk.Treeview(body, columns=columns, show="headings", height=14)
        headers = {
            "date": tr("backup.col_date"), "size": tr("backup.col_size"),
            "files": tr("backup.col_files"), "encrypted": tr("backup.col_encrypted"),
            "status": tr("backup.col_status"),
        }
        for col in columns:
            self.tree.heading(col, text=headers[col])
            self.tree.column(col, width=130 if col != "status" else 100)
        self.tree.pack(fill="both", expand=True)

        btn_row = ttk.Frame(body)
        btn_row.pack(fill="x", pady=(12, 0))
        ttk.Button(btn_row, text=tr("common.refresh"), command=self._refresh).pack(side="left")
        ttk.Button(btn_row, text=tr("backup.btn_verify"), command=self._verify_selected).pack(side="left", padx=8)
        ttk.Button(btn_row, text=tr("backup.btn_view_files"), command=self._view_files_selected).pack(side="left")
        ttk.Button(btn_row, text=tr("backup.btn_delete_old"), command=self._delete_old).pack(side="left", padx=8)
        ttk.Button(btn_row, text=tr("backup.btn_delete"), style="Danger.TButton", command=self._delete_selected).pack(side="right")

        self.status_label = ttk.Label(body, text="", style="Muted.TLabel")
        self.status_label.pack(anchor="w", pady=(8, 0))

        self._refresh()

    # ----------------------------------------------------------- Data
    def _refresh(self):
        if self.ctx.backup_manager is None:
            return
        report = self.ctx.backup_manager.refresh()
        self._load_list()
        if "error" not in report and (report.get("missing", 0) > 0):
            self.status_label.configure(
                text=f"{report['missing']} backup(s) missing on USB", foreground=theme.WARNING,
            )
        else:
            self.status_label.configure(text="")

    def _load_list(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        for b in self.ctx.backup_manager.list_backups():
            status_key = {"OK": "backup.status_ok", "CORRUPTED": "backup.status_corrupted",
                          "MISSING_ON_USB": "backup.status_missing"}.get(b.status, b.status)
            self.tree.insert("", "end", iid=b.backup_id, values=(
                b.created_at[:19], _format_size(b.total_size), b.file_count,
                tr("common.yes") if b.encrypted else tr("common.no"), tr(status_key),
            ))

    def _selected_id(self) -> str | None:
        sel = self.tree.selection()
        return sel[0] if sel else None

    # ----------------------------------------------------------- Actions
    def _verify_selected(self):
        bid = self._selected_id()
        if not bid:
            return
        ok, detail = self.ctx.backup_manager.verify_backup(bid)
        if ok:
            messagebox.showinfo(tr("common.success"), tr("backup.verify_result_ok"))
        else:
            messagebox.showerror(tr("common.error"), tr("backup.verify_result_fail", detail=detail))
        self._load_list()

    def _view_files_selected(self):
        bid = self._selected_id()
        if not bid:
            return
        try:
            entries = self.ctx.backup_manager.get_backup_file_list(bid)
        except Exception as e:
            messagebox.showerror(tr("common.error"), tr("error.unexpected", detail=str(e)))
            return

        win = tk.Toplevel(self)
        win.title(tr("backup.btn_view_files"))
        win.configure(bg=theme.BG_PRIMARY)
        win.geometry("500x400")
        listbox = tk.Listbox(win, bg=theme.BG_TERTIARY, fg=theme.TEXT_PRIMARY, borderwidth=0)
        listbox.pack(fill="both", expand=True, padx=16, pady=16)
        for e in entries:
            size_txt = _format_size(e["size"])
            listbox.insert(tk.END, f"{e['original_path']}  ({size_txt})")

    def _delete_selected(self):
        bid = self._selected_id()
        if not bid:
            return
        referenced = self.ctx.backup_manager.is_backup_referenced_by_active_files(bid)
        msg_key = "backup.confirm_delete_referenced" if referenced else "backup.confirm_delete"
        if not messagebox.askyesno(tr("common.warning"), tr(msg_key)):
            return
        self.ctx.backup_manager.delete_backup(bid)
        self._load_list()

    def _delete_old(self):
        n = simpledialog.askinteger(
            tr("backup.btn_delete_old"),
            tr("backup.btn_delete_old") + " - " + tr("common.ok"),
            minvalue=0, initialvalue=3, parent=self,
        )
        if n is None:
            return
        count = self.ctx.backup_manager.delete_old_backups(n)
        messagebox.showinfo(tr("common.success"), f"{count} backup(s) deleted")
        self._load_list()
