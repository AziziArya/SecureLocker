"""
ui/log_viewer.py

مشاهده‌ی کامل Logها: جستجو، فیلتر بر اساس نوع/سطح، Export، Clear.
یادآوری امنیتی: core/metadata.py هرگز Password/Secret/Key را لاگ نمی‌کند؛
این Viewer صرفاً همان رکوردهای امن ذخیره‌شده را نمایش می‌دهد.
"""

from __future__ import annotations

import csv
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from ui.app_context import AppContext
from ui import theme
from localization.strings import tr

EVENT_TYPES = [
    "LOGIN", "FAILED_LOGIN", "LOGOUT", "LOCK", "UNLOCK", "BACKUP", "RESTORE",
    "RECOVERY", "PASSWORD_CHANGE", "SECURITY_SETTINGS_CHANGE", "SETUP",
    "INTEGRITY_FAILURE", "CRASH_RECOVERY",
]
SEVERITIES = ["INFO", "WARNING", "ERROR", "CRITICAL"]


class LogViewerDialog(tk.Toplevel):
    def __init__(self, parent: tk.Widget, ctx: AppContext):
        super().__init__(parent)
        self.ctx = ctx
        self.title(tr("logs.title"))
        self.geometry("880x560")
        self.configure(bg=theme.BG_PRIMARY)
        self.transient(parent)
        self.grab_set()

        body = ttk.Frame(self, padding=16)
        body.pack(fill="both", expand=True)

        filter_row = ttk.Frame(body)
        filter_row.pack(fill="x", pady=(0, 12))

        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(filter_row, textvariable=self.search_var, width=24)
        search_entry.pack(side="left")
        search_entry.insert(0, "")
        search_entry.bind("<KeyRelease>", lambda e: self._reload())
        ttk.Label(filter_row, text=tr("logs.search")).pack(side="left", padx=(4, 12))

        ttk.Label(filter_row, text=tr("logs.filter_type")).pack(side="left")
        self.type_var = tk.StringVar(value=tr("logs.filter_all"))
        type_combo = ttk.Combobox(filter_row, textvariable=self.type_var, state="readonly",
                                   values=[tr("logs.filter_all")] + EVENT_TYPES, width=20)
        type_combo.pack(side="left", padx=(4, 12))
        type_combo.bind("<<ComboboxSelected>>", lambda e: self._reload())

        ttk.Label(filter_row, text=tr("logs.filter_severity")).pack(side="left")
        self.severity_var = tk.StringVar(value=tr("logs.filter_all"))
        sev_combo = ttk.Combobox(filter_row, textvariable=self.severity_var, state="readonly",
                                  values=[tr("logs.filter_all")] + SEVERITIES, width=12)
        sev_combo.pack(side="left", padx=4)
        sev_combo.bind("<<ComboboxSelected>>", lambda e: self._reload())

        columns = ("time", "type", "severity", "message")
        self.tree = ttk.Treeview(body, columns=columns, show="headings", height=18)
        headers = {"time": tr("logs.col_time"), "type": tr("logs.col_type"),
                   "severity": tr("logs.col_severity"), "message": tr("logs.col_message")}
        widths = {"time": 160, "type": 130, "severity": 90, "message": 420}
        for col in columns:
            self.tree.heading(col, text=headers[col])
            self.tree.column(col, width=widths[col], anchor="w")
        self.tree.pack(fill="both", expand=True)

        btn_row = ttk.Frame(body)
        btn_row.pack(fill="x", pady=(12, 0))
        ttk.Button(btn_row, text=tr("common.refresh"), command=self._reload).pack(side="left")
        ttk.Button(btn_row, text=tr("logs.btn_export"), command=self._export).pack(side="left", padx=8)
        ttk.Button(btn_row, text=tr("logs.btn_clear"), style="Danger.TButton", command=self._clear).pack(side="right")

        self._reload()

    def _current_filters(self):
        event_type = self.type_var.get()
        severity = self.severity_var.get()
        search = self.search_var.get().strip()
        return (
            None if event_type == tr("logs.filter_all") else event_type,
            None if severity == tr("logs.filter_all") else severity,
            search or None,
        )

    def _reload(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        event_type, severity, search = self._current_filters()
        logs = self.ctx.metadata.query_logs(event_type=event_type, severity=severity, search_text=search)
        for row in logs:
            self.tree.insert("", "end", values=(row["timestamp"][:19], row["event_type"], row["severity"], row["message"]))

    def _export(self):
        path = filedialog.asksaveasfilename(
            parent=self, defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("Text", "*.txt")],
        )
        if not path:
            return
        event_type, severity, search = self._current_filters()
        logs = self.ctx.metadata.query_logs(event_type=event_type, severity=severity, search_text=search, limit=100000)
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "event_type", "severity", "message"])
            for row in logs:
                writer.writerow([row["timestamp"], row["event_type"], row["severity"], row["message"]])
        messagebox.showinfo(tr("common.success"), tr("logs.export_success", path=path))

    def _clear(self):
        if not messagebox.askyesno(tr("common.warning"), tr("logs.confirm_clear")):
            return
        self.ctx.metadata.clear_logs()
        self._reload()
