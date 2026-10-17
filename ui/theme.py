"""
ui/theme.py

پالت رنگ و استایل Dark Mode حرفه‌ای برای Secure Locker.
هدف: حس یک ابزار امنیتی جدی (مثل BitLocker/VeraCrypt)، نه ظاهر «هکری» با
رنگ سبز نئون و انیمیشن‌های اضافه. رنگ‌ها آرام، خوانا، و دارای hierarchy واضح‌اند.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

# ------------------------------------------------------------------------- Palette
BG_PRIMARY = "#12161c"      # پس‌زمینه‌ی اصلی پنجره
BG_SECONDARY = "#1a2029"    # پس‌زمینه‌ی کارت‌ها/پنل‌ها
BG_TERTIARY = "#222937"     # پس‌زمینه‌ی ورودی‌ها/جدول
BORDER = "#2e3644"

TEXT_PRIMARY = "#e8ebf0"
TEXT_SECONDARY = "#9aa5b5"
TEXT_MUTED = "#6b7688"

ACCENT = "#3b82f6"          # آبی - اکشن‌های اصلی
ACCENT_HOVER = "#2563eb"
SUCCESS = "#22c55e"
WARNING = "#f59e0b"
DANGER = "#ef4444"
DANGER_HOVER = "#dc2626"

FONT_FAMILY = "Segoe UI"    # روی ویندوز موجود؛ fallback خودکار روی سایر سیستم‌عامل‌ها
FONT_FAMILY_MONO = "Consolas"

FONT_TITLE = (FONT_FAMILY, 18, "bold")
FONT_HEADING = (FONT_FAMILY, 13, "bold")
FONT_BODY = (FONT_FAMILY, 10)
FONT_SMALL = (FONT_FAMILY, 9)
FONT_MONO = (FONT_FAMILY_MONO, 10)


def apply_theme(root: tk.Tk) -> None:
    """اعمال تم Dark روی کل برنامه (فراخوانی یک‌بار در main.py)."""
    root.configure(bg=BG_PRIMARY)
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass

    style.configure(".", background=BG_PRIMARY, foreground=TEXT_PRIMARY, font=FONT_BODY)
    style.configure("TFrame", background=BG_PRIMARY)
    style.configure("Card.TFrame", background=BG_SECONDARY)
    style.configure("TLabel", background=BG_PRIMARY, foreground=TEXT_PRIMARY, font=FONT_BODY)
    style.configure("Card.TLabel", background=BG_SECONDARY, foreground=TEXT_PRIMARY)
    style.configure("Title.TLabel", background=BG_PRIMARY, foreground=TEXT_PRIMARY, font=FONT_TITLE)
    style.configure("Heading.TLabel", background=BG_SECONDARY, foreground=TEXT_PRIMARY, font=FONT_HEADING)
    style.configure("Muted.TLabel", background=BG_PRIMARY, foreground=TEXT_MUTED, font=FONT_SMALL)
    style.configure("Muted.Card.TLabel", background=BG_SECONDARY, foreground=TEXT_MUTED, font=FONT_SMALL)
    style.configure("Success.TLabel", background=BG_SECONDARY, foreground=SUCCESS, font=FONT_HEADING)
    style.configure("Warning.TLabel", background=BG_SECONDARY, foreground=WARNING, font=FONT_HEADING)
    style.configure("Danger.TLabel", background=BG_SECONDARY, foreground=DANGER, font=FONT_HEADING)

    style.configure(
        "TButton", background=BG_TERTIARY, foreground=TEXT_PRIMARY,
        font=FONT_BODY, borderwidth=0, focusthickness=0, padding=(14, 8),
    )
    style.map("TButton", background=[("active", BORDER)])

    style.configure(
        "Accent.TButton", background=ACCENT, foreground="#ffffff",
        font=(FONT_FAMILY, 10, "bold"), borderwidth=0, padding=(16, 10),
    )
    style.map("Accent.TButton", background=[("active", ACCENT_HOVER)])

    style.configure(
        "Danger.TButton", background=DANGER, foreground="#ffffff",
        font=(FONT_FAMILY, 10, "bold"), borderwidth=0, padding=(14, 8),
    )
    style.map("Danger.TButton", background=[("active", DANGER_HOVER)])

    style.configure(
        "TEntry", fieldbackground=BG_TERTIARY, foreground=TEXT_PRIMARY,
        borderwidth=1, insertcolor=TEXT_PRIMARY, padding=8,
    )
    style.configure("TCombobox", fieldbackground=BG_TERTIARY, foreground=TEXT_PRIMARY,
                     background=BG_TERTIARY, arrowcolor=TEXT_PRIMARY)
    style.map("TCombobox", fieldbackground=[("readonly", BG_TERTIARY)])

    style.configure("TCheckbutton", background=BG_PRIMARY, foreground=TEXT_PRIMARY, font=FONT_BODY)
    style.map("TCheckbutton", background=[("active", BG_PRIMARY)])
    style.configure("Card.TCheckbutton", background=BG_SECONDARY, foreground=TEXT_PRIMARY, font=FONT_BODY)
    style.map("Card.TCheckbutton", background=[("active", BG_SECONDARY)])

    style.configure("TRadiobutton", background=BG_SECONDARY, foreground=TEXT_PRIMARY, font=FONT_BODY)
    style.map("TRadiobutton", background=[("active", BG_SECONDARY)])

    style.configure(
        "Treeview", background=BG_TERTIARY, fieldbackground=BG_TERTIARY,
        foreground=TEXT_PRIMARY, borderwidth=0, rowheight=28, font=FONT_BODY,
    )
    style.configure("Treeview.Heading", background=BG_SECONDARY, foreground=TEXT_SECONDARY,
                     font=(FONT_FAMILY, 9, "bold"), borderwidth=0)
    style.map("Treeview", background=[("selected", ACCENT)], foreground=[("selected", "#ffffff")])

    style.configure("TProgressbar", background=ACCENT, troughcolor=BG_TERTIARY, borderwidth=0)
    style.configure("TSeparator", background=BORDER)
    style.configure("TNotebook", background=BG_PRIMARY, borderwidth=0)
    style.configure("TNotebook.Tab", background=BG_SECONDARY, foreground=TEXT_SECONDARY,
                     padding=(16, 8), font=FONT_BODY)
    style.map("TNotebook.Tab", background=[("selected", BG_TERTIARY)], foreground=[("selected", TEXT_PRIMARY)])

    style.configure("Vertical.TScrollbar", background=BG_TERTIARY, troughcolor=BG_PRIMARY, borderwidth=0)


def status_color(status: str) -> str:
    """رنگ متناظر برای مقادیر رایج وضعیت (برای Label های وضعیت روی Dashboard)."""
    mapping = {
        "READY": SUCCESS, "OK": SUCCESS, "VERIFIED": SUCCESS, "LOCKED_OK": SUCCESS,
        "CONNECTED": SUCCESS, "MATCHED": SUCCESS,
        "BUSY": WARNING, "PENDING": WARNING, "WARNING": WARNING,
        "ERROR": DANGER, "FAILED": DANGER, "CORRUPTED": DANGER,
        "WRONG_USB": DANGER, "NOT_FOUND": TEXT_MUTED, "NOT_CONNECTED": TEXT_MUTED,
    }
    return mapping.get(status.upper(), TEXT_SECONDARY)


def make_card(parent: tk.Widget, padding: int = 16):
    """یک کارت استاندارد (پس‌زمینه‌ی روشن‌تر، بوردر ملایم) برای Dashboard/Dialogها."""
    outer = tk.Frame(parent, bg=BORDER)
    inner = ttk.Frame(outer, style="Card.TFrame", padding=padding)
    inner.pack(fill="both", expand=True, padx=1, pady=1)
    return outer, inner
