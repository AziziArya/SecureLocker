"""
ui/dnd_utils.py

پارس صحیح مسیرهای Drag & Drop از tkinterdnd2.
مشکل نسخه‌ی قبلی: استفاده از split() ساده که با مسیرهای دارای فاصله (خیلی رایج
در ویندوز، مثل "C:\\Users\\Ali Reza\\My Documents\\file.docx") داده را خراب می‌کرد.

فرمت event.data در tkinterdnd2: اگر مسیر فاصله دارد داخل {} قرار می‌گیرد،
در غیر این صورت با فاصله از هم جدا می‌شوند. مثال:
    "{C:/Users/Ali Reza/file.docx} C:/temp/other.txt"
"""

from __future__ import annotations

import re
from typing import List

try:
    from tkinterdnd2 import TkinterDnD, DND_FILES
    HAS_DND = True
except ImportError:
    HAS_DND = False
    TkinterDnD = None  # type: ignore
    DND_FILES = None  # type: ignore


def parse_dnd_paths(raw: str) -> List[str]:
    """
    پارس صحیح رشته‌ی event.data به لیستی از مسیرهای فایل/فولدر.
    مسیرهای داخل {} (شامل فاصله) به‌درستی به‌عنوان یک آیتم واحد شناسایی می‌شوند.
    """
    if not raw:
        return []
    tokens = re.findall(r"\{[^}]*\}|\S+", raw)
    paths = []
    for tok in tokens:
        if tok.startswith("{") and tok.endswith("}"):
            tok = tok[1:-1]
        paths.append(tok)
    return paths
