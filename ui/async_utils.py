"""
ui/async_utils.py

اجرای عملیات سنگین (Lock/Unlock/Backup) در یک Thread جدا تا GUI فریز نشود،
اما بدون این‌که آن Thread هرگز مستقیماً ویجت‌های Tkinter را تغییر دهد
(که باعث race condition/crash می‌شود). تمام برگشت به UI از طریق root.after()
روی Main Thread انجام می‌شود.
"""

from __future__ import annotations

import queue
import threading
import tkinter as tk
from typing import Any, Callable, Optional


def run_in_background(
    root: tk.Misc,
    task: Callable[..., Any],
    on_success: Optional[Callable[[Any], None]] = None,
    on_error: Optional[Callable[[Exception], None]] = None,
    on_progress: Optional[Callable[[Any], None]] = None,
    poll_ms: int = 80,
) -> Callable[[], None]:
    """
    task را در یک Thread پس‌زمینه اجرا می‌کند. task یک آرگومان progress_cb می‌گیرد
    که هر بار فراخوانی شود، مقدارش (thread-safe از طریق صف) به on_progress
    (روی Main Thread) می‌رسد.

    خروجی: تابعی که برای *شروع* عملیات باید فراخوانی شود.
    """
    result_queue: "queue.Queue[tuple[str, Any]]" = queue.Queue()

    def progress_cb(*args, **kwargs):
        payload = args if len(args) != 1 else args[0]
        result_queue.put(("progress", payload))

    def worker():
        try:
            result = task(progress_cb)
            result_queue.put(("success", result))
        except Exception as e:  # noqa: BLE001 - هر خطایی باید به UI گزارش شود
            result_queue.put(("error", e))

    def poll():
        try:
            while True:
                kind, payload = result_queue.get_nowait()
                if kind == "progress" and on_progress:
                    on_progress(payload)
                elif kind == "success":
                    if on_success:
                        on_success(payload)
                    return
                elif kind == "error":
                    if on_error:
                        on_error(payload)
                    return
        except queue.Empty:
            pass
        root.after(poll_ms, poll)

    def start():
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        root.after(poll_ms, poll)

    return start


def periodic(root: tk.Misc, interval_ms: int, callback: Callable[[], None]) -> Callable[[], None]:
    """
    اجرای یک callback هر interval_ms میلی‌ثانیه (برای Auto Logout polling، بررسی
    وضعیت USB و ...). یک تابع stop برمی‌گرداند که واقعاً after-id فعلی را لغو
    می‌کند (نه فقط یک flag که چک شود) - چون بعد از destroy شدن ویجت، Tcl ممکن
    است بخواهد یک after زمان‌بندی‌شده‌ی قدیمی را روی چیزی که دیگر وجود ندارد
    اجرا کند و خطای "invalid command name" بدهد.
    """
    state = {"stopped": False, "after_id": None}

    def loop():
        if state["stopped"]:
            return
        callback()
        if not state["stopped"]:
            state["after_id"] = root.after(interval_ms, loop)

    state["after_id"] = root.after(interval_ms, loop)

    def stop():
        state["stopped"] = True
        if state["after_id"] is not None:
            try:
                root.after_cancel(state["after_id"])
            except (tk.TclError, ValueError):
                pass
            state["after_id"] = None

    return stop

    return stop
