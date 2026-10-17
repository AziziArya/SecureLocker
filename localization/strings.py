"""
localization/strings.py

تمام متن‌های قابل‌مشاهده توسط کاربر از این‌جا می‌آیند - هیچ رشته‌ی hardcoded
پراکنده‌ای در کد UI وجود ندارد. زبان از طریق Settings قابل تغییر است.

استفاده:
    from localization.strings import tr
    tr("dashboard.title")            # -> "قفل‌کننده امن" یا "Secure Locker"
    tr("lock.confirm", count=3)      # پشتیبانی از جای‌گذاری متغیر با .format()
"""

from __future__ import annotations

CURRENT_LANG = "fa"  # پیش‌فرض؛ توسط core/config.py در startup بازنویسی می‌شود

STRINGS: dict[str, dict[str, str]] = {
    # ============================================================= عمومی
    "app.title": {"fa": "قفل‌کننده امن (Secure Locker)", "en": "Secure Locker"},
    "app.tagline": {"fa": "محافظت رمزنگاری‌شده از فایل‌های شخصی", "en": "Cryptographic protection for your personal files"},
    "common.ok": {"fa": "تایید", "en": "OK"},
    "common.cancel": {"fa": "انصراف", "en": "Cancel"},
    "common.yes": {"fa": "بله", "en": "Yes"},
    "common.no": {"fa": "خیر", "en": "No"},
    "common.close": {"fa": "بستن", "en": "Close"},
    "common.back": {"fa": "بازگشت", "en": "Back"},
    "common.next": {"fa": "بعدی", "en": "Next"},
    "common.finish": {"fa": "پایان", "en": "Finish"},
    "common.browse": {"fa": "انتخاب...", "en": "Browse..."},
    "common.refresh": {"fa": "به‌روزرسانی", "en": "Refresh"},
    "common.delete": {"fa": "حذف", "en": "Delete"},
    "common.save": {"fa": "ذخیره", "en": "Save"},
    "common.error": {"fa": "خطا", "en": "Error"},
    "common.warning": {"fa": "هشدار", "en": "Warning"},
    "common.success": {"fa": "موفق", "en": "Success"},
    "common.loading": {"fa": "در حال پردازش...", "en": "Processing..."},
    "common.retry": {"fa": "تلاش مجدد", "en": "Retry"},
    "common.skip": {"fa": "رد کردن", "en": "Skip"},
    "common.remove": {"fa": "حذف", "en": "Remove"},
    "common.password": {"fa": "رمز عبور", "en": "Password"},
    "common.show": {"fa": "نمایش", "en": "Show"},
    "common.hide": {"fa": "مخفی", "en": "Hide"},

    # ============================================================= Setup Wizard
    "setup.welcome_title": {"fa": "به قفل‌کننده امن خوش آمدید", "en": "Welcome to Secure Locker"},
    "setup.welcome_body": {
        "fa": "برای شروع، باید یک USB به‌عنوان کلید اصلی، یک رمز عبور، و یک سوال امنیتی تعیین کنید.",
        "en": "To get started, you'll set up a USB key, a master password, and a security question.",
    },
    "setup.step_usb": {"fa": "مرحله ۱: انتخاب USB", "en": "Step 1: Choose USB Key"},
    "setup.usb_instruction": {
        "fa": "فلش USB خود را وصل کنید. این فلش از این پس «کلید اصلی» برنامه خواهد بود.",
        "en": "Insert your USB flash drive. It will become the master key for this application.",
    },
    "setup.usb_select_drive": {"fa": "انتخاب درایو USB:", "en": "Select USB drive:"},
    "setup.usb_no_drives": {"fa": "هیچ درایو Removable ای پیدا نشد", "en": "No removable drives found"},
    "setup.usb_scan": {"fa": "اسکن مجدد درایوها", "en": "Rescan drives"},
    "setup.step_password": {"fa": "مرحله ۲: رمز عبور اصلی", "en": "Step 2: Master Password"},
    "setup.password_new": {"fa": "رمز عبور جدید:", "en": "New password:"},
    "setup.password_confirm": {"fa": "تکرار رمز عبور:", "en": "Confirm password:"},
    "setup.password_mismatch": {"fa": "رمزهای عبور مطابقت ندارند", "en": "Passwords do not match"},
    "setup.password_too_short": {"fa": "رمز عبور باید حداقل ۸ کاراکتر باشد", "en": "Password must be at least 8 characters"},
    "setup.step_security_question": {"fa": "مرحله ۳: سوال امنیتی", "en": "Step 3: Security Question"},
    "setup.security_question_label": {"fa": "سوال امنیتی خود را بنویسید:", "en": "Write your security question:"},
    "setup.security_answer_label": {"fa": "پاسخ:", "en": "Answer:"},
    "setup.security_answer_confirm": {"fa": "تکرار پاسخ:", "en": "Confirm answer:"},
    "setup.security_hint": {
        "fa": "این سوال تنها راه بازیابی رمز عبور در صورت فراموشی است. آن را با دقت انتخاب کنید.",
        "en": "This question is the only way to recover your password if forgotten. Choose it carefully.",
    },
    "setup.review_title": {"fa": "مرحله ۴: بازبینی و تایید", "en": "Step 4: Review & Confirm"},
    "setup.review_usb": {"fa": "USB انتخاب‌شده: {drive}", "en": "Selected USB: {drive}"},
    "setup.review_warning": {
        "fa": "بدون این USB و این رمز عبور، هیچ فایلی قابل بازیابی نخواهد بود. لطفاً از فلش خود مراقبت کنید.",
        "en": "Without this USB and this password, no file will be recoverable. Please keep your USB safe.",
    },
    "setup.complete_title": {"fa": "راه‌اندازی کامل شد", "en": "Setup Complete"},
    "setup.complete_body": {"fa": "برنامه آماده استفاده است.", "en": "Secure Locker is ready to use."},

    # ============================================================= Login
    "login.title": {"fa": "ورود", "en": "Login"},
    "login.usb_status": {"fa": "وضعیت USB:", "en": "USB Status:"},
    "login.usb_connected": {"fa": "متصل ✓", "en": "Connected ✓"},
    "login.usb_not_connected": {"fa": "متصل نیست", "en": "Not Connected"},
    "login.usb_wrong": {"fa": "USB نادرست است ✗", "en": "Wrong USB ✗"},
    "login.password_label": {"fa": "رمز عبور:", "en": "Password:"},
    "login.submit": {"fa": "ورود", "en": "Unlock"},
    "login.forgot_password": {"fa": "رمز عبور را فراموش کرده‌ام", "en": "Forgot Password"},
    "login.error_no_usb": {"fa": "لطفاً ابتدا USB خود را وصل کنید", "en": "Please insert your USB key first"},
    "login.error_wrong_usb": {
        "fa": "این USB با کلید ثبت‌شده مطابقت ندارد",
        "en": "This USB does not match the registered key",
    },
    "login.error_wrong_password": {"fa": "رمز عبور نادرست است", "en": "Incorrect password"},
    "login.attempts_remaining": {"fa": "{n} تلاش باقی‌مانده", "en": "{n} attempts remaining"},
    "login.locked_out": {
        "fa": "تعداد تلاش‌های ناموفق از حد مجاز گذشت. از گزینه‌ی «فراموشی رمز عبور» استفاده کنید.",
        "en": "Too many failed attempts. Please use 'Forgot Password'.",
    },

    # ============================================================= Recovery Dialog
    "recovery.title": {"fa": "بازیابی رمز عبور", "en": "Password Recovery"},
    "recovery.usb_required": {
        "fa": "برای بازیابی هم به USB اصلی و هم پاسخ صحیح سوال امنیتی نیاز است.",
        "en": "Recovery requires both your USB key and the correct security answer.",
    },
    "recovery.answer_label": {"fa": "پاسخ سوال امنیتی:", "en": "Security answer:"},
    "recovery.submit": {"fa": "بررسی", "en": "Verify"},
    "recovery.wrong_answer": {"fa": "پاسخ یا USB نادرست است", "en": "Wrong answer or USB"},
    "recovery.success": {"fa": "احراز هویت موفق. رمز عبور جدید تعیین کنید:", "en": "Verified. Set a new password:"},
    "recovery.new_password": {"fa": "رمز عبور جدید:", "en": "New password:"},
    "recovery.new_password_confirm": {"fa": "تکرار رمز عبور جدید:", "en": "Confirm new password:"},
    "recovery.done": {
        "fa": "رمز عبور با موفقیت تغییر کرد. تمام فایل‌های قفل‌شده‌ی قبلی همچنان قابل بازیابی هستند.",
        "en": "Password changed successfully. All previously locked files remain fully recoverable.",
    },
    "recovery.not_configured": {
        "fa": "سوال امنیتی برای این حساب تنظیم نشده است.",
        "en": "No security question is configured for this account.",
    },

    # ============================================================= Dashboard
    "dashboard.title": {"fa": "داشبورد", "en": "Dashboard"},
    "dashboard.usb_key": {"fa": "کلید USB", "en": "USB KEY"},
    "dashboard.system_status": {"fa": "وضعیت سیستم", "en": "SYSTEM STATUS"},
    "dashboard.status_ready": {"fa": "آماده", "en": "READY"},
    "dashboard.status_locked": {"fa": "قفل شده", "en": "LOCKED OUT"},
    "dashboard.status_error": {"fa": "خطا", "en": "ERROR"},
    "dashboard.status_busy": {"fa": "در حال پردازش", "en": "BUSY"},
    "dashboard.protected_files": {"fa": "فایل‌های محافظت‌شده", "en": "Protected Files"},
    "dashboard.last_operation": {"fa": "آخرین عملیات", "en": "Last Operation"},
    "dashboard.backup_status": {"fa": "وضعیت Backup", "en": "Backup Status"},
    "dashboard.integrity_status": {"fa": "وضعیت صحت فایل‌ها", "en": "Integrity Status"},
    "dashboard.btn_lock": {"fa": "قفل کردن فایل/فولدر", "en": "Lock Files/Folders"},
    "dashboard.btn_unlock": {"fa": "باز کردن قفل", "en": "Unlock Files"},
    "dashboard.btn_backup_manager": {"fa": "مدیریت Backup", "en": "Backup Manager"},
    "dashboard.btn_logs": {"fa": "گزارش‌ها (Logs)", "en": "View Logs"},
    "dashboard.btn_settings": {"fa": "تنظیمات", "en": "Settings"},
    "dashboard.btn_logout": {"fa": "خروج", "en": "Logout"},
    "dashboard.locked_files_list": {"fa": "لیست فایل‌های قفل‌شده", "en": "Locked Files"},
    "dashboard.no_locked_files": {"fa": "هیچ فایل قفل‌شده‌ای وجود ندارد", "en": "No locked files yet"},
    "dashboard.crash_recovery_notice": {
        "fa": "یک عملیات ناتمام از اجرای قبلی شناسایی و به‌صورت ایمن پاک‌سازی شد ({n} فایل موقت).",
        "en": "An unfinished operation from a previous run was detected and safely cleaned up ({n} temp files).",
    },

    # ============================================================= Lock Dialog
    "lock.title": {"fa": "قفل کردن فایل‌ها", "en": "Lock Files"},
    "lock.select_items": {"fa": "فایل‌ها یا فولدرهای مورد نظر را انتخاب کنید", "en": "Select files or folders to lock"},
    "lock.add_files": {"fa": "افزودن فایل...", "en": "Add Files..."},
    "lock.add_folder": {"fa": "افزودن فولدر...", "en": "Add Folder..."},
    "lock.drop_hint": {"fa": "یا فایل/فولدر را اینجا رها کنید", "en": "or drag & drop files/folders here"},
    "lock.selected_items": {"fa": "{n} مورد انتخاب شده", "en": "{n} item(s) selected"},
    "lock.ask_backup_title": {"fa": "آیا Backup گرفته شود؟", "en": "Create a backup?"},
    "lock.ask_backup_body": {
        "fa": "پیشنهاد می‌شود پیش از قفل کردن، یک نسخه‌ی پشتیبان روی USB گرفته شود.",
        "en": "It is recommended to back up your files to the USB before locking.",
    },
    "lock.backup_and_lock": {"fa": "Backup بگیر و قفل کن", "en": "Backup && Lock"},
    "lock.lock_without_backup": {"fa": "بدون Backup قفل کن", "en": "Lock Without Backup"},
    "lock.confirm_no_backup": {
        "fa": "بدون Backup ادامه می‌دهید؟ در صورت خرابی، امکان بازیابی وجود نخواهد داشت.",
        "en": "Continue without backup? If something goes wrong, recovery will not be possible.",
    },
    "lock.ask_protect_names": {"fa": "آیا نام فایل‌ها نیز محافظت شود؟", "en": "Protect file names too?"},
    "lock.protect_names_hint": {
        "fa": "در صورت انتخاب، نام اصلی فایل‌ها در Explorer قابل مشاهده نخواهد بود.",
        "en": "If enabled, original file names will not be visible in Explorer.",
    },
    "lock.ask_protect_structure": {"fa": "آیا ساختار فولدرها نیز محافظت شود؟", "en": "Protect folder structure too?"},
    "lock.protect_structure_hint": {
        "fa": "نام پوشه‌ها نیز obfuscate می‌شود (نیازمند فعال بودن محافظت نام فایل).",
        "en": "Folder names will also be obfuscated (requires name protection enabled).",
    },
    "lock.emergency_lock_option": {"fa": "Emergency Lock (تلاش بیشتر برای قفل فایل‌های مشکل‌دار)", "en": "Emergency Lock (extra retry for problematic files)"},
    "lock.confirm_title": {"fa": "تایید نهایی Lock", "en": "Confirm Lock"},
    "lock.confirm_body": {"fa": "{n} فایل قفل خواهد شد. ادامه می‌دهید؟", "en": "{n} file(s) will be locked. Continue?"},
    "lock.progress_title": {"fa": "در حال قفل کردن...", "en": "Locking..."},
    "lock.progress_current_file": {"fa": "فایل جاری: {name}", "en": "Current file: {name}"},
    "lock.progress_count": {"fa": "فایل {done} از {total}", "en": "File {done} of {total}"},
    "lock.result_title": {"fa": "نتیجه Lock", "en": "LOCK COMPLETED"},
    "lock.result_success": {"fa": "موفق: {n}", "en": "Success: {n}"},
    "lock.result_failed": {"fa": "ناموفق: {n}", "en": "Failed: {n}"},
    "lock.result_skipped": {"fa": "رد شده: {n}", "en": "Skipped: {n}"},
    "lock.result_backup": {"fa": "Backup: {status}", "en": "Backup: {status}"},
    "lock.result_names": {"fa": "نام‌ها: {status}", "en": "Names: {status}"},
    "lock.result_structure": {"fa": "ساختار فولدر: {status}", "en": "Folder Structure: {status}"},
    "lock.status_protected": {"fa": "محافظت‌شده", "en": "Protected"},
    "lock.status_original": {"fa": "اصلی (بدون تغییر)", "en": "Original"},
    "lock.status_verified": {"fa": "تایید شد", "en": "Verified"},
    "lock.status_not_requested": {"fa": "درخواست نشد", "en": "Not Requested"},
    "lock.status_failed": {"fa": "ناموفق", "en": "Failed"},
    "lock.aborted_title": {"fa": "Lock انجام نشد", "en": "Lock Aborted"},
    "lock.aborted_backup_failed": {
        "fa": "چون Backup ناموفق بود، هیچ فایلی قفل نشد. فایل‌های اصلی دست‌نخورده باقی ماندند.",
        "en": "Because the backup failed, no files were locked. Original files remain untouched.",
    },
    "lock.already_locked_hint": {"fa": "این موارد قبلاً قفل شده بودند و رد شدند", "en": "These items were already locked and were skipped"},
    "lock.symlink_skipped_hint": {"fa": "این موارد symlink/junction بودند و رد شدند", "en": "These items were symlinks/junctions and were skipped"},

    # ============================================================= Unlock Dialog
    "unlock.title": {"fa": "باز کردن قفل فایل‌ها", "en": "Unlock Files"},
    "unlock.select_locked": {"fa": "فایل‌های قفل‌شده را انتخاب کنید", "en": "Select locked files to unlock"},
    "unlock.select_all": {"fa": "انتخاب همه", "en": "Select All"},
    "unlock.deselect_all": {"fa": "لغو انتخاب همه", "en": "Deselect All"},
    "unlock.no_items_selected": {"fa": "هیچ موردی انتخاب نشده است", "en": "No items selected"},
    "unlock.confirm_title": {"fa": "تایید Unlock", "en": "Confirm Unlock"},
    "unlock.confirm_body": {"fa": "{n} فایل باز خواهد شد. ادامه می‌دهید؟", "en": "{n} file(s) will be unlocked. Continue?"},
    "unlock.progress_title": {"fa": "در حال باز کردن قفل...", "en": "Unlocking..."},
    "unlock.conflict_title": {"fa": "تعارض نام فایل", "en": "File Name Conflict"},
    "unlock.conflict_body": {"fa": "مقصد از قبل وجود دارد:\n{path}", "en": "Destination already exists:\n{path}"},
    "unlock.conflict_replace": {"fa": "جایگزینی", "en": "Replace"},
    "unlock.conflict_keep_both": {"fa": "نگه‌داشتن هر دو", "en": "Keep Both"},
    "unlock.conflict_rename": {"fa": "تغییر نام", "en": "Rename"},
    "unlock.conflict_skip": {"fa": "رد کردن", "en": "Skip"},
    "unlock.conflict_abort": {"fa": "لغو کل عملیات", "en": "Abort All"},
    "unlock.apply_to_all": {"fa": "اعمال به همه موارد مشابه", "en": "Apply to all similar conflicts"},
    "unlock.result_title": {"fa": "نتیجه Unlock", "en": "UNLOCK COMPLETED"},
    "unlock.result_success": {"fa": "بازیابی موفق: {n}", "en": "Restored: {n}"},
    "unlock.result_failed": {"fa": "ناموفق: {n}", "en": "Failed: {n}"},
    "unlock.corrupted_title": {"fa": "فایل آسیب دیده است", "en": "File is Corrupted"},
    "unlock.corrupted_body": {
        "fa": "فایل «{name}» رمزگشایی نشد (احتمال دستکاری یا خرابی). یک Backup معتبر برای آن پیدا شد. بازیابی شود؟",
        "en": "File \"{name}\" failed to decrypt (possibly corrupted or tampered). A valid backup was found. Restore it?",
    },
    "unlock.corrupted_no_backup": {
        "fa": "فایل «{name}» رمزگشایی نشد و هیچ Backup معتبری برای آن یافت نشد.",
        "en": "File \"{name}\" failed to decrypt and no valid backup was found.",
    },
    "unlock.restore_from_backup": {"fa": "بازیابی از Backup", "en": "Restore from Backup"},
    "unlock.try_another_backup": {"fa": "امتحان Backup دیگر", "en": "Try Another Backup"},

    # ============================================================= Backup Manager
    "backup.title": {"fa": "مدیریت Backup", "en": "Backup Manager"},
    "backup.list_header": {"fa": "لیست Backup ها", "en": "Backups"},
    "backup.col_date": {"fa": "تاریخ", "en": "Date"},
    "backup.col_size": {"fa": "حجم", "en": "Size"},
    "backup.col_files": {"fa": "تعداد فایل", "en": "Files"},
    "backup.col_status": {"fa": "وضعیت", "en": "Status"},
    "backup.col_encrypted": {"fa": "رمزگذاری‌شده", "en": "Encrypted"},
    "backup.status_ok": {"fa": "سالم", "en": "OK"},
    "backup.status_corrupted": {"fa": "خراب", "en": "Corrupted"},
    "backup.status_missing": {"fa": "روی USB یافت نشد", "en": "Missing on USB"},
    "backup.btn_verify": {"fa": "بررسی صحت", "en": "Verify"},
    "backup.btn_delete": {"fa": "حذف", "en": "Delete"},
    "backup.btn_delete_old": {"fa": "حذف Backup های قدیمی", "en": "Delete Old Backups"},
    "backup.btn_view_files": {"fa": "مشاهده فایل‌ها", "en": "View Files"},
    "backup.confirm_delete": {
        "fa": "آیا از حذف این Backup مطمئن هستید؟ این عمل قابل بازگشت نیست.",
        "en": "Are you sure you want to delete this backup? This cannot be undone.",
    },
    "backup.confirm_delete_referenced": {
        "fa": "هشدار: فایل‌های قفل‌شده‌ی فعالی به این Backup متکی هستند. حذف آن، شبکه‌ی ایمنی این فایل‌ها را از بین می‌برد. ادامه می‌دهید؟",
        "en": "Warning: active locked files depend on this backup. Deleting it removes their safety net. Continue?",
    },
    "backup.verify_result_ok": {"fa": "Backup سالم است", "en": "Backup is healthy"},
    "backup.verify_result_fail": {"fa": "Backup خراب است: {detail}", "en": "Backup is corrupted: {detail}"},
    "backup.encrypt_setting": {"fa": "رمزگذاری محتوای Backup", "en": "Encrypt backup content"},
    "backup.no_backups": {"fa": "هیچ Backup ای وجود ندارد", "en": "No backups yet"},

    # ============================================================= Settings
    "settings.title": {"fa": "تنظیمات", "en": "Settings"},
    "settings.tab_general": {"fa": "عمومی", "en": "General"},
    "settings.tab_security": {"fa": "امنیت", "en": "Security"},
    "settings.tab_backup": {"fa": "Backup", "en": "Backup"},
    "settings.language": {"fa": "زبان برنامه:", "en": "Application Language:"},
    "settings.auto_logout": {"fa": "خروج خودکار پس از عدم فعالیت:", "en": "Auto Logout after inactivity:"},
    "settings.auto_logout_30s": {"fa": "۳۰ ثانیه", "en": "30 seconds"},
    "settings.auto_logout_1m": {"fa": "۱ دقیقه", "en": "1 minute"},
    "settings.auto_logout_5m": {"fa": "۵ دقیقه", "en": "5 minutes"},
    "settings.auto_logout_10m": {"fa": "۱۰ دقیقه", "en": "10 minutes"},
    "settings.auto_logout_never": {"fa": "هرگز", "en": "Never"},
    "settings.max_attempts": {"fa": "حداکثر تلاش اشتباه رمز عبور:", "en": "Max wrong password attempts:"},
    "settings.default_backup_behavior": {"fa": "رفتار پیش‌فرض Backup هنگام Lock:", "en": "Default backup behavior on Lock:"},
    "settings.ask_backup_names": {"fa": "همیشه قبل از Lock سوال شود (نام‌ها/ساختار)", "en": "Always ask before Lock (names/structure)"},
    "settings.change_password": {"fa": "تغییر رمز عبور", "en": "Change Password"},
    "settings.change_security_question": {"fa": "تغییر سوال امنیتی", "en": "Change Security Question"},
    "settings.saved": {"fa": "تنظیمات ذخیره شد", "en": "Settings saved"},

    # ============================================================= Password Change (from Settings)
    "pwchange.title": {"fa": "تغییر رمز عبور", "en": "Change Password"},
    "pwchange.current": {"fa": "رمز عبور فعلی:", "en": "Current password:"},
    "pwchange.new": {"fa": "رمز عبور جدید:", "en": "New password:"},
    "pwchange.confirm": {"fa": "تکرار رمز عبور جدید:", "en": "Confirm new password:"},
    "pwchange.usb_required": {"fa": "USB اصلی باید وصل باشد", "en": "The master USB must be connected"},
    "pwchange.success": {"fa": "رمز عبور با موفقیت تغییر کرد", "en": "Password changed successfully"},
    "pwchange.wrong_current": {"fa": "رمز عبور فعلی نادرست است", "en": "Current password is incorrect"},

    # ============================================================= Log Viewer
    "logs.title": {"fa": "گزارش‌ها (Logs)", "en": "Log Viewer"},
    "logs.search": {"fa": "جستجو...", "en": "Search..."},
    "logs.filter_type": {"fa": "نوع رویداد:", "en": "Event type:"},
    "logs.filter_severity": {"fa": "سطح:", "en": "Severity:"},
    "logs.filter_all": {"fa": "همه", "en": "All"},
    "logs.col_time": {"fa": "زمان", "en": "Time"},
    "logs.col_type": {"fa": "نوع", "en": "Type"},
    "logs.col_severity": {"fa": "سطح", "en": "Severity"},
    "logs.col_message": {"fa": "پیام", "en": "Message"},
    "logs.btn_export": {"fa": "خروجی گرفتن", "en": "Export"},
    "logs.btn_clear": {"fa": "پاک کردن گزارش‌ها", "en": "Clear Logs"},
    "logs.confirm_clear": {"fa": "آیا از پاک کردن تمام گزارش‌ها مطمئن هستید؟", "en": "Are you sure you want to clear all logs?"},
    "logs.export_success": {"fa": "گزارش‌ها با موفقیت ذخیره شدند: {path}", "en": "Logs exported successfully: {path}"},

    # ============================================================= خطاهای عمومی/سیستمی
    "error.usb_removed_during_op": {
        "fa": "USB حین عملیات خارج شد. عملیات به‌صورت ایمن متوقف شد؛ هیچ فایلی آسیب ندید.",
        "en": "USB was removed during the operation. The operation stopped safely; no file was harmed.",
    },
    "error.unexpected": {"fa": "خطای غیرمنتظره: {detail}", "en": "Unexpected error: {detail}"},
    "error.disk_full": {"fa": "فضای دیسک کافی نیست", "en": "Not enough disk space"},
    "error.permission_denied": {"fa": "دسترسی کافی وجود ندارد", "en": "Permission denied"},
}


def tr(key: str, lang: str | None = None, **kwargs) -> str:
    """
    ترجمه‌ی یک کلید متن. اگر ترجمه یا کلید موجود نباشد، خود کلید (به‌صورت fallback
    قابل‌تشخیص) برگردانده می‌شود تا در توسعه سریع متوجه‌ی متن جا‌افتاده شویم.
    """
    lang = lang or CURRENT_LANG
    entry = STRINGS.get(key)
    if entry is None:
        return f"[[{key}]]"
    text = entry.get(lang) or entry.get("fa") or entry.get("en") or f"[[{key}]]"
    if kwargs:
        try:
            return text.format(**kwargs)
        except (KeyError, IndexError):
            return text
    return text


def set_language(lang: str) -> None:
    global CURRENT_LANG
    if lang not in ("fa", "en"):
        raise ValueError(f"زبان پشتیبانی‌نشده: {lang}")
    CURRENT_LANG = lang


def get_language() -> str:
    return CURRENT_LANG
