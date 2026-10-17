# Secure Locker

ابزار امنیتی شخصی برای محافظت رمزنگاری‌شده از فایل‌ها روی یک لپ‌تاپ مشترک، با
استفاده از یک USB Flash Drive به‌عنوان «کلید فیزیکی» دوم (Two-Factor: Password + USB).

> **صادقانه بگوییم**: این ابزار شما را در برابر یک مهاجم Administrator واقعی که از
> قبل به فایل‌ها دسترسی داشته یا کل دیسک را کنترل می‌کند، کاملاً غیرقابل‌نفوذ نمی‌کند.
> آنچه واقعاً تضمین می‌کند: بدون USB فیزیکی + Password صحیح، محتوای فایل‌های قفل‌شده
> از نظر رمزنگاری غیرقابل خواندن است. بخش [Threat Model](#threat-model) را حتماً بخوانید.

---

## فهرست

1. [Threat Model](#threat-model)
2. [معماری امنیتی](#معماری-امنیتی)
3. [نصب](#نصب)
4. [اجرا روی ویندوز](#اجرا-روی-ویندوز)
5. [ساخت فایل EXE](#ساخت-فایل-exe)
6. [ساختار پروژه](#ساختار-پروژه)
7. [تست‌های امنیتی](#تستهای-امنیتی)
8. [محدودیت‌های شناخته‌شده](#محدودیتهای-شناختهشده)
9. [Security Review نهایی](#security-review-نهایی)

---

## Threat Model

**مهاجم فرضی:**
- به اکانت Windows دسترسی دارد؛ ممکن است Administrator باشد.
- به فایل‌های لپ‌تاپ، دیسک، و حتی برنامه‌ی نصب‌شده دسترسی دارد.
- می‌تواند فایل‌ها را کپی/حذف/تغییرنام دهد، Secure Locker را حذف کند، یا کل دیسک را ایمیج بگیرد.
- **USB اصلی را در اختیار ندارد.**

**چیزی که Secure Locker تضمین می‌کند:**
- محتوای هر فایل قفل‌شده با AES-256-GCM رمزگذاری شده و بدون Master Key (که خودش
  بدون **Password صحیح + USB فیزیکی صحیح** قابل استخراج نیست) قابل خواندن نیست.
- حتی اگر مهاجم کل دیسک را کپی کند و USB Secret را هم به‌نحوی حدس بزند اما Password
  را نداشته باشد (یا برعکس)، Master Key باز نمی‌شود — این یک دو-عاملی *واقعی* روی
  ساختار رمزنگاری است، نه صرفاً دو رمز جدا.
- هرگونه دستکاری (Tamper) در فایل رمزگذاری‌شده یا Backup، در سطح هر Chunk تشخیص داده
  می‌شود (AEAD)، نه این‌که داده‌ی خراب بی‌صدا قبول شود.

**چیزی که Secure Locker تضمین *نمی‌کند*:**
- اگر مهاجم Administrator، **قبل از اولین Lock** به فایل دسترسی داشته، ممکن است
  محتوای قدیمی جایی (مثل Windows Search Index، Thumbnail Cache، Recent Files، یا
  یک نسخه‌ی قبلی در Recycle Bin) باقی مانده باشد. Secure Locker گذشته را پاک نمی‌کند.
- مهاجم Administrator نظری می‌تواند حین اجرای برنامه از حافظه‌ی RAM (memory dump)
  کلید را استخراج کند. Master Key فقط برای کوتاه‌ترین زمان لازم در RAM نگه داشته
  می‌شود، اما در CPython zero-شدن تضمینی حافظه ممکن نیست (به بخش محدودیت‌ها مراجعه شود).
- **حذف فیزیکی** فایل قفل‌شده توسط مهاجم قابل جلوگیری نیست (Confidentiality محافظت
  می‌شود، نه Availability). به همین دلیل Backup روی USB پیشنهاد می‌شود.
- Keylogger، malware سطح سیستم، یا سرقت فیزیکی USB **به‌همراه** دیدن Password
  (مثلاً از پشت سر) خارج از scope این ابزار است.

**نتیجه‌ی صادقانه:** هدف محافظت Cryptographic از محتوای فایل‌هاست، نه ایجاد یک
OS-level security boundary کامل در برابر یک Administrator مصمم با دسترسی فیزیکی نامحدود.

---

## معماری امنیتی

### Key Hierarchy

```
Password + salt_p --Argon2id--> KEK_password ─┐
                                                ├─ HKDF ──> KEK_combined ──wrap──> Master Key (256-bit, رندوم)
USB Secret + salt_u --HKDF-SHA256--> KEK_usb ──┘

Security Answer + salt --Argon2id--> KEK_answer ─┐
                                                   ├─ HKDF ──> KEK_recovery ──wrap──> Master Key (همان MK بالا)
USB Secret + salt_u --HKDF-SHA256--> KEK_usb ─────┘

Master Key --HKDF(info=file_id)--> File Key + File HMAC Key   (per-file، مشتق نه ذخیره‌شده)
Master Key --HKDF(info="name-map")--> Name/Path Encryption Key
Master Key --HKDF(info="backup")--> Backup Encryption Key
```

**نکات کلیدی:**
- Master Key فقط **یک‌بار** (در Setup اولیه) تصادفی تولید می‌شود و **هرگز عوض نمی‌شود**
  مگر Key Rotation صریح (که در این نسخه به دلایل امنیتی حذف شده - به محدودیت‌ها مراجعه شود).
- دو wrap کاملاً مستقل از Master Key وجود دارد: یکی با `Password+USB`، یکی با
  `Security Answer+USB`. تغییر Password فقط روی wrap اول اثر می‌گذارد؛ فراموشی
  Password از طریق wrap دوم (Security Question) قابل بازیابی است — **بدون این‌که
  حتی یک فایل نیاز به رمزگذاری مجدد داشته باشد.**
- هر دو مسیر واقعاً دو-عاملی هستند: چون `unwrap` یک عملیات AEAD است، نبود صحیح **هر
  یک** از دو فاکتور باعث شکست قطعی احراز هویت می‌شود (نه یک نتیجه‌ی نادرست ساکت).

### فرمت فایل (SLF1)

```
MAGIC("SLF1") | VERSION | ALG_ID
HEADER_LEN | HEADER_NONCE | HEADER_CIPHERTEXT (AEAD، شامل file_id/size/chunk_count)
NONCE_BASE | CHUNK_COUNT
[برای هر Chunk: NONCE | LEN | CIPHERTEXT+TAG]  ×N   (پیش‌فرض ۸ مگابایت هر Chunk)
FOOTER_TAG (HMAC-SHA256 روی توالی کامل - ضد truncation/reorder)
```

هر Chunk با AES-256-GCM و nonce یکتا (مشتق از nonce_base فایل + شماره‌ی Chunk)
رمزگذاری می‌شود؛ شماره‌ی Chunk هم به‌عنوان AAD اضافه می‌شود تا جابه‌جایی/substitute
بین Chunkهای معتبر هم تشخیص داده شود. **هیچ فایلی به‌طور کامل در RAM خوانده نمی‌شود.**

### Atomic Write (اصل طلایی)

```
original_file --(read, chunk by chunk)--> encrypt --> temp_file
                                                          │
                                          verify (رمزگشایی کامل به یک sink دورریز)
                                                          │
                                              os.replace(temp, final_path)  [atomic]
```

فایل اصلی **هرگز** قبل از تایید کامل (verify) لمس نمی‌شود. اگر هر مرحله قبل از
`os.replace` شکست بخورد، فقط فایل موقت حذف می‌شود؛ اصلی دست‌نخورده می‌ماند. اگر
برنامه بعد از `os.replace` کرش کند، آن عملیات سیستم‌عامل atomic است، پس یا کاملاً
انجام شده یا اصلاً انجام نشده - هیچ‌وقت فایل نیمه‌نوشته نمی‌ماند.

### Portable-on-USB (اجرای مستقل از هر لپ‌تاپی)

کل «مرکز کنترل» برنامه — نه فقط کلید، بلکه خود دیتابیس (`vault_metadata.db`) و
تنظیمات (`config.json`) هم — مستقیم روی خود USB (کنار `key.bin`، در پوشه‌ی
`.securelocker\`) ساخته و نگه‌داری می‌شود. یعنی با کپی کردن یک `SecureLocker.exe`
به همان فلش، برنامه کاملاً Portable است: هر لپ‌تاپ ویندوزی (حتی بدون Python)
با زدن EXE، خودش فلش را پیدا می‌کند و مستقیم به Login می‌رود.

```
<USB>\
├── SecureLocker.exe          (اختیاری - می‌تواند همین‌جا هم باشد)
├── .securelocker\
│   ├── key.bin                USB Secret (فاکتور دوم احراز هویت)
│   ├── vault_metadata.db       دیتابیس (Master Key wrap شده، لیست فایل‌ها، لاگ‌ها)
│   └── config.json             تنظیمات (زبان، Auto Logout و ...)
└── SecureLockerVault\
    └── backups\...
```

**نکته‌ی مهم — چه‌چیزی هنوز روی لپ‌تاپ می‌ماند:** خود فایل‌های قفل‌شده (محتوای
رمزگذاری‌شده) طبق طراحی اصلی **در همان مسیر اصلی روی دیسک لپ‌تاپ** باقی می‌مانند؛
تغییر نمی‌کنند. آنچه به فلش منتقل شده فقط «مرکز کنترل» (کلید+دیتابیس+تنظیمات+بکاپ)
است، نه محتوای فایل‌های شخصی.

**ریسک جدید که باید بدانید:** چون حالا دیتابیس هم روی USB است (نه لپ‌تاپ)، اگر
وسط کار با برنامه (نه فقط وسط Lock/Unlock که از قبل ایمن است) فلش را بیرون
بکشید، ممکن است خطای دسترسی به دیتابیس بگیرید. برنامه این خطا را با یک پیام
واضح مدیریت می‌کند (نه crash خام)، اما توصیه: فلش را فقط بعد از بستن برنامه یا
Logout جدا کنید.

اگر main.py هیچ فلشی با Vault آماده پیدا نکند (اولین اجرا)، به‌صورت خودکار به
Setup Wizard می‌رود؛ همان‌جا که کاربر یک فلش را انتخاب می‌کند، `key.bin`،
دیتابیس، و تنظیمات همگی از همان لحظه روی همان فلش ساخته می‌شوند.

### USB به‌عنوان کلید

روی USB یک فایل کلید (`.securelocker/key.bin`) نگه‌داری می‌شود شامل یک شناسه‌ی
یکتا (USB ID) و یک Secret تصادفی ۲۵۶-بیتی. تشخیص USB **مستقل از Drive Letter**
است: تمام درایوهای Removable اسکن می‌شوند و محتوای فایل کلید (نه حرف درایو) تعیین
می‌کند کدام USB «همان کلید ثبت‌شده» است — این کار با یک Fingerprint یک‌طرفه
(`SHA-256(usb_id || usb_secret)`) که در دیتابیس لپ‌تاپ نگه‌داری می‌شود انجام می‌گیرد.

### Backup

Backup **قبل از** رمزگذاری از فایل‌های اصلی گرفته می‌شود و روی
`<USB>/SecureLockerVault/backups/<id>/` قرار می‌گیرد. بعد از هر Backup، صحت آن
اجباراً تایید می‌شود (AEAD authentication در حالت رمزگذاری‌شده، یا مقایسه‌ی
SHA-256 در حالت خام). **اگر Backup ناموفق شود، Lock اصلاً انجام نمی‌شود** (فایل
اصلی دست‌نخورده می‌ماند) - این قانون در `core/file_engine.py` و تست‌های
`test_05` و `test_17` تضمین و تایید شده است.

می‌توانید در Settings انتخاب کنید که آیا محتوای Backup هم رمزگذاری شود یا نه.
پیش‌فرض رمزگذاری‌شده است چون در صورت سرقت/گم‌شدن فلش، بکاپ رمزنگاری‌نشده یعنی
افشای کامل بدون نیاز به Password.

---

## نصب

```bash
python -m venv venv
venv\Scripts\activate        # ویندوز
pip install -r requirements.txt
```

نیازمندی‌ها: Python 3.11 یا بالاتر، ویندوز ۱۰/۱۱ (برای اجرای نهایی؛ توسعه روی
هر سیستم‌عاملی که Tkinter دارد ممکن است).

## اجرا روی ویندوز

```bash
python main.py
```

اولین اجرا شما را به Setup Wizard می‌برد (انتخاب USB → Password → Security
Question → تایید نهایی). اجراهای بعدی، اگر همان USB وصل باشد، **خودکار** آن را
تشخیص داده و مستقیماً به صفحه‌ی Login می‌روند (نیازی به انتخاب دستی دیتابیس نیست).

### حالت Portable-on-USB (پیش‌فرض)

Secure Locker به‌صورت پیش‌فرض کاملاً «همه‌کاره روی فلش» طراحی شده:
هم کلید (`~/.securelocker/key.bin`)، هم دیتابیس (`vault_metadata.db`)، هم
تنظیمات (`config.json`)، هم Backupها همگی **روی خود USB** (داخل پوشه‌ی
`.securelocker/`) ذخیره می‌شوند - نه روی لپ‌تاپ. یعنی:

- می‌توانید `SecureLocker.exe` را هم مستقیم روی همان USB بگذارید تا کل «برنامه +
  کلید + داده» یک بسته‌ی واحد و قابل‌حمل باشد.
- همان فلش را به هر لپ‌تاپ ویندوزی دیگری (حتی بدون Python نصب‌شده) بزنید و
  `SecureLocker.exe` را از روی خود فلش اجرا کنید؛ برنامه به‌طور خودکار Vault
  موجود را پیدا کرده و مستقیم صفحه‌ی Login را نشان می‌دهد.
- **فایل‌های قفل‌شده** طبق طراحی اصلی، همچنان **روی لپ‌تاپ در همان مسیر اصلی**
  باقی می‌مانند (طبق درخواست پروژه)؛ فقط "مرکز کنترل" برنامه (کلید/دیتابیس/تنظیمات)
  روی فلش است.
- اگر چند فلش Secure Locker هم‌زمان وصل باشند، برنامه از شما می‌خواهد کدام‌یک را
  انتخاب کنید (به‌جای حدس زدن خودکار).

## ساخت فایل EXE

```bash
build.bat
```

این اسکریپت:
1. Dependencyها را نصب/به‌روزرسانی می‌کند (شامل bundle کامل باینری‌های بومی
   `argon2-cffi`، `cryptography`، و `tkinterdnd2` با `--collect-all` - این
   dependencyها فقط hidden-import کافی نیست چون فایل‌های داده/باینری جداگانه
   هم دارند).
2. Build قبلی را پاک می‌کند.
3. یک `dist\SecureLocker.exe` تک‌فایلی و کاملاً مستقل می‌سازد (نیازی به نصب
   Python روی سیستم مقصد نیست).

بعد از Build موفق، خروجی (`dist\SecureLocker.exe`) را مستقیم روی USB کپی کنید
تا حالت Portable-on-USB کامل شود.

اگر مایل به تنظیمات دستی PyInstaller هستید:
```bash
pyinstaller --name SecureLocker --onefile --windowed --icon assets\icon.ico ^
    --collect-all argon2 --collect-all tkinterdnd2 --collect-all cryptography main.py
```

---

## ساختار پروژه

```
SecureLocker/
├── main.py                  نقطه ورود
├── config.py                تنظیمات persistent (JSON، غیرحساس)
├── requirements.txt
├── build.bat
├── README.md
├── core/
│   ├── crypto.py             AEAD streaming، فرمت SLF1
│   ├── key_manager.py        Key Hierarchy، Argon2id، HKDF، Recovery KEK
│   ├── usb_manager.py        تشخیص USB مستقل از Drive Letter
│   ├── metadata.py           SQLite (بدون داده‌ی حساس خام)
│   ├── transaction.py        State Machine برای Crash Safety
│   ├── file_engine.py        موتور Lock/Unlock، Atomic Replace
│   ├── backup_manager.py     Backup روی USB + Verification
│   ├── recovery.py           Password Recovery + Crash Recovery
│   └── security.py           Session، Auto Logout، محدودیت تلاش
├── ui/
│   ├── theme.py, async_utils.py, dnd_utils.py, app_context.py
│   ├── setup_wizard.py, login.py, recovery_dialog.py, dashboard.py
│   ├── lock_dialog.py, unlock_dialog.py
│   ├── backup_manager_ui.py, settings.py, log_viewer.py
├── localization/strings.py   دیکشنری کامل fa/en
├── tests/                    ۵۲ تست pytest (شامل هر ۲۸ سناریوی درخواستی)
└── assets/icon.ico
```

---

## تست‌های امنیتی

```bash
pip install pytest
python -m pytest tests/ -v
```

۵۲ تست، شامل دقیقاً ۲۸ سناریوی زیر (`tests/test_scenarios.py`)، هرکدام با رفتار
مورد انتظار مستندشده در docstring:

| # | سناریو | رفتار مورد انتظار |
|---|---|---|
| 1-2 | Lock/Unlock فایل کوچک | محتوا دقیقاً حفظ می‌شود |
| 3 | فایل بزرگ | Streaming صحیح، بدون OOM |
| 4-5 | Backup + Lock / شکست Backup | شکست Backup ⇒ Lock کلاً abort |
| 6-8 | Password/USB اشتباه | همیشه رد می‌شود، حتی با یکی صحیح |
| 9-10 | تغییر Password / Recovery | Master Key و فایل‌ها دست‌نخورده می‌مانند |
| 11-12 | فایل/Backup خراب | تشخیص داده می‌شود، هرگز سکوت نمی‌کند |
| 13-14 | تعارض نام (Lock/Unlock) | هرگز overwrite خودکار نمی‌شود |
| 15-16 | Crash / Disk Full | فایل اصلی همیشه دست‌نخورده |
| 17 | خروج USB | عملیات ایمن متوقف می‌شود |
| 18-19 | چند فایل / پوشه‌ی تودرتو | همه صحیح پردازش می‌شوند |
| 20-23 | یونیکد/فارسی/فاصله/مسیر بلند | همه به‌درستی مدیریت می‌شوند |
| 24 | Symlink | دنبال نمی‌شود، Skip می‌شود |
| 25-26 | پوشه‌ی خالی/بزرگ | بدون خطا |
| 27 | فایل از‌قبل‌قفل‌شده | دوباره پردازش نمی‌شود |
| 28 | شکست جزئی دسته‌ای | success/failed دقیقاً جدا گزارش می‌شود |

---

## محدودیت‌های شناخته‌شده

1. **RAM zero-شدن تضمینی نیست**: در CPython به‌خاطر Garbage Collector و immutability
   برخی انواع، پاک‌سازی قطعی حافظه ممکن نیست. Master Key فقط best-effort پاک می‌شود.
2. **Key Rotation حذف شد**: دکمه‌ی «ساخت کلید جدید» نسخه‌ی قبلی به دلیل عدم امکان
   پیاده‌سازی امن (بدون خطر از‌دست‌رفتن غیرقابل‌بازگشت فایل‌ها) در این نسخه وجود ندارد.
   امنیت و قابلیت بازیابی مهم‌تر از داشتن این ویژگی است.
3. **محافظت ساختار فولدر محدودیت NTFS دارد**: پوشه‌ها rename می‌شوند (نه واقعاً
   "مخفی")؛ عمق و مکان فیزیکی درخت حفظ می‌شود، فقط نام‌ها obfuscate می‌شوند.
4. **حذف فیزیکی قابل جلوگیری نیست**: رمزنگاری از Confidentiality محافظت می‌کند نه
   از حذف. Backup روی USB تنها راه مقابله است.
5. **تغییر زبان نیازمند بازکردن مجدد صفحات است**: چون متن ویجت‌های Tkinter در لحظه‌ی
   ساخت تنظیم می‌شود، صفحات از‌قبل‌باز‌شده بلافاصله زبان را عوض نمی‌کنند.
6. **Drag & Drop اختیاری است**: اگر `tkinterdnd2` نصب نباشد، به‌صورت خودکار به
   Browse/Paste محدود می‌شود (بدون خطا یا کرش).
7. **همه‌چیز روی یک فلش یعنی یک نقطه‌ی شکست فیزیکی**: چون کلید، دیتابیس، تنظیمات
   و Backupها همگی روی همان USB هستند، **گم‌شدن یا خراب‌شدن فیزیکی همان فلش**
   یعنی از دست رفتن همزمان کلید *و* راه بازیابی. این trade-off آگاهانه است (در
   ازای portability کامل)، اما به‌شدت توصیه می‌شود از خود USB هم به‌صورت دوره‌ای
   یک کپی امن (مثلاً disk image) در جای دیگری نگه‌داری کنید - Secure Locker این
   کار را خودکار انجام نمی‌دهد.
7. **دیتابیس روی USB یعنی وابستگی بیشتر به سلامت اتصال**: از وقتی معماری
   Portable-on-USB فعال شد، حذف فیزیکی فلش وسط استفاده‌ی فعال از برنامه (نه فقط
   وسط Lock/Unlock) می‌تواند باعث خطای I/O دیتابیس شود. این خطا مدیریت می‌شود
   (پیام واضح، نه crash)، اما توصیه می‌شود فلش فقط بعد از بستن برنامه جدا شود.
   یک پنجره‌ی زمانی بسیار باریک هم نظری وجود دارد (بین نوشتن فایل رمزگذاری‌شده
   و ثبت رکورد آن در دیتابیس) که اگر دقیقاً در همان میلی‌ثانیه فلش کنده شود،
   فایل روی دیسک رمزگذاری‌شده می‌ماند اما رکورد دیتابیسش ثبت نمی‌شود (نه از دست
   رفتن داده، بلکه نیاز به تشخیص دستی توسط کاربر مطلع).

---

## Security Review نهایی

### چه‌بخش‌هایی واقعاً امنیت Cryptographic ایجاد می‌کنند:
- `core/crypto.py` (AES-256-GCM streaming + HMAC footer)
- `core/key_manager.py` (Argon2id، HKDF، دو مسیر wrap مستقل)
- `core/usb_manager.py` (Fingerprint یک‌طرفه، Secret تصادفی)
- `core/file_engine.py` (Atomic replace + Verify-before-commit)
- `core/backup_manager.py` (Verification اجباری، رمزگذاری اختیاری)

### چه‌بخش‌هایی فقط UX/تجربه‌ی کاربری هستند (بدون اثر امنیتی مستقیم):
- تمام `ui/*.py` (رابط کاربری صرفاً orchestration منطق core را نمایش می‌دهد؛
  هیچ تصمیم رمزنگاری در لایه‌ی UI گرفته نمی‌شود)
- `localization/strings.py`, `ui/theme.py`
- `config.py` (تنظیمات غیرحساس)

### جمع‌بندی
- ✅ AES-256-GCM (نه Fernet، نه AES-ECB/CBC ساده)
- ✅ Argon2id (نه SHA-256 ساده، نه بدون Salt)
- ✅ Streaming chunk-based (هرگز کل فایل در RAM)
- ✅ Atomic replace با Verify اجباری قبل از commit
- ✅ دو-عاملی واقعی (Password + USB) در سطح رمزنگاری، نه فقط UI
- ✅ Master Key هرگز از Password/USB مستقیم مشتق نمی‌شود (فقط wrap/unwrap)
- ✅ Mapping نام فایل رمزگذاری‌شده (نه `name_map.json` plaintext)
- ✅ تشخیص USB مستقل از Drive Letter
- ✅ Backup Verification اجباری با Abort کامل در صورت شکست
- ✅ Crash Recovery واقعی (تست‌شده با شبیه‌سازی)
