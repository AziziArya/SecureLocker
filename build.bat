@echo off
REM ============================================================
REM Secure Locker - Windows Build Script
REM ساخت SecureLocker.exe مستقل (بدون نیاز به نصب Python)
REM ============================================================

echo [1/4] Checking Python...
python --version
if errorlevel 1 (
    echo ERROR: Python not found in PATH. Install Python 3.11+ first.
    exit /b 1
)

echo.
echo [2/4] Installing/updating dependencies...
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

echo.
echo [3/4] Cleaning previous build artifacts...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
if exist SecureLocker.spec del SecureLocker.spec

echo.
echo [4/4] Building SecureLocker.exe with PyInstaller...
python -m PyInstaller ^
    --name SecureLocker ^
    --onefile ^
    --windowed ^
    --icon assets\icon.ico ^
    --add-data "localization;localization" ^
    --hidden-import tkinterdnd2 ^
    --hidden-import argon2 ^
    --hidden-import argon2.low_level ^
    --hidden-import _cffi_backend ^
    --collect-all argon2 ^
    --collect-all tkinterdnd2 ^
    --collect-all cryptography ^
    main.py

if errorlevel 1 (
    echo.
    echo BUILD FAILED. See errors above.
    exit /b 1
)

echo.
echo ============================================================
echo BUILD SUCCESSFUL
echo Output: dist\SecureLocker.exe
echo ============================================================
echo.
echo NEXT STEP (Portable-on-USB mode):
echo   1. Copy dist\SecureLocker.exe directly onto your USB flash drive.
echo   2. Run it from the USB on any Windows PC (no Python needed there).
echo   3. On first run it will ask you to set up that same USB as the key
echo      AND will store the database/settings/backups on it too - the
echo      USB becomes fully self-contained (key + data + app all-in-one).
echo   4. To use it on a different laptop, just plug in the SAME USB and
echo      run SecureLocker.exe from it again - it auto-detects the vault.
pause
