@echo off
chcp 65001 >nul 2>&1
title NetGuard — Build EXE
color 0E

echo.
echo  ╔═══════════════════════════════════════════════╗
echo  ║    🛡️  NetGuard — EXE Builder (PyInstaller)   ║
echo  ╚═══════════════════════════════════════════════╝
echo.

:: Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Python not found. Install Python first.
    pause
    exit /b
)

:: Install PyInstaller if needed
pip show pyinstaller >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] Installing PyInstaller...
    pip install pyinstaller -q
)

:: Install dependencies
echo [*] Checking dependencies...
pip install psutil flask scapy -q

:: Build EXE
echo.
echo [*] Building NetGuard.exe...
echo [*] This may take 1-2 minutes...
echo.

pyinstaller ^
    --onefile ^
    --name "NetGuard" ^
    --icon "NONE" ^
    --uac-admin ^
    --add-data "fonts;fonts" ^
    --add-data "version.json;." ^
    --hidden-import "psutil" ^
    --hidden-import "flask" ^
    --hidden-import "scapy" ^
    --hidden-import "scapy.all" ^
    --hidden-import "scapy.layers" ^
    --hidden-import "scapy.layers.inet" ^
    --hidden-import "scapy.arch.windows" ^
    --hidden-import "engineio.async_drivers.threading" ^
    --noupx ^
    --clean ^
    netguard.py

if exist "dist\NetGuard.exe" (
    echo.
    echo ═══════════════════════════════════════════════
    echo  ✅ Build successful!
    echo  Output: dist\NetGuard.exe
    echo  Size:
    for %%A in ("dist\NetGuard.exe") do echo    %%~zA bytes
    echo ═══════════════════════════════════════════════
    echo.

    :: Copy fonts to dist (for serving)
    xcopy /E /I /Y fonts dist\fonts >nul 2>&1

    :: Copy version.json
    copy /Y version.json dist\ >nul 2>&1

    echo [*] To distribute: zip the dist\ folder
    echo [*] Users just run NetGuard.exe — no Python needed!
) else (
    echo.
    echo [!] Build failed. Check errors above.
)

echo.
pause
