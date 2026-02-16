@echo off
title NetGuard Build
color 0E

echo.
echo  NetGuard - EXE Builder
echo  ======================
echo.

python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Python not found. Install Python first.
    pause
    exit /b
)

pip show pyinstaller >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] Installing PyInstaller...
    pip install pyinstaller -q
)

echo [*] Checking dependencies...
pip install psutil flask scapy -q

echo.
echo [*] Building NetGuard.exe ...
echo.

pyinstaller ^
    --onefile ^
    --name "NetGuard" ^
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
    echo ===================================
    echo  BUILD OK - dist\NetGuard.exe
    echo ===================================
    xcopy /E /I /Y fonts dist\fonts >nul 2>&1
    copy /Y version.json dist\ >nul 2>&1
    echo.
    echo Done. Zip the dist folder to distribute.
) else (
    echo.
    echo [!] Build failed.
)

echo.
pause
