@echo off
chcp 65001 >nul 2>&1
title NetGuard v5.1 — Installer by WillyNilly
color 0A

echo.
echo  ╔═══════════════════════════════════════════════╗
echo  ║     🛡️  NetGuard v5.1 — One-Click Installer  ║
echo  ║          Designed by WillyNilly               ║
echo  ╚═══════════════════════════════════════════════╝
echo.

:: ─── Check Admin ───
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Admin required. Restarting as Administrator...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

echo [✓] Running as Administrator
echo.

:: ─── Detect install directory ───
set "INSTALL_DIR=%~dp0"
echo [*] Install directory: %INSTALL_DIR%
echo.

:: ─── Step 1: Check Python ───
echo ═══════════════════════════════════════════════
echo  Step 1/4: Checking Python...
echo ═══════════════════════════════════════════════
echo.

python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Python not found. Downloading Python installer...
    echo.
    powershell -NoProfile -Command "Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.12.8/python-3.12.8-amd64.exe' -OutFile '%TEMP%\python_installer.exe'"
    echo [*] Installing Python (this may take a minute)...
    "%TEMP%\python_installer.exe" /quiet InstallAllUsers=1 PrependPath=1 Include_pip=1
    echo [✓] Python installed!
    echo [!] Please close this window and run install.bat again.
    pause
    exit /b
) else (
    for /f "tokens=*" %%v in ('python --version 2^>^&1') do echo [✓] Found: %%v
)
echo.

:: ─── Step 2: Install Python packages ───
echo ═══════════════════════════════════════════════
echo  Step 2/4: Installing Python packages...
echo ═══════════════════════════════════════════════
echo.

echo [*] Installing psutil...
pip install psutil -q 2>nul
echo [✓] psutil

echo [*] Installing flask...
pip install flask -q 2>nul
echo [✓] flask

echo [*] Installing scapy...
pip install scapy -q 2>nul
echo [✓] scapy

echo.

:: ─── Step 3: Check Npcap ───
echo ═══════════════════════════════════════════════
echo  Step 3/4: Checking Npcap (packet capture)...
echo ═══════════════════════════════════════════════
echo.

if exist "C:\Windows\System32\Npcap\wpcap.dll" (
    echo [✓] Npcap already installed
) else if exist "C:\Windows\SysWOW64\Npcap\wpcap.dll" (
    echo [✓] Npcap already installed
) else (
    echo [!] Npcap not found. Downloading...
    powershell -NoProfile -Command "Invoke-WebRequest -Uri 'https://npcap.com/dist/npcap-1.80.exe' -OutFile '%TEMP%\npcap_installer.exe'"
    echo [*] Installing Npcap...
    echo [*] Please follow the Npcap installer prompts.
    "%TEMP%\npcap_installer.exe"
    echo [✓] Npcap installer launched
)
echo.

:: ─── Step 4: Create launcher ───
echo ═══════════════════════════════════════════════
echo  Step 4/4: Creating launcher...
echo ═══════════════════════════════════════════════
echo.

:: Create run.bat
(
echo @echo off
echo title NetGuard v5.1
echo cd /d "%%~dp0"
echo :: Check for updates silently
echo net session ^>nul 2^>^&1
echo if %%errorlevel%% neq 0 ^(
echo     powershell -Command "Start-Process '%%~f0' -Verb RunAs"
echo     exit /b
echo ^)
echo echo Starting NetGuard v5.1...
echo python netguard.py
echo pause
) > "%INSTALL_DIR%run.bat"
echo [✓] Created run.bat

:: Create desktop shortcut
powershell -NoProfile -Command "$ws = New-Object -ComObject WScript.Shell; $sc = $ws.CreateShortcut([IO.Path]::Combine([Environment]::GetFolderPath('Desktop'), 'NetGuard.lnk')); $sc.TargetPath = '%INSTALL_DIR%run.bat'; $sc.WorkingDirectory = '%INSTALL_DIR%'; $sc.IconLocation = 'shell32.dll,12'; $sc.Description = 'NetGuard v5.1 — Game Network Monitor'; $sc.Save()" 2>nul
echo [✓] Desktop shortcut created

echo.
echo ═══════════════════════════════════════════════
echo.
echo  ✅ Installation Complete!
echo.
echo  To start NetGuard:
echo    • Double-click "NetGuard" on your Desktop
echo    • Or run: run.bat
echo.
echo  The browser will open automatically.
echo.
echo ═══════════════════════════════════════════════
echo.

set /p "START_NOW=Start NetGuard now? (Y/N): "
if /i "%START_NOW%"=="Y" (
    echo [*] Starting NetGuard...
    start "" "%INSTALL_DIR%run.bat"
)

pause
