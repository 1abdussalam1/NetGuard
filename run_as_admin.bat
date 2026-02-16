@echo off
title NetGuard v5.1 — WillyNilly
cd /d "%~dp0"

:: Check admin
net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:: Quick dependency check
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Python not found. Please run install.bat first.
    pause
    exit /b
)

:: Check key packages
python -c "import psutil, flask" 2>nul
if %errorlevel% neq 0 (
    echo [*] Installing missing packages...
    pip install psutil flask scapy -q
)

echo Starting NetGuard v5.1...
python netguard.py
pause
