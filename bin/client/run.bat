@echo off
title Cloudflare WARP Handshake Migration Engine (WinDivert Layer 3)
cd /d "%~dp0"

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo =========================================================================
    echo [ERROR] Administrator privileges required.
    echo Right-click this script and select 'Run as Administrator'.
    echo =========================================================================
    pause
    exit /b 1
)

masque-client.exe
pause
