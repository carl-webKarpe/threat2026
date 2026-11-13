@echo off
rem Double-click to install (or update) the MalDetect agent on this PC.
rem Server: http://192.168.0.63/threat2026 (set in install_agent.ps1).
cd /d "%~dp0"

rem The installer needs Administrator rights: ask Windows for them and start again.
net session >nul 2>&1
if errorlevel 1 (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

echo MalDetect agent installer
echo Server: http://192.168.0.63/threat2026
echo.
echo Paste this PC's device token (from Devices on the server, starts with mdt_) and press Enter.
echo If this PC already has the agent, just press Enter to keep its token.
set "TOKEN="
set /p "TOKEN=Token: "

if defined TOKEN (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install_agent.ps1" -Token "%TOKEN%"
) else (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install_agent.ps1"
)
echo.
pause
