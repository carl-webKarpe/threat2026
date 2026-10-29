@echo off
rem Builds MalDetectAgent.exe so lab PCs do not need Python.
rem Run this once on a PC that has Python (for example the server laptop):
rem     cd C:\xampp1\htdocs\threat2026\agent
rem     build_exe.bat
rem The result is the folder agent\dist: copy that whole folder to each lab PC and run install_agent.ps1 there.
setlocal
cd /d "%~dp0"

echo Installing PyInstaller and watchdog (real-time file activity monitoring)...
python -m pip install --upgrade pyinstaller watchdog
if errorlevel 1 goto :error

echo Building MalDetectAgent.exe...
rem file_activity.py and watchdog are bundled automatically; the hidden import makes sure the Windows watcher is included.
python -m PyInstaller --onefile --noconsole --clean --name MalDetectAgent --hidden-import watchdog.observers.read_directory_changes maldetect_agent.py
if errorlevel 1 goto :error

copy /Y config.example.json dist\ >nul
copy /Y install_agent.ps1 dist\ >nul
copy /Y uninstall_agent.ps1 dist\ >nul
copy /Y change_server.ps1 dist\ >nul
if exist maldetect-ca.crt copy /Y maldetect-ca.crt dist\ >nul

echo.
echo Done. Copy the folder below to each lab PC (USB, shared folder, ...):
echo     %~dp0dist
echo It contains MalDetectAgent.exe, install_agent.ps1, uninstall_agent.ps1, change_server.ps1 and config.example.json.
exit /b 0

:error
echo.
echo Build failed. Check that Python is installed and that "python --version" works in this window.
exit /b 1
