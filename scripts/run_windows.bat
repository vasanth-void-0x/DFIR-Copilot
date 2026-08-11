@echo off
setlocal
cd /d "%~dp0.."

if not exist ".venv\Scripts\python.exe" (
    echo [DFIR Copilot] Creating virtual environment...
    py -3 -m venv .venv
    if errorlevel 1 goto :error
)

call ".venv\Scripts\activate.bat"
echo [DFIR Copilot] Using:
python --version
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
if errorlevel 1 goto :error

echo [DFIR Copilot] Setup complete. Official YARA-X scanning is enabled.
python main.py
exit /b 0

:error
echo.
echo Setup failed. Confirm Python 3.10 through 3.13 is installed.
pause
exit /b 1
