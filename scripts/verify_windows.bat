@echo off
setlocal
cd /d "%~dp0.."
if not exist ".venv\Scripts\python.exe" (
    echo Run scripts\run_windows.bat once to install the environment.
    exit /b 1
)
call ".venv\Scripts\activate.bat"
python -m unittest discover -s tests -v
python main.py --self-check

