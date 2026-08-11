@echo off
setlocal
cd /d "%~dp0.."

if not exist ".venv\Scripts\python.exe" py -3 -m venv .venv
if errorlevel 1 goto :error
call ".venv\Scripts\activate.bat"

python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
if errorlevel 1 goto :error

python -m unittest discover -s tests -v
if errorlevel 1 goto :error

pyinstaller --noconfirm --clean DFIR-Copilot.spec
if errorlevel 1 goto :error

echo.
echo Build complete: dist\DFIR-Copilot\DFIR-Copilot.exe
exit /b 0

:error
echo.
echo Build failed. Review the error above.
pause
exit /b 1

