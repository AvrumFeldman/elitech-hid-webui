@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
    py -3 -m venv .venv
    if errorlevel 1 goto error
)
".venv\Scripts\python.exe" -c "import hid" >nul 2>&1
if errorlevel 1 (
    ".venv\Scripts\python.exe" -m pip install -r requirements.txt
    if errorlevel 1 goto error
)
".venv\Scripts\python.exe" elitech-webui.py --open-browser %*
if errorlevel 1 goto error
exit /b 0
:error
echo.
echo Could not start Elitech WebUI. Review the error above.
pause
exit /b 1
