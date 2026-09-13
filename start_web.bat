@echo off
cd /d "%~dp0"

title SOC IOC Enrichment Tool
color 0B

echo ===================================================
echo     SOC IOC ENRICHMENT - WEB INTERFACE
echo ===================================================
echo.

if not exist ".venv\Scripts\python.exe" (
    echo [ERROR] Virtual environment is missing!
    echo Please ensure you are in the correct directory.
    pause
    exit /b 1
)

echo Launching browser: http://127.0.0.1:5000 ...
start http://127.0.0.1:5000

echo Starting Flask web server...
echo Press CTRL+C to stop the server.
echo.
".venv\Scripts\python.exe" web\app.py

pause