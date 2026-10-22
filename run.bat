@echo off
title Network Device Scanner
echo ====================================
echo Network Device Scanner Installer
echo ====================================
echo.
echo Installing dependencies...
pip install -r requirements.txt
echo.
if errorlevel 1 (
    echo ERROR: Failed to install dependencies. Please make sure pip is installed.
    pause
    exit /b 1
)

echo.
echo Installing done! Running scanner...
echo.
python network_scanner.py
echo.
echo Press any key to exit...
pause >nul
