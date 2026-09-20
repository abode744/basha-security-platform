@echo off
title BASHA Security Platform
color 0b
cls

echo ===================================================
echo           BASHA Security Platform (Windows)
echo ===================================================
echo.

cd /d "%~dp0"

echo [*] Step 1: Freeing port 8080 if occupied...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :8080 ^| findstr LISTENING 2^>nul') do taskkill /F /PID %%a >nul 2>&1

echo [*] Step 2: Installing / verifying required libraries...
python -m pip install fastapi "uvicorn[standard]" sqlalchemy bcrypt python-jose httpx pydantic-settings fpdf2

echo.
echo [*] Step 3: Starting BASHA Platform...
echo.
echo ===================================================
echo   Dashboard URL : http://localhost:8080
echo   Username      : abod
echo   Password      : 2024
echo ===================================================
echo.

python run_local.py

pause
