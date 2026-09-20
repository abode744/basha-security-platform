@echo off
title BASHA - GitHub One-Click Deploy
color 0b
cls
cd /d "%~dp0"
echo ========================================================
echo       منصة باشا - التسجيل والرفع التلقائي إلى GitHub
echo ========================================================
echo.
python deploy_github.py
pause
