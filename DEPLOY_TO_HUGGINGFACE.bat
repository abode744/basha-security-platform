@echo off
title BASHA - Deploy to Hugging Face Spaces
color 0b
cls
cd /d "%~dp0"
echo ========================================================
echo       رفع منصة باشا إلى Hugging Face Spaces (مجاني 100%)
echo ========================================================
echo.
python deploy_hf.py
pause
