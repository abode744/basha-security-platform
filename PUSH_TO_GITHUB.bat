@echo off
title Push BASHA to GitHub
color 0b
cls
cd /d "%~dp0"
echo ========================================================
echo       رفع منصة باشا إلى GitHub بنقرة واحدة
echo ========================================================
echo.
set /p REPO_URL="الصق رابط مستودع GitHub الخاص بك (مثال: https://github.com/username/basha.git): "
if "%REPO_URL%"=="" (
    echo [!] لم يتم إدخال رابط. تم الإلغاء.
    pause
    exit /b
)

echo.
echo [*] جاري ربط المستودع ورفع الملفات إلى GitHub...
"%~dp0mingit\cmd\git.exe" remote remove origin 2>nul
"%~dp0mingit\cmd\git.exe" remote add origin %REPO_URL%
"%~dp0mingit\cmd\git.exe" branch -M main
"%~dp0mingit\cmd\git.exe" push -u origin main

if %ERRORLEVEL% equ 0 (
    echo.
    echo ========================================================
    echo   [+] تم الرفع بنجاح! يمكنك الآن ربط المستودع في Render.com
    echo ========================================================
) else (
    echo.
    echo [!] حدث خطأ أثناء الرفع. تأكد من صحة الرابط وصلاحيات الوصول.
)
pause
