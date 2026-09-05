@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"
call :ts
if not exist "bin\trust-check.exe" (
  echo [%TS%] [ERROR] Нет программы. Сначала запусти install.bat один раз.
  pause
  exit /b 1
)
if not "%~1"=="" (
  echo [%TS%] [INFO] Проверяю: %~1
  "bin\trust-check.exe" "%~1"
) else (
  echo [%TS%] [INFO] Пакетная проверка из links.txt...
  "bin\trust-check.exe"
)
call :ts
echo [%TS%] [INFO] Готово.
pause
exit /b 0
:ts
for /f "usebackq delims=" %%T in (`powershell -NoProfile -Command "Get-Date -Format 'yyyy-MM-dd HH:mm:ss'"`) do set TS=%%T
exit /b 0
