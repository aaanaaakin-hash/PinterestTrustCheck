@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"
call :ts
echo [%TS%] [INFO] Проверка запуска...
if not exist ".tools\go\bin\go.exe" (
  call :ts
  echo [%TS%] [INFO] Качаю Go в проект...
  curl.exe -L --fail -o ".tools\go.zip" "https://go.dev/dl/go1.27.1.windows-amd64.zip"
  if errorlevel 1 (
    call :ts
    echo [%TS%] [ERROR] Не скачалось. Проверь интернет и запусти снова.
    pause
    exit /b 1
  )
  powershell -NoProfile -Command "Expand-Archive -LiteralPath '.tools\go.zip' -DestinationPath '.tools' -Force"
  del ".tools\go.zip"
)
call :ts
echo [%TS%] [INFO] Собираю программу...
set GOTOOLCHAIN=local
set GOPROXY=off
set GOCACHE=%~dp0.tools\go-build
set GOPATH=%~dp0.tools\gopath
if not exist "bin" mkdir "bin"
".tools\go\bin\go.exe" build -ldflags="-s -w" -o bin\trust-check.exe ./cmd
if errorlevel 1 (
  call :ts
  echo [%TS%] [ERROR] Не собралось. Смотри ошибку выше.
  pause
  exit /b 1
)
if not exist "links.txt" (
  echo amazon.com> links.txt
  echo sites.google.com>> links.txt
  echo bit.ly>> links.txt
)
call :ts
echo [%TS%] [INFO] Все готово. Впиши ссылки в links.txt и запускай run.bat.
pause
exit /b 0
:ts
for /f "usebackq delims=" %%T in (`powershell -NoProfile -Command "Get-Date -Format 'yyyy-MM-dd HH:mm:ss'"`) do set TS=%%T
exit /b 0
