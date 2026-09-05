@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"
call :ts
echo [%TS%] [INFO] Собираю архив для раздачи...
if not exist ".tools\go\bin\go.exe" (
  echo [%TS%] [ERROR] Нет движка Go. Сначала запусти install.bat один раз.
  pause
  exit /b 1
)
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
if exist "release" rmdir /s /q "release"
mkdir "release\PinterestTrustCheck\bin"
copy "run-web.bat" "release\PinterestTrustCheck\" >nul
copy "run.bat" "release\PinterestTrustCheck\" >nul
copy "install.bat" "release\PinterestTrustCheck\" >nul
copy "links.txt" "release\PinterestTrustCheck\" >nul
copy "README.txt" "release\PinterestTrustCheck\" >nul
copy "README.md" "release\PinterestTrustCheck\" >nul
copy "go.mod" "release\PinterestTrustCheck\" >nul
copy "bin\trust-check.exe" "release\PinterestTrustCheck\bin\" >nul
mkdir "release\PinterestTrustCheck\cmd"
xcopy "cmd" "release\PinterestTrustCheck\cmd\" /e /q >nul
powershell -NoProfile -Command "Compress-Archive -Path 'release\PinterestTrustCheck' -DestinationPath 'release\PinterestTrustCheck.zip' -Force"
if errorlevel 1 (
  call :ts
  echo [%TS%] [ERROR] Не упаковалось.
  pause
  exit /b 1
)
call :ts
echo [%TS%] [INFO] Готово: release\PinterestTrustCheck.zip
certutil -hashfile "release\PinterestTrustCheck.zip" SHA256
pause
exit /b 0
:ts
for /f "usebackq delims=" %%T in (`powershell -NoProfile -Command "Get-Date -Format 'yyyy-MM-dd HH:mm:ss'"`) do set TS=%%T
exit /b 0
