# AGENTS.md — trustcheck (проверка доверия Pinterest к домену)

Go 1.27, только стандартная библиотека (`go.mod` без зависимостей, модуль `trustcheck`).
Комментарии и все строки для пользователя — по-русски.

## Движок и сборка (не ставить Go глобально)

- Движок лежит в `.tools/go` (качает `install.bat`, go1.27.1 windows-amd64). Собирать и тестить только им.
- `install.bat` — первая сборка: `GOTOOLCHAIN=local GOPROXY=off GOCACHE=.tools\go-build GOPATH=.tools\gopath` + `go build -ldflags="-s -w" -o bin\trust-check.exe ./cmd`. Сеть для сборки не нужна.
- `run.bat [ссылка]` — без аргумента пакет из `links.txt`, с аргументом одна ссылка. `run-web.bat` — `trust-check.exe serve`. Оба требуют готовый `bin\trust-check.exe`.
- `make-release.bat` — пересборка + `release\PinterestTrustCheck.zip` + SHA256. В релиз кладёт `cmd/` как открытый код.
- bat-файлы: `chcp 65001`, `cd /d "%~dp0"`, лог `[YYYY-MM-DD HH:MM:SS] [INFO/ERROR]`, в конце `pause`.

## Команды для агента (из корня)

```bat
set GOTOOLCHAIN=local & set GOPROXY=off & set GOCACHE=%CD%\.tools\go-build & set GOPATH=%CD%\.tools\gopath
.tools\go\bin\go.exe build -o bin\trust-check.exe ./cmd
.tools\go\bin\go.exe test ./...
.tools\go\bin\go.exe test ./internal/check -run TestИмя -v
.tools\go\bin\go.exe test ./cmd -run TestИмя -v
bin\trust-check.exe --version
bin\trust-check.exe example.com --json
```

Без этих `set` сборка может уйти в сеть или в чужой тулчейн — не пропускать.

## Архитектура: где что лежит

- `cmd/main.go` — точка входа. Без аргументов пакет (`links.txt` → таблица + `results.csv`), один аргумент — подробный разбор, `serve` — веб, `--version` / `--json` — флаги. `web/index.html` зашит через `go:embed`, отдельных статик-файлов не нужно.
- `cmd/scan.go` — вся сеть (редиректы, TLS, RDAP, DNSBL, Wayback, crt.sh, OTX, VT, Safe Browsing). Для тестов — швы `resolveFn/tlsFn/ageFn/gsbFn/hostingFn/listsFn/waybackFn/crtFn/otxFn/vtFn/newScanClient` + `tlsSkipVerify`, подменять только их.
- `cmd/server.go` — только localhost, порт из `check.ServeAddr()`. Ручки отдают JSON результата, значения ключей наружу не отдают.
- `cmd/store.go` — файлы рядом с кнопками: `linksSpot()` ищет `links.txt` сначала в cwd, потом в папке exe; `loadLinks` создаёт образец при отсутствии; `ensureKeyTemplate` создаёт шаблоны `*.key`; `writeCSV` — `results.csv` с `;` и кавычками; история дописывается в `history.csv`.
- `internal/check/check.go` — чистая логика без сети (ввод, баллы, вердикты, `AppVersion`, `ServeAddr`, `ReadLinks`). Тестируется полностью офлайн.

## Тесты

- Обычный `go test ./...` — офлайн: `cmd` ходит только в локальный `httptest` через `stubEnv`, наружу не ходит.
- `cmd/live_test.go` — только с `PINTEREST_LIVE=1`, требует интернет и ключи. В обычной проверке не запускать.
- Лимиты скана зашиты в `main.go`: `timeoutMs=10000`, `maxRedirects=5`, `maxBody=1МБ`.

## Файлы, ключи, версия

- Версия — один источник `check.AppVersion` (`internal/check/check.go`), видна в `--version` и в вебе. Менять вместе с `README.md`.
- Сервер: `127.0.0.1:18743` по умолчанию, `PINTEREST_PORT` меняет только порт (хост всегда loopback).
- Ключи необязательны, без них проверка пишет «не проверено»: файлы `gsb.key/otx.key/vt.key` или env `PINTEREST_GSB_KEY/PINTEREST_OTX_KEY/PINTEREST_VT_KEY`. Строки с `#` — комментарий, не ключ.
- Никогда не коммитить: `*.key`, `history.csv`, `results.csv` (уже в `.gitignore`). `links.txt` — tracked-образец, личные ссылки туда не писать. Новых зависимостей не добавлять без спроса — проект принципиально без deps.
- Безопасность не ломать: ввод недоверенный (`ToStartURL/CleanHost/ValidHost`), `resolveGuard` режет private-IP и подмену DNS, ключи не логировать и не отдавать в API.
