# Сборка Windows 1.2.0

Этот каталог содержит исходники Go-приложения, адаптированного Telegram-прокси, тесты, иконку и лицензии. Он соответствует Windows 1.2.0 (`VersionCode = 10200`). Область подтверждённых проверок и ограничения описаны в [VALIDATION.md](VALIDATION.md).

Нужны Windows 10/11 x64, Go 1.24 или новее, PowerShell и доступ к GitHub/Go Modules. Для установщика дополнительно нужен NSIS 3 (`makensis` в `PATH`). Python отдельно устанавливать не требуется. Из этого каталога выполните:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/build.ps1
```

Скрипт восстанавливает сторонний runtime, создаёт ресурсы версии 1.2.0 из `resources/icon.png` с помощью закреплённого `go-winres v0.3.3` и собирает приложение. Сгенерированный `.syso` не включён в исходники и исключён через `.gitignore`; для повторной генерации доступен `scripts/resources.ps1`. Секретов автора и сертификата подписи для сборки не требуется; EXE остаётся без подписи издателя.

Результаты:

- `dist/SorryRKN.exe` — интерфейс; для работы нужны соседние каталоги `runtime` и `licenses`.
- `dist/check-network.exe` — диагностика HTTPS/API/WebSocket без загрузки драйвера.
- `dist/package/SorryRKN/` — готовая папка приложения.
- `dist/SorryRKN-Windows-1.2.0.zip` — переносная версия.
- `dist/SorryRKN-Windows-1.2.0-Setup.exe` — установщик, если доступен NSIS.

## Сторонние зависимости

Для runtime используется [закреплённый архив Windows 1.0.0](https://raw.githubusercontent.com/Def01d/SorryRKN/windows-v1.0.0/windows/SorryRKN-Windows-1.0.0.zip), SHA-256:

```text
63352bcffc05fd180ad9f2a179ed2770978bff24090abfe040e62503a2693986
```

Скрипт проверяет хеш перед распаковкой и копирует только `runtime/python` и `runtime/zapret`. Go-интерфейс и код Telegram из архива не используются: они собираются или копируются из этих исходников. Сторонние бинарные файлы не изменяются. Python 3.12.10, его пакеты, winws/WinDivert/Cygwin, списки, fake-пакеты и каталог профилей берутся из закреплённой зависимости. Распакованные бинарные зависимости и выходные файлы не включены в архив исходников; для первой сборки нужен доступ к закреплённому архиву. [Компоненты и лицензии](THIRD-PARTY.md).

Для подготовки runtime без сборки:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/build.ps1 -RuntimeOnly
```

## Проверки

Сначала подготовьте runtime: тест каталога проверяет реальные профили и файлы из `runtime/zapret`. Затем выполните:

```powershell
go test ./...
go vet ./internal/core ./internal/platform
runtime\python\python.exe -m unittest discover -s runtime/app -p 'test_*.py' -v
```

Дополнительно можно запустить `go test -race ./internal/core`. Для `-race` нужен поддерживаемый Go компилятор C в `PATH`, например GCC из MinGW-w64; обычные тесты этого не требуют.

После сборки доступны отдельные проверки сети без изменения настроек и без прав администратора:

```powershell
dist\package\SorryRKN\check-network.exe -output dist/network-check.json
dist\package\SorryRKN\runtime\python\python.exe scripts/check-telegram.py --runtime dist/package/SorryRKN/runtime --output dist/telegram-check.json
```

Они проверяют публичные ответы сервисов и MTProto DC1–5, но не вход в аккаунт, воспроизведение видео, звонки или ответы ChatGPT. Доступность внешних сервисов зависит от сети и времени проверки.

Отдельная ручная нативная проверка на Windows с правами администратора:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/validate.ps1 -AppDir dist/package/SorryRKN -InstallerPath dist/SorryRKN-Windows-1.2.0-Setup.exe
```

Если NSIS не установлен, опустите параметр `-InstallerPath`. Проверяются криптография, DPAPI, WinDivert, выборочный DNS, Telegram, завершение дочерних процессов, интерфейс и трей; при передаче установщика — также установка и удаление. Проверка создаёт тестовые настройки и отчёт в профиле текущего пользователя, поэтому для неё удобен отдельный тестовый пользователь Windows. Нативная проверка не входит в обычную сборку или CI исходников и не доказывает обход ограничений конкретного оператора.

В репозитории `.github/workflows/windows-source.yml` собирает текущие исходники, запускает Go-тесты, core/platform vet и 11 автономных Python-тестов, затем сохраняет переносной ZIP и журналы. `.github/workflows/windows-validation.yml` и его копия `scripts/windows-validation.yml` остаются отдельной ручной проверкой ранее опубликованного пакета 1.1.0. Служебные скрипты публикации и локальные настройки разработчика в экспорт не входят.
