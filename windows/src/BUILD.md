# Сборка Windows

Нужны Windows x64 и Go 1.24 или новее. Для установщика дополнительно нужен NSIS 3 (`makensis` в PATH). Запустите `powershell -ExecutionPolicy Bypass -File scripts/build.ps1` из этого каталога.

Скрипт получает встроенные Python 3.12.10, зависимости и Flowseal/winws из закреплённой переносной версии 1.0.0, проверяет SHA-256, затем собирает собственный Go-интерфейс. Код Telegram-прокси находится в `runtime/app` и берётся из исходников. В `cmd/sorryrkn/rsrc_windows_amd64.syso` включены иконка, сведения о версии и манифест запроса прав администратора.

Для перегенерации ресурсов: `go install github.com/tc-hib/go-winres@v0.3.3`, затем `go-winres simply --arch amd64 --out cmd/sorryrkn/rsrc --manifest gui --admin --icon resources/icon.png --product-version 1.0.0 --file-version 1.0.0 --file-description SorryRKN --product-name SorryRKN --original-filename SorryRKN.exe`.

Логика: `go test -race ./internal/core`. Настоящая Windows с правами администратора: `scripts/validate.ps1 -AppDir dist/package/SorryRKN -InstallerPath dist/SorryRKN-Windows-1.0.0-Setup.exe`. Проверяются нативная криптография, DPAPI, WinDivert, выборочный DNS, Telegram, завершение дочерних процессов, интерфейс, трей, установка и удаление. Проверка не доказывает обход ограничений конкретного оператора.

Исходный код движка: https://github.com/bol-van/zapret, WinDivert: https://github.com/basil00/WinDivert, Python: https://www.python.org/downloads/release/python-31210/, Cygwin: https://cygwin.com/. Дистрибутив включает лицензии; Python-пакеты содержат собственные notices в dist-info. Изменений в бинарных файлах этих компонентов нет.
