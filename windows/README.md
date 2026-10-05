# SorryRKN для Windows

Локальный обход DPI и Telegram-прокси, минималистичный интерфейс и управление через системный трей.

[**Скачать установщик 1.0.0**](https://raw.githubusercontent.com/Def01d/SorryRKN/windows-v1.0.0/windows/SorryRKN-Windows-1.0.0-Setup.exe) · [**Переносной ZIP**](https://raw.githubusercontent.com/Def01d/SorryRKN/windows-v1.0.0/windows/SorryRKN-Windows-1.0.0.zip)

Windows 10/11 x64, Intel/AMD. Для WinDivert нужны права администратора; Python включён в дистрибутив. ZIP нужно распаковать целиком.

1. Запустите SorryRKN и подтвердите запрос администратора.
2. Выберите сервисы и нажмите большую кнопку.
3. Для Telegram нажмите **«Подключить Telegram»**.
4. Закрытие окна сворачивает программу в трей; полное завершение — **«Выход»** в меню значка.

[Подробная инструкция](../docs/WINDOWS.md) · [Частые вопросы](../docs/FAQ.md) · [Контрольные суммы](SHA256SUMS.txt) · [Проверки](VALIDATION.md)

## Для разработчиков

[Исходники](src) · [Сборка](src/BUILD.md) · [Архив исходников 1.0.0](https://raw.githubusercontent.com/Def01d/SorryRKN/windows-v1.0.0/windows/SorryRKN-Windows-1.0.0-source.zip)

Используются оригинальные zapret/winws + WinDivert и Flowseal/tg-ws-proxy. Это независимое приложение, не официальный продукт авторов компонентов. Лицензии включены в `licenses`; результат обхода зависит от сети.
