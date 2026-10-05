# Изменения

[← Главная](README.md) · [Все релизы](https://github.com/Def01d/SorryRKN/releases)

Android и Windows имеют независимые номера версий.

## Windows 1.0.0

[Релиз](https://github.com/Def01d/SorryRKN/releases/tag/windows-v1.0.0) · [Установщик](https://raw.githubusercontent.com/Def01d/SorryRKN/windows-v1.0.0/windows/SorryRKN-Windows-1.0.0-Setup.exe) · [Переносная версия](https://raw.githubusercontent.com/Def01d/SorryRKN/windows-v1.0.0/windows/SorryRKN-Windows-1.0.0.zip)

- Первая Windows-версия: нативный интерфейс в чёрно-бело-серых тонах, установщик и переносной ZIP.
- Оригинальный zapret/winws и WinDivert, 22 совместимых профиля, быстрый и расширенный автоподбор.
- Встроенный Telegram MTProto → WebSocket/HTTP2 прокси; Python и криптография включены.
- Выборочный Comss DNS для ChatGPT, Claude и Gemini, отдельное правило DPI для Instagram.
- Управление из системного трея, работа после закрытия окна и завершение собственных процессов при выходе.
- Хранение секрета Telegram с Windows DPAPI.
- Автообновление совместимых данных GitHub; отдельный источник обновления Windows с проверкой размера и SHA-256 установщика.
- Опубликованы исходники Windows и инструкция по сборке.

[Проверки Windows](windows/VALIDATION.md)

## Android 0.8.0

[Релиз](https://github.com/Def01d/SorryRKN/releases/tag/v0.8.0) · [APK](https://raw.githubusercontent.com/Def01d/SorryRKN/v0.8.0/SorryRKN-0.8.0.apk)

- Приложение переименовано из GrayBridge в SorryRKN; обновлены иконка, кнопка подключения и переключатели.
- Ускорена передача данных для AES-CTR между Java и Python: пакетное копирование вместо побайтовых JNI-вызовов.
- Пул готовых Telegram-соединений увеличен с 2 до 4.
- Добавлены счётчики Telegram в диагностику.
- Добавлены проверка новых APK при запуске и пункт **«Обновить приложение»**.
- Перед установкой проверяются размер, SHA-256, пакет, версия и подпись.
- Пакет `dev.graybridge` и подпись сохранены для обновления поверх GrayBridge 0.7.

Методы YouTube, Discord, Instagram и профиль Gemini в 0.8 не менялись. Изменения Telegram уменьшают затраты обработки в программе; скорость на конкретной сети требует отдельной проверки.

[Проверки Android](docs/VALIDATION-ANDROID.md)
