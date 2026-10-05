# SorryRKN

Минималистичное Android-приложение без root: локальный VPN для обхода DPI и Telegram MTProto → WebSocket/HTTP2 прокси.

## Установка

[Скачать последнюю версию APK](https://github.com/Def01d/SorryRKN/releases/latest/download/SorryRKN-0.8.0.apk) · [Все релизы](https://github.com/Def01d/SorryRKN/releases)

Установите SorryRKN 0.8 поверх GrayBridge 0.7, не удаляя приложение. Пакет `dev.graybridge` и подпись сохранены; настройки и секрет Telegram остаются прежними. Версия 0.7 не умеет проверять новые APK, поэтому первый переход выполняется вручную. Начиная с 0.8 новые версии предлагаются при запуске; установка требует подтверждения Android.

## Версия 0.8

- Ускорена обработка фото, видео и файлов Telegram: пакетная конвертация Java byte[] вместо побайтовых JNI-вызовов при AES-CTR.
- Пул готовых Telegram-соединений увеличен с 2 до 4.
- Добавлены счётчики Telegram в диагностику.
- Новое имя SorryRKN, иконка, кнопка подключения и переключатели.
- Проверка APK-обновлений при запуске и в меню «Обновить приложение». Перед установкой проверяются размер, SHA-256, пакет, версия и подпись.

Источник обновлений: https://github.com/Def01d/SorryRKN/releases/latest/download/update.json

Android 8+; arm64-v8a и x86_64. Результат обхода и скорость загрузок зависят от сети. Это репозиторий релизов; ключ подписи здесь не публикуется.

## Открытые компоненты

Независимая адаптация [Flowseal/tg-ws-proxy](https://github.com/Flowseal/tg-ws-proxy), [Flowseal/zapret-discord-youtube](https://github.com/Flowseal/zapret-discord-youtube), zapret/tpws, ByeDPI и hev-socks5-tunnel. Приложение не является официальным продуктом авторов этих проектов. Лицензии и notices включены в приложение: «О приложении» → «Лицензии».
