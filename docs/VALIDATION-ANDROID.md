# Проверки SorryRKN 0.8.0

- Python: 202 passed, 32 subtests passed.
- Gradle assembleDebug/assembleDebugAndroidTest/lintDebug: успешно; lint — 0 ошибок, 3 предупреждения.
- APK: dev.graybridge, versionCode 8, versionName 0.8.0, minSdk 26, arm64-v8a + x86_64. SHA-256 подписанта совпадает с 0.7: 854ef7e3cbfdb5fc624bc3ec7b7d9e17780b709bac7fb85b77dbf4ea0acf2ef4. zipalign -c -P 16 4: успешно.
- Android API 26 x86_64: NIST AES-CTR, двоичные данные всех значений, невыравненные фрагменты и 4 MiB encrypt→decrypt проходят.
- В программном эмуляторе преобразование Java byte[]: старый цикл 0.02 MiB/s, buffer protocol 359.91 MiB/s. Полная пара AES-CTR encrypt→decrypt с передачей между Python/Java — 1.68 MiB/s. Эти числа описывают эмулятор; это не замеры скорости Telegram на телефоне.
- Android APK-обновления: принят APK с тем же подписантом; отклонены APK с другим ключом, повреждённый APK, неправильная версия, HTTP/file URL, URL с userinfo, слишком большой размер и некорректный SHA-256.
- Трафик из отдельного UID через настоящий TUN: TCP 128 KiB, UDP 1000 байт, восемь HTTPS-имён по 1 MiB, Discord WebSocket Hello и ответы AI DNS AAAA/HTTPS прошли. Правильные раздельные native-маршруты YouTube/Discord/Instagram подтверждены счётчиками. DNS адреса и тестовый CA задаются исключительно test APK.

- Включение/выключение tpws/ByeDPI VPN + Telegram, Telegram-only при неудачных проверках и отмена автоподбора с освобождением портов прошли.
- Публичные update.json и APK скачаны без авторизации; размер 21017821 байт и SHA-256 3d4f4951a44e4962a5ab105dc7407e133bd82698ef17c127c11abbb8e1d4bafa совпали.
- Релиз опубликован: https://github.com/Def01d/SorryRKN/releases/tag/v0.8.0. Обновления читаются из публичного main/update.json; бинарник APK закреплён тегом v0.8.0.

Публичные сети Telegram/Yota/Indikom и аккаунты сервисов не проверялись здесь. Android 16 на реальном Samsung не проверялся.
