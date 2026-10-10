# Исходники SorryRKN

[← Главная](../README.md)

## Текущие версии

[**Android 0.11.0 + Windows 1.2.0 — исходники ZIP**](https://github.com/Def01d/SorryRKN/releases/download/v0.11.0/SorryRKN-Android-0.11.0-Windows-1.2.0-source.zip). Исходники в основной ветке: [Android](../android/src), [Windows](../windows/src). Результаты проверки: [Android](../android/src/VALIDATION.md), [Windows](../windows/src/VALIDATION.md). Контрольные суммы и готовые файлы приложены к [Android-релизу](https://github.com/Def01d/SorryRKN/releases/tag/v0.11.0) и [Windows-релизу](https://github.com/Def01d/SorryRKN/releases/tag/windows-v1.2.0).

## Архив исходников 0.10.3 / 1.1.0

[**Скачать Android 0.10.3 + Windows 1.1.0 одним ZIP**](SorryRKN-Android-0.10.3-Windows-1.1.0-source.zip) · [SHA-256](SHA256SUMS.txt)

В архиве **815 файлов исходного пакета** и два файла описания/контрольных сумм. Размер ZIP — 3,018,856 байт. Для просмотра на GitHub:

| Платформа | Исходники | Сборка |
| --- | --- | --- |
| Android 0.10.3 | [android/src](https://github.com/Def01d/SorryRKN/tree/dc2141f4ec9e91589420277d629fedcdf9901126/android/src) | [README](https://github.com/Def01d/SorryRKN/blob/dc2141f4ec9e91589420277d629fedcdf9901126/android/src/README.md) |
| Windows 1.1.0 | [windows/src](https://github.com/Def01d/SorryRKN/tree/dc2141f4ec9e91589420277d629fedcdf9901126/windows/src) | [BUILD.md](https://github.com/Def01d/SorryRKN/blob/dc2141f4ec9e91589420277d629fedcdf9901126/windows/src/BUILD.md) |

Включены интерфейсы, службы, адаптированные Telegram-прокси, ресурсы, сценарии сборки и тесты. Android содержит исходники своих нативных зависимостей; HEV-подмодули уже заполнены. Windows-сборка загружает сторонний runtime из закреплённого архива с проверкой SHA-256. Первоначальная сборка обеих платформ требует интернета и описанных в инструкциях инструментов.

Приватные ключи подписи, токены, личные конфигурации, кеши и результаты сборок исключены. Для своей Android-сборки используется собственная подпись, поэтому она не устанавливается поверх официального APK с другой подписью. Лицензии собственного кода и зависимостей находятся внутри соответствующих каталогов.

## Что проверено при публикации архива 0.10.3 / 1.1.0

- Android собран из отдельной чистой копии: APK, test APK и lint. Все нативные библиотеки пересобраны из опубликованных исходников. Использован отдельный локальный debug-ключ; ключ официального APK не нужен. Lint: 0 ошибок, 3 прежних предупреждения; выравнивание 16 KiB проверено.
- Сетевые тестовые бинарники собраны из этой копии; **366 Python-тестов и 28 подтестов прошли**. Для Linux-тестов нужен заголовок из `libcap-dev`, что указано в инструкции.
- Windows: Go-тесты с `-race`, генерация ресурсов и сборка Windows x64 прошли. EXE побайтно совпал с опубликованной Windows 1.1.0: SHA-256 `419d82142e23d88f5426e176533b52e7431656532c77f76b809c82d1818500a0`. Нативные Windows GUI/WinDivert-проверки в рамках экспорта повторно не запускались.
- Состав архива проверен по явному списку; выполнен поиск приватных файлов и встроенных токенов. Полный список файлов и их SHA-256: [MANIFEST.json](MANIFEST.json). Внутри ZIP есть `MANIFEST.sha256`.

Публикация исходников не меняет версии приложений и не подтверждает устранение проблем Telegram в сети пользователя. Результаты сетевых проверок: [Android](../docs/VALIDATION-ANDROID.md), [Windows](../windows/VALIDATION.md).

SHA-256 архива 0.10.3 / 1.1.0:

```text
8ba4bb9ef4b070db35cd3ff78141a3900ee133e9f2412bfec4c18d815e350dc4
```
