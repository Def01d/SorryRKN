# SorryRKN для Android — исходники

Исходники Android-приложения версии **0.10.3**: интерфейс Java, локальный
`VpnService`, Python-маршрутизация и MTProto-прокси, а также нативные движки
ByeDPI, tpws и hev-socks5-tunnel. Это снимок текущей реализации; публикация
исходников сама по себе не исправляет доступность Telegram у конкретного оператора.

## Сборка APK

Проверяемая среда сборки — Linux x86_64. В Windows используйте WSL2 с Linux-версией
Android SDK. Скрипт нативной сборки требует Bash и не рассчитан на запуск из
обычного Windows CMD/PowerShell.

Понадобятся:

- JDK 17 и Python 3.12 в `PATH`;
- Android SDK Platform 35, Build Tools 35.0.0 и Platform Tools;
- Android NDK **28.2.13676358**;
- интернет для первоначальной загрузки Gradle, Android Gradle Plugin и пакетов
  Chaquopy/Python.

Из этой папки, содержащей `gradlew` и `settings.gradle`:

```bash
export ANDROID_HOME="$HOME/Android/Sdk"
export PATH="$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools:$PATH"
sdkmanager "platform-tools" "platforms;android-35" "build-tools;35.0.0" "ndk;28.2.13676358"
sdkmanager --licenses
./gradlew :app:assembleDebug
```

Если SDK установлен в другом месте, измените `ANDROID_HOME`. В Android Studio
можно открыть эту папку как Gradle-проект и выбрать JDK 17; IDE создаст локальный
`local.properties`, который не следует коммитить.

Результат: `app/build/outputs/apk/debug/app-debug.apk`.

```bash
adb install app/build/outputs/apk/debug/app-debug.apk
```

Debug-сборка использует ваш локальный отладочный ключ Android. Закрытый ключ автора
для неё не нужен и в репозитории отсутствует. APK с другой подписью не может
обновить уже установленную официальную сборку с тем же `applicationId`.

`./gradlew :app:assembleRelease` создаёт **неподписанный** release APK. Для своей
публикации подпишите его собственным ключом, храня ключ и пароли вне репозитория.
Конфигурация проекта не обращается к закрытому release-keystore.

Нативные `.so` не включены в исходники: задача `buildNative` автоматически собирает
их из `native/` и `third_party/` для `arm64-v8a` и `x86_64`. Минимальная версия
Android — 8.0/API 26. Корректировки линковки для страниц 16 КБ находятся в
`native/` и `scripts/build-native.sh`.

## Проверка на компьютере

Для локальных сетевых тестов нужны Python 3.12, C-компилятор, Make и заголовки
zlib/libcap. В Debian/Ubuntu установите `build-essential`, `zlib1g-dev` и
`libcap-dev` (последний предоставляет `sys/capability.h` для Linux-версии tpws).

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
source .venv/bin/activate
bash scripts/test-network.sh
```

Скрипт собирает отдельные тестовые tpws/ByeDPI и запускает `pytest`. Разрешение
локальных адресов в тестовом tpws применяется только к временной копии исходника
и не входит в APK. Стендовые проверки проверяют протоколы, конкурентные соединения
и очистку ресурсов; они не доказывают доступность сервисов в конкретной сети.

Android-инструментальные проверки находятся в `app/src/androidTest/`;
`tests/device-probe/` — вспомогательное приложение с отдельным UID. Для сборки:

```bash
./gradlew :app:assembleDebugAndroidTest :device-probe:assembleDebug
```

Часть инструментальных сценариев требует локальных серверов из `tests/` и
параметров тестового runner; это инструменты разработки, а не автоматическая
проверка оператора связи.

Для `tests/telegram_dpi_server.py` и `tests/telegram_fronting_server.py` явно
передавайте `--fixture-dir` с отдельной локальной папкой для тестовых сертификатов.
Созданный там `key.pem` не должен попадать в репозиторий или APK.

## Состав и зависимости

- `app/src/main/java/` — Android UI, сервис и плитка быстрых настроек.
- `app/src/main/python/` — маршрутизация, DNS и Telegram-прокси.
- `app/src/main/assets/` — стартовые данные и тексты лицензий.
- `native/`, `third_party/` — JNI и полные нативные зависимости для сборки.
- `tests/`, `app/src/androidTest/` — тесты и локальные серверы.
- `docs/upstream-lock.json`, `docs/hev-submodules.txt` — версии исходных проектов.
- [THIRD_PARTY.md](THIRD_PARTY.md) — происхождение и лицензии компонентов.

HEV-зависимости уже включены обычными файлами: `git submodule update` не требуется.
Их внутренние символьные ссылки заголовков представлены содержимым соответствующих
файлов, чтобы исходники работали и после загрузки ZIP. Перечень преобразований —
`docs/export-symlinks.json`.

Версии сборки зафиксированы в Gradle: Gradle 8.13, Android Gradle Plugin 8.9.2,
Chaquopy 17.0.0, Python 3.12; Python runtime устанавливает
`httpx[http2,socks]==0.28.1` и `certifi==2026.2.25`.

Собственный код распространяется под [MIT](LICENSE). Лицензии сторонних файлов
продолжают действовать отдельно. Кеши, APK, готовые нативные бинарники, `local.properties`,
ключи подписи и локальные Git-каталоги в этот экспорт не включены.
