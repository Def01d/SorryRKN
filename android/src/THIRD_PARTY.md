# Происхождение сторонних компонентов

`LICENSE` в корне относится к собственному коду проекта. Он не заменяет лицензии
сторонних компонентов. Сохраняйте их уведомления при распространении исходников
и бинарных сборок. Все тексты, отображаемые приложением, находятся в
`app/src/main/assets/licenses/`.

| Компонент | Исходники в проекте | Лицензия / источник |
| --- | --- | --- |
| [Flowseal/tg-ws-proxy](https://github.com/Flowseal/tg-ws-proxy) | `app/src/main/python/proxy/`, с изменениями SorryRKN | MIT; `app/src/main/assets/licenses/tg-ws-proxy.txt` |
| [bol-van/zapret](https://github.com/bol-van/zapret), tpws | `third_party/tpws/` | MIT; `third_party/tpws/LICENSE` |
| [hufrea/byedpi](https://github.com/hufrea/byedpi) | `third_party/byedpi/` | MIT; `third_party/byedpi/LICENSE` |
| [heiher/hev-socks5-tunnel](https://github.com/heiher/hev-socks5-tunnel) | `third_party/hev-socks5-tunnel/` | MIT; лицензия рядом с исходниками |
| [heiher/hev-socks5-core](https://github.com/heiher/hev-socks5-core) | `third_party/hev-socks5-tunnel/src/core/` | MIT; лицензия рядом с исходниками |
| [heiher/hev-task-system](https://github.com/heiher/hev-task-system) | `third_party/hev-socks5-tunnel/third-part/hev-task-system/` | MIT; лицензия рядом с исходниками |
| [heiher/lwip](https://github.com/heiher/lwip) | `third_party/hev-socks5-tunnel/third-part/lwip/` | BSD-3-Clause; лицензия рядом с исходниками |
| [heiher/yaml](https://github.com/heiher/yaml), fork libyaml | `third_party/hev-socks5-tunnel/third-part/yaml/` | MIT; `License` и `LICENSE-libyaml` рядом с исходниками |
| [Flowseal/zapret-discord-youtube](https://github.com/Flowseal/zapret-discord-youtube) | Совместимые данные/стратегии в `bundled-data.json`, преобразования в `bridge_data.py` | MIT-уведомления Flowseal/bol-van в `licenses/Flowseal-zapret-discord-youtube.txt`; Windows-программы этого проекта не входят в Android APK |

Исходные коммиты перечислены в `docs/upstream-lock.json`. Для четырёх вложенных
HEV-компонентов точные коммиты перечислены в `docs/hev-submodules.txt`. Это
версионированные снимки с локальными изменениями, а не заявление об идентичности
текущему upstream. Например, HEV `Android.mk` исключает пример upstream JNI,
поскольку приложение использует собственный `native/bridge.c`, и содержит флаги
линковки для страниц 16 КБ. Python-прокси адаптирован для Android и локальной
маршрутизации.

Полный исходный файл лицензии Flowseal сохранён без изменений, включая его
уведомление о WinDivert. Сам WinDivert в Android-сборку и этот набор исходников
не включён.

Вложенные заголовки HEV, представленные upstream символьными ссылками, экспортированы
как обычные файлы с тем же содержимым; соответствия указаны в
`docs/export-symlinks.json`. Папки `.git`, gitlinks и внешние пути в экспорт не входят.

Файлы `Android.mk` с уведомлением Android Open Source Project сохраняют свою
лицензию Apache-2.0. В отдельных исходных файлах могут быть дополнительные
уведомления их авторов; они сохранены вместе с кодом.

Дополнительно включён неизменённый [License libyaml 0.2.5](https://github.com/yaml/libyaml/blob/0.2.5/License)
с уведомлениями Ingy döt Net и Kirill Simonov: HEV-снимок сохраняет свою MIT-лицензию
отдельно. SHA-256 файла `LICENSE-libyaml`:
`c40112449f254b9753045925248313e9270efa36d226b22d82d4cc6c43c57f29`.

Gradle wrapper (`gradlew`, `gradlew.bat`, `gradle/wrapper/gradle-wrapper.jar`) —
загрузчик [Gradle 8.13](https://github.com/gradle/gradle/tree/v8.13.0), Apache-2.0.
Полные уведомления сохранены в `licenses/Gradle-LICENSE.txt` и
`licenses/Gradle-NOTICE.txt`. Это единственный исполняемый бинарный компонент исходного экспорта; он нужен для
воспроизводимого выбора версии Gradle, а не для сетевого движка приложения.

Chaquopy, Python, HTTPX и их транзитивные зависимости скачиваются при сборке.
Их уведомления входят в `app/src/main/assets/licenses/`; в частности, CA bundle
certifi имеет собственные условия Mozilla Public License, а Python — лицензию PSF.
Зависимости для тестов устанавливаются отдельно из `requirements-dev.txt`.
