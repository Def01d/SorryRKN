# Компоненты Windows 1.1.0

Собственный код SorryRKN распространяется по [MIT](LICENSE). Лицензии сторонних компонентов сохраняются в `licenses/` и в `dist-info` Python-пакетов восстановленного runtime. Они не заменяются лицензией приложения.

| Компонент | Источник и версия | Лицензия в исходниках |
| --- | --- | --- |
| Профили Flowseal | [zapret-discord-youtube 1.10.3](https://github.com/Flowseal/zapret-discord-youtube/tree/1.10.3) | `licenses/zapret-MIT.txt` |
| Telegram-прокси | [tg-ws-proxy, снимок 50c980e9ea7460f4a52ef795b5abc4682a15f8a3](https://github.com/Flowseal/tg-ws-proxy/tree/50c980e9ea7460f4a52ef795b5abc4682a15f8a3), адаптация находится в `runtime/app/proxy` | `licenses/Flowseal-tg-ws-proxy-MIT.txt` |
| zapret/winws | [bol-van/zapret](https://github.com/bol-van/zapret), бинарный runtime сообщает v72.9 и commit `c849e55ef0f1c244206f5a05ff7b1ab41a3824ee` | `licenses/zapret-MIT.txt` |
| WinDivert | [basil00/WinDivert](https://github.com/basil00/WinDivert), неизменённые DLL и драйвер из закреплённого runtime | `licenses/WinDivert-LGPL3.txt` |
| Cygwin | [Cygwin](https://cygwin.com/), неизменённая DLL из закреплённого runtime | `licenses/Cygwin-License.txt` |
| CPython | [Python 3.12.10](https://www.python.org/downloads/release/python-31210/), Windows embeddable x64 | `licenses/Python.txt` |
| Go | [Go](https://go.dev/) | `licenses/Go-BSD.txt` |
| golang.org/x/sys, x/net, x/text | Версии и хеши закреплены в `go.mod` / `go.sum` | `licenses/golang-x-*-BSD.txt` |
| Генератор ресурсов | [go-winres v0.3.3](https://github.com/tc-hib/go-winres/tree/v0.3.3), используется при сборке | Лицензия upstream; бинарник в исходники не включён |

Точный архив стороннего runtime и его SHA-256 указаны в [BUILD.md](BUILD.md). Он содержит готовые профили, поэтому исходные BAT-утилиты Flowseal для сборки приложения не нужны. В этом экспорте нет собранных EXE, DLL, драйверов или установленного Python. Сам Telegram-прокси включён исходниками; его локальный запуск получает секрет от приложения через stdin и создаёт настройки отдельно от каталога программы.

При распространении собранных сторонних компонентов сохраняйте их лицензионные уведомления и выполняйте требования соответствующих лицензий. Этот исходный архив относится к приложению SorryRKN и его адаптации Telegram-прокси; он не является архивом всех исходников CPython, WinDivert или Cygwin.

## Исходные версии бинарных компонентов

В строках сборки и PDB-путях закреплённого runtime указаны WinDivert 2.2.2 и Cygwin 3.4.10. Исходники соответствующих upstream-версий доступны отдельно:

- [WinDivert v2.2.2](https://github.com/basil00/WinDivert/tree/v2.2.2), [лицензия](https://raw.githubusercontent.com/basil00/WinDivert/v2.2.2/LICENSE).
- [Cygwin 3.4.10](https://cygwin.com/cgit/newlib-cygwin/tree/?h=cygwin-3.4.10), [лицензия](https://cygwin.com/cgit/newlib-cygwin/plain/winsup/CYGWIN_LICENSE?h=cygwin-3.4.10).

Это ссылки на указанные upstream-версии; побайтная воспроизводимость сторонних DLL из этих исходников здесь не проверена.
