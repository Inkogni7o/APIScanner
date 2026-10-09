# ADScan

Локальный CLI для быстрого первичного анализа исходников веб-сервиса в Attack/Defense.
Находит HTTP-маршруты, показывает обработчики и входные параметры, отмечает
потенциально опасные потоки данных и сортирует endpoints по приоритету проверки.

Анализ работает с исходным кодом без запуска сервиса и установки его зависимостей.
После установки ADScan интернет для сканирования не нужен.

## Установка

Требуется Python 3.13+.

```bash
python -m pip install .
adscan ./service
```

Или через uv:

```bash
uv sync
uv run adscan ./service
```

## Использование

```bash
adscan ./service                                  # сводка по приоритетам
adscan ./service endpoints                        # все маршруты
adscan ./service findings                         # только находки
adscan ./service endpoint "/files/{filename}"      # подробности маршрута
adscan ./service endpoint "/proxy" --method GET     # выбрать HTTP-метод
adscan ./service --show-code                       # фрагменты кода возле находок
adscan ./service --severity high                   # высокий приоритет и выше
adscan ./service --format json                     # JSON в stdout
adscan ./service --output report.json              # сохранить JSON и показать сводку
adscan ./service -v                                # диагностика пропущенных файлов/маршрутов
adscan ./rust-service --language rust              # Rust-проект целиком
adscan ./go-service --language go                  # Go-проект целиком
adscan ./ts-service --language typescript          # TypeScript-проект целиком
adscan ./service/main.rs --framework axum           # отдельный исходный файл
adscan --help                                     # все параметры
```

`--severity` фильтрует приоритет endpoints в сводке и severity находок в режиме
`findings`. `--output` сохраняет JSON по указанному пути; stdout остаётся в выбранном
формате. Для отключения цветов используйте `--no-color` или переменную `NO_COLOR`.

Для анализа сервиса укажите его корневой каталог с `Cargo.toml`, `go.mod` или
`tsconfig.json`: тогда обработчики и helpers из других файлов тоже доступны анализу.
При выборе отдельного файла анализируется только он.

## Что анализируется

| Стек | Извлечение маршрутов |
| --- | --- |
| FastAPI | HTTP-декораторы, `api_route`, `add_api_route`, вложенные `APIRouter` и префиксы |
| Flask | Декораторы, `add_url_rule`, вложенные и повторно зарегистрированные Blueprint |
| Django | `path`, `re_path`, вложенные `include`, функции и HTTP-методы class views |
| Django REST Framework | `api_view`, APIView/generic views, SimpleRouter/DefaultRouter, ViewSet и `action` |
| Express | ESM/CommonJS и `import = require`, Router, вложенные `use`, `route().get().post()`, простые factories и функции регистрации |
| Fastify | Короткие методы, `route({...})`, локальные plugins через `register` и их префиксы |
| NestJS | Controller, HTTP-декораторы, декораторы параметров, guards, статический global prefix |
| Spring Boot / MVC | Controller/RestController, class/method mappings, параметры и security annotations |
| Gin / Echo / Fiber | Конструкторы, HTTP-методы, вложенные Group, middleware, функции регистрации с router-аргументами |
| Go net/http | ServeMux и глобальный HandleFunc/Handle, шаблоны с HTTP-методом, функции регистрации |
| Chi | NewRouter/NewMux, HTTP-методы, Route/Group, With/Use и функции регистрации |
| Gorilla Mux | NewRouter, HandleFunc/Handle, Methods, PathPrefix/Subrouter |
| Axum | Router, route, nest, merge, цепочки HTTP-методов, локальные router factories и extractors Path/Query/Json/Form |
| Actix Web | App, scope/resource, service/route/configure, HTTP-атрибуты и web extractors |
| Rocket | HTTP-атрибуты, mount/routes!, path/query параметры |
| Hono | New Hono, HTTP-методы, basePath и вложенные route |
| Elysia | New Elysia, HTTP-методы, prefix, group и простые use plugins |

В отчёт попадают методы, пути, обработчики, расположение в исходниках, входные параметры
и распознанные признаки аутентификации. Поддерживаются Python, JavaScript,
TypeScript (`.ts`, `.tsx`, `.mts`, `.cts`), Java, Go и Rust. Regex-маршруты Django
сохраняются как `regex:...`; неизвестный набор HTTP-методов обозначается `ANY`.
Неявные HEAD/OPTIONS, создаваемые самим фреймворком, не добавляются.

Встроенные проверки Command Injection, Path Traversal и SSRF работают для Python,
JavaScript/TypeScript, Go и Rust без Semgrep. Они учитывают HTTP-входы, присваивания,
преобразования и опасные операции; в JS/TS, Go и Rust также прослеживают переданные
аргументы простых локальных helpers. Для Java проверки безопасности доступны через Semgrep.
В TypeScript распознаются статические aliases из `tsconfig.json` и именованные reexports;
в Go — локальные импорты пакетов по `go.mod`, в Rust — обычные импорты модулей.
`--framework drf`, `--framework express`, `--framework spring` и другие значения
выбирают extractor; `--language typescript` фильтрует endpoints по языку.

| Находка | Что проверять |
| --- | --- |
| Command Injection | Пользовательские данные в shell, динамическом коде или выборе executable |
| Path Traversal | Пользовательские данные в пути чтения, записи, удаления или отправки файла |
| SSRF | Пользовательские данные в URL исходящего HTTP-запроса |

## Semgrep

Semgrep — опциональный дополнительный движок: обычный скан его не запускает.
Установите его вместе с ADScan и включайте явно через `--semgrep`:

```bash
python -m pip install '.[semgrep]'
# или
uv sync --extra semgrep
uv run --extra semgrep adscan ./service --semgrep
```

```bash
adscan ./service --semgrep                         # встроенный локальный набор правил
adscan ./service --semgrep-config ./rules.yml       # собственные локальные правила
adscan ./service --semgrep-config ./a.yml --semgrep-config ./b.yml
adscan ./service --semgrep --semgrep-binary /path/to/semgrep
```

С `--semgrep` по умолчанию используются **81 локальное правило**: шесть правил ADScan,
48 из [GitLab SAST rules](https://gitlab.com/gitlab-org/security-products/sast-rules)
и 27 из [njsscan](https://github.com/ajinabraham/njsscan). Набор расширяет проверки Python,
Go, Java и JS/TS: SQL/NoSQL injection, XSS, SSRF, path traversal, XXE, template injection,
опасная десериализация, настройки TLS и JWT. Для Rust сохранена проверка запуска процессов.
Часть правил отслеживает поток данных, часть отмечает опасную операцию или настройку:
эксплуатируемость нужно проверять вручную.

Правила поставляются с пакетом в зафиксированных версиях и не скачиваются при сканировании.
Источники, версии и лицензии описаны в
[каталоге сторонних правил](src/adscan/rules/third_party/README.md).
`--semgrep-config` заменяет весь набор по умолчанию и включает Semgrep автоматически;
registry-конфиги и URL не принимаются.

Semgrep получает только выбранные исходники, локальные правила, отключённые metrics
и проверку версии. Сервис и его сборка не запускаются. Такой режим соответствует
[локальному CLI Semgrep](https://docs.semgrep.dev/cli-reference).

Находки с `rule_id: "semgrep:..."` привязываются к handler или статически разрешённым
локальным helper calls, включая вызовы из другого файла. Цепочка вызовов показывается
в подробностях endpoint. Находки без известного маршрута сохраняются в
`unmatched_findings` и выводятся в сводке и режиме `findings`.

## Как читать отчёт

Пример:

```text
Endpoints: 9
Findings: 7

CRITICAL   95  POST  /run
               Command Injection
               main.py:38

HIGH       80  GET   /proxy
               SSRF
               main.py:33

HIGH       70  GET   /files/{filename}
               Path Traversal
               main.py:27

INFO        0  GET   /health
               main.py:22
```

Число возле endpoint — **score**. Его причины, входные параметры, source → sink
цепочка и confidence доступны в режиме `endpoint`. Priority endpoint и severity
отдельной находки — разные оценки.

Пороги priority: `0–19 INFO`, `20–39 LOW`, `40–59 MEDIUM`, `60–89 HIGH`, `90+ CRITICAL`.
Confidence (`LOW`, `MEDIUM`, `HIGH`) описывает уверенность в распознанном потоке данных.
Для Semgrep confidence берётся из metadata правила; score учитывает severity самой
находки, не утверждая наличие HTTP source → sink потока. Совпадающие результаты
одного правила не повышают score повторно. JSON schema `1.1` добавляет `unmatched_findings`.
Пример полного JSON: [docs/example-report.json](docs/example-report.json).

## Конфигурация

Создайте `.adscan.toml` в корне анализируемого сервиса:

```toml
[analysis]
include_tests = false
max_file_bytes = 2000000

[severity]
minimum = "info"

[output]
color = true

[ignore]
paths = ["generated", "src/legacy/*"]

[semgrep]
enabled = false
configs = []               # локальные YAML относительно корня сервиса; [] = встроенные
binary = "semgrep"
timeout_seconds = 120
```

Каталоги зависимостей, сборки, caches и вложенные тесты по умолчанию пропускаются.
Чтобы включить тесты, передайте `--include-tests`. Ошибка в одном исходном файле
не прерывает анализ остальных; диагностика доступна с `-v` или `--debug`.

## Ограничения

ADScan выполняет эвристический статический анализ. **Finding не доказывает наличие
уязвимости** — результаты требуют ручной проверки.

Для Python встроенные потоки отслеживаются внутри одной функции. В JS/TS, Go и Rust
анализ helpers ограничен статически разрешёнными вызовами и передачей аргументов:
DI, отражение, сложные замыкания и состояние объектов учитываются не полностью.
Привязка находки Semgrep
через helper показывает достижимость операции, но сама по себе не доказывает передачу
пользовательских данных. Для наследуемого обработчика DRF, реализация которого находится
в установленном framework, указывается строка класса; внешнее тело не анализируется.
Динамически созданные маршруты и сложные runtime prefixes могут быть пропущены.
Сложные runtime factories, DI, global guards, Spring Security filter chains, порядок
middleware и wildcard reexports разрешаются не полностью. Go Mount с произвольным
Handler factory, TypeScript `tsconfig extends` и Rust procedural macros, генерирующие
маршруты, пока не поддерживаются. Fastify autoload и глобальные hooks не извлекаются.
Наличие или отсутствие распознанной security dependency не гарантирует состояние
аутентификации в работающем приложении. Возможны false positives и false negatives.
