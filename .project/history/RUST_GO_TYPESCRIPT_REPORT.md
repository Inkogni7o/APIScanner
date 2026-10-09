# Текущее состояние

2026-10-09. Выполнен запрос: реальные Rust, Go и TypeScript scans после сообщения,
что анализ сработал только на Python. Предыдущий отчёт сохранён в
`history/SEMGREP_FRAMEWORK_REPORT.md`.

## Что изменено

- Rust parser Tree-sitter и extractors Axum, Actix Web, Rocket: HTTP routes,
  nest/merge/scope/resource/mount, атрибуты, локальные modules/aliases, factories,
  generic Router/handler references, extractors и Rocket path/query parameters.
- Go net/http ServeMux/HandleFunc, Chi Route/Group/With, Gorilla Mux Methods и
  PathPrefix/Subrouter. Исправлены Gin/Echo/Fiber registration helpers с router args,
  импортированные handlers из локальных go.mod packages и methods struct receivers.
- TypeScript `.mts`/`.cts`, import=require, tsconfig JSONC paths, named barrel exports,
  статические router factories, registration functions, controller instances/.bind;
  добавлены Hono basePath/route и Elysia prefix/group/use.
- Встроенные Command Injection, Path Traversal и SSRF для JS/TS, Go и Rust без
  обязательного Semgrep: HTTP collections/extractors, body binding, assignments,
  augmented assignments, transformations, branches, простой helper argument flow,
  command builders и client calls. Java security по-прежнему через Semgrep.
- Нормальный executable + user argv не Command Injection; fixed path + user content
  не Path Traversal. Constant reassignment очищает taint; uninvoked functions пропускаются.
- Rust macro expression view разбирает format!/обычные выражения и implicit captures;
  используются исходные byte/line positions и одна дополнительная Tree на файл.
- Scope-aware constants и полные expression span keys исправляют app shadowing и
  потерю ранних маршрутов в fluent chains. Inline mounted TS plugins не дублируются.
- Можно сканировать каталог или отдельный source file. CLI language=rust и новые
  --framework значения. Пустые Rust/Go/TS routes и некорректный tsconfig диагностируются.
- Шестое bundled Semgrep rule — Rust process execution; integration проверена.
- Модели Pydantic v2 и named constructors; except Exception отсутствует.
  Исходники сервиса не импортируются/не запускаются, scan local/offline.
- README и example JSON обновлены; агентские данные хранятся здесь и в CONTEXT.md.

## Проверки

- pytest: **185 passed, 4 skipped in 1.02s**; отдельные real Semgrep tests opt-in.
- Real Semgrep 1.179.0: **4 passed in 6.26s** — Python, Express, mixed Java/Go/TS/JS,
  Rust Axum. Native flow и Semgrep results сосуществуют без искажения correlation.
- Ruff check clean, format: 51 Python files; mypy strict: 37 source files, clean.
- FastAPI CLI: 9 endpoints/7 findings, /run 95, /proxy 80, /files/{filename} 70.
- CLI Rust Axum, Go Chi и TS service: каждый 4 endpoints/3 findings, без diagnostics.
- CLI source-file режим `.rs`/`.go`/`.mts`/`.cts` проверен вместе с language/framework filters.
- Fixtures: Axum 4/3, Actix 2/2, Rocket 2/2, Chi 4/3, net/http 2/2, Mux 2/2,
  TS service 4/3, Hono 2/2, Elysia 3/2 (endpoints/findings).
- Регрессии: multi-file helpers, body decode, controller methods, safe argv/content,
  constant/augmented assignments, raw/unicode Rust paths, macro helpers, factories
  с одноимённым app, dynamic prefixes, invalid source во всех трёх языках.
  Отдельно проверены Go http.Client и Rust reqwest Client builder.
- uv build --offline --cache-dir .uv-cache: wheel/sdist; uv lock --check: 83 packages.
- Wheel проверен из изолированного extracted package на 10 fixtures, включая Python
  baseline и все новые стеки. Содержит новые parser/extractor/flow modules и Rust YAML.
  Metadata имеет tree-sitter-rust и ограничение runtime <0.26. Sdist исключает .project/AGENTS.

## Среда и найденная несовместимость

Windows/Python 3.13.13, Pydantic 2.13.5, Tree-sitter **0.25.2**, Rust grammar 0.24.2.
На Tree-sitter 0.26.0 воспроизведён native access violation после Rust helper в format!
и следующего AST traversal; этот сбой нельзя ловить обычным except.
Dependency ограничена >=0.25,<0.26, lockfile обновлён. На 0.25.2 repro и полный suite
проходят. Upstream ссылки и решение находятся в CONTEXT.md.

Semgrep native executable в sandbox Windows не может читать certificate store;
real integration запускалась с разрешённым require_escalated, без remote scan.
Escalated pytest использовать с -k installed_semgrep_integration -p no:cacheprovider,
чтобы не использовать temp/cache от другого sandbox account.

## Команды

```powershell
.venv/Scripts/python.exe -m pytest -q
.venv/Scripts/ruff.exe check .
.venv/Scripts/ruff.exe format --check .
.venv/Scripts/python.exe -m mypy src/adscan
uv build --offline --cache-dir .uv-cache
uv lock --check --offline --cache-dir .uv-cache

.venv/Scripts/adscan.exe tests/fixtures/fastapi_vulnerable --no-color
.venv/Scripts/adscan.exe tests/fixtures/rust_axum --language rust -v
.venv/Scripts/adscan.exe tests/fixtures/go_chi --language go -v
.venv/Scripts/adscan.exe tests/fixtures/typescript_service --language typescript -v

# Real Semgrep, optional extra установлен:
$env:ADSCAN_TEST_SEMGREP='1'
.venv/Scripts/python.exe -m pytest tests/test_semgrep.py -k installed_semgrep_integration -q -p no:cacheprovider
```

`uv sync`/`uv run` без --extra semgrep могут удалить optional executable.
Интернет нужен для установки зависимостей, но не для анализа.

## Граница поддержки

Python taint остаётся intra-procedural; CST helper flow ограничен разрешимыми вызовами
и аргументами, без полного DI/closure/object-state/alias analysis. Unknown transforms
сохраняют taint, branches объединяются консервативно, loops обходятся один раз.
Привязка Semgrep через helper показывает достижимость, сама по себе не доказывает HTTP taint.
Go Mount с произвольным Handler factory, wildcard exports/tsconfig extends, сложные
runtime registrations/guards/hooks, Rust procedural macros и inline module/reexport
arrangements разрешаются не полностью. Статические routes перечисленных стеков покрыты
fixtures, это не обещание произвольного framework/DSL. При file scan соседние файлы
не добавляются: для сервиса нужен его корневой каталог.
OpenAPI, IDOR, secrets и остальные security rules исходного ТЗ ещё не реализованы.
