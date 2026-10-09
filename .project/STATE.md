# Текущее состояние

2026-10-09. Выполнен запрос: найти кастомные Semgrep rules в интернете и подключить
их по умолчанию. Пользователь уточнил: **только с флагом --semgrep**; обычный scan
не запускает внешний движок. Предыдущий отчёт сохранён в
`history/RUST_GO_TYPESCRIPT_REPORT.md`, более ранние этапы — в остальных history files.

## Что изменено

- Default Semgrep selection: **81 правило** — шесть ADScan, 48 GitLab SAST rules и
  27 njsscan. Это 67 локальных YAML-файлов, поставляемых внутри Python package.
- GitLab snapshot: `53bf5cf6df3c51b6c02110f5a638b5e6213666cd`; njsscan snapshot:
  `4137df39e743e07e912a31ca7dab19633f40324a`. Выбранные YAML сохранены byte-for-byte.
- Покрытие Python/Go/Java/JS/TS расширено SQL/NoSQL injection, XSS, XXE, SSTI,
  SSRF, path traversal/archives, deserialization, TLS, JWT и опасными настройками.
  Rust использует собственное process-execution rule; сторонних Rust rules нет.
- `rules/third_party/`: оригинальные licenses, дополнительные Apache-2.0/GPL-3.0
  тексты, README атрибуции, provenance.json с commit/path/IDs/SHA-256 для каждого файла.
  GitLab MIT, gosec-derived Go rules Apache-2.0, njsscan LGPL-3.0.
- Runner выбирает bundled YAML только при отсутствии явных configs. Поведение
  `--semgrep-config` сохранено: полностью заменяет defaults и явно включает движок.
  Config.semgrep_enabled остаётся False, optional dependency extra не изменён.
- GitLab metadata `security-severity` и `shortDescription` используются для severity
  и title; явные `severity`/`title` имеют приоритет. High/Critical/Low/Info сохраняются.
- Добавлена multilang fixture с vulnerable/safe SQL, TLS, XSS, NoSQL и XXE cases,
  cross-file Python helper и unmatched Java DB password. Проверяется severity/score,
  helper chain, сохранение unmatched и отсутствие findings в безопасных маршрутах.
- Регрессии default selection, override и integrity snapshot/unique rule IDs.
  Старые integration assertions выделяют собственные adscan rules, чтобы расширенные
  находки не ломали проверку исходного coverage.
- README обновлён для человека; CONTEXT.md содержит решения, источники и лицензии.
  `.project/vendor_semgrep.py` воспроизводит vendoring из локальных pinned archives;
  `.project/check_semgrep_package.py` проверяет wheel/sdist и CLI из isolated wheel.
  Игнорируются `.project/vendor-cache/` и `.project/package-check/`.
- Scan по-прежнему полностью локальный: selected-source snapshot, metrics/version
  check off, временные settings/logs, без токена, загрузок rules и запуска service code.
  Новых dependency, error handlers, моделей или изменений native dataflow не добавлено.

## Проверки

- pytest: **191 passed, 5 skipped in 1.17s**; real Semgrep tests opt-in.
- Real Semgrep 1.179.0: **5 passed in 37.99s** — старые Python/Express/mixed/Rust
  интеграции и новая community fixture Python/Go/TS/JS/Java. Все rules компилируются,
  diagnostics отсутствуют, безопасные варианты не дают findings.
- Ruff check clean; format --check: 52 files; mypy strict: 37 source files, clean.
- FastAPI CLI без Semgrep: baseline 9 endpoints/7 findings, /run 95, /proxy 80,
  /files/{filename} 70, diagnostics=[] — исходное поведение сохранено.
- uv lock --check --offline: 83 packages; uv build --offline: wheel и sdist собраны.
- Все bundled rules/provenance/licenses побайтово проверены в wheel И sdist;
  `.project/` и AGENTS.md отсутствуют. CLI isolated wheel с `--semgrep`:
  12 endpoints/8 attached findings/1 unmatched, diagnostics=[], safe routes пустые.

## Как повторить

```powershell
.venv/Scripts/python.exe -m pytest -q
.venv/Scripts/ruff.exe check .
.venv/Scripts/ruff.exe format --check .
.venv/Scripts/python.exe -m mypy src/adscan
.venv/Scripts/adscan.exe tests/fixtures/fastapi_vulnerable --format json

# Optional extra установлен:
$env:ADSCAN_TEST_SEMGREP='1'
.venv/Scripts/python.exe -m pytest tests/test_semgrep.py -k installed_semgrep -q -p no:cacheprovider
uv build --offline --cache-dir .uv-cache
.venv/Scripts/python.exe .project/check_semgrep_package.py
```

В этой Windows sandbox среде Semgrep initialization требует чтения системного
certificate store вне sandbox: real checks выполнены с разрешённой эскалацией.
Это не сетевой запрос. `uv sync`/`uv run` без --extra semgrep могут удалить executable.
В lock tree-sitter 0.25.2: ограничение <0.26 из-за воспроизведённого Windows native
heap crash, подробности в CONTEXT.md и предыдущем отчёте.

## Граница поддержки

Новый набор — проверенная выборка, не весь upstream каталог. Часть правил — taint,
часть — audit patterns: findings требуют ручной проверки; confidence по metadata,
связь с helper доказывает достижимость, а не HTTP taint. Framework/import-specific
patterns могут не совпадать с иной формой записи. Обновление snapshot выполняется
при разработке, автоматически во время анализа правила не обновляются.

Python native taint intra-procedural, CST helpers требуют статически разрешимых
вызовов/аргументов; полного DI/closure/object-state/alias analysis нет. Поддержаны
Python FastAPI/Flask/Django/DRF, JS/TS Express/Fastify/NestJS/Hono/Elysia, Go
Gin/Echo/Fiber/net-http/Chi/Mux, Rust Axum/Actix/Rocket, Java Spring. Runtime routes,
complex factories, Rust procedural macros и wildcard/сложные exports не полностью
разрешаются. При file scan соседние файлы не включаются.

OpenAPI, IDOR и полноценный native secrets engine остаются следующими этапами.
Некоторые password/config issues теперь доступны через сторонние Semgrep rules.
