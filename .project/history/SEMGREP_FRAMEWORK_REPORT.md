# Текущее состояние

2026-10-08. Выполнен запрос: Semgrep и parsers остальных фреймворков первого этапа ТЗ.
Предыдущий отчёт сохранён в history/PYDANTIC_REFACTOR_REPORT.md.

## Изменения

- Python AST: Flask Blueprint/decorators/add_url_rule, Django URLconf/include/class views,
  DRF api_view/routers/ViewSet/actions/inherited CRUD и generic views.
- Tree-sitter: Express ESM/CommonJS/routers/chains, Fastify plugins/route objects,
  NestJS controllers/params/guards/global prefix, Spring mappings/params/security,
  Gin/Echo/Fiber groups/middleware/request access.
- CLI --framework/--language, общие Pydantic модели, JSON/terminal для всех frameworks.
- Python dataflow расширен на Flask/Django/DRF request inputs.
- Optional Semgrep extra/CLI/config; local snapshot, metrics/version checks off,
  без remote configs/build/service execution. Пять bundled rules, custom local YAML.
- Статические helper chains связывают findings через imports/self/this/local package,
  cycle guard и line/column spans. Непривязанные находки сохраняются.
- Schema 1.1 добавляет unmatched_findings; 1.0 документы читаются.
- Semgrep score учитывает severity, не утверждает недоказанный HTTP taint.
- Fixtures/tests для всех новых стеков, README/example JSON обновлены.
- Pydantic и узкие обработчики ожидаемых ошибок сохранены, except Exception отсутствует.

## Проверки

- pytest: **138 passed, 3 skipped in 0.98s** (real Semgrep — opt-in).
- Real Semgrep 1.179.0: **3 passed in 5.56s**. Python helper/unmatched, Express imported
  helper, multilingual NestJS/Spring/Go/Fastify fixture. Всего 141 успешная проверка.
- Ruff check: clean; format: 47 files already formatted.
- Mypy strict: 34 source files, clean.
- uv build --offline --cache-dir .uv-cache: wheel/sdist построены.
- uv lock --check --offline --cache-dir .uv-cache: 82 packages, актуален.
- Wheel содержит semgrep.yml/optional extra metadata, sdist исключает .project/AGENTS.md.
- Из wheel проверены все fixtures: FastAPI vulnerable 9 endpoints/7 findings,
  Flask 5/4, Django/DRF 5/3, Express 4, Fastify 3, NestJS 2, Spring 6,
  Gin/Echo/Fiber по 2 endpoints.
- FastAPI baseline сохранён: /run 95, /proxy 80, /files/{filename} 70.

Среда: Windows/Python 3.13.13, Pydantic 2.13.5, Tree-sitter 0.26.0.
Semgrep native binary в sandbox не мог читать Windows certificate store;
для настоящих integration tests использован разрешённый require_escalated.
Сетевой scan не включался. Escalated pytest запускать через -k installed_semgrep_integration
-p no:cacheprovider: обычный pytest temp создан другим sandbox account, вызывает ACL errors.

## Команды

```powershell
.venv/Scripts/python.exe -m pytest -q
.venv/Scripts/ruff.exe check .
.venv/Scripts/ruff.exe format --check .
.venv/Scripts/python.exe -m mypy src/adscan
uv build --offline --cache-dir .uv-cache
uv lock --check --offline --cache-dir .uv-cache

# Real Semgrep (extra должен быть установлен):
uv sync --extra semgrep --cache-dir .uv-cache
$env:ADSCAN_TEST_SEMGREP='1'
.venv/Scripts/python.exe -m pytest tests/test_semgrep.py -k installed_semgrep_integration -q -p no:cacheprovider
.venv/Scripts/adscan.exe tests/fixtures/semgrep --semgrep --semgrep-binary .venv/Scripts/semgrep.exe
```

uv run без --extra semgrep может удалить optional executable из .venv.
Интернет требуется для установки, сканирование local/offline.

## Ограничения

Встроенный taint — intra-procedural Python. Semgrep helper correlation показывает
достижимость, не доказывает передачу HTTP input. Runtime routes/factories, middleware order,
DI/global hooks/guards, Spring security chains, сложные scopes/reexports и передача
Go router в registration functions разрешаются не полностью. Bundled Semgrep rules —
triage операций, не полный security ruleset; custom YAML расширяет анализ.
OpenAPI, IDOR, secrets и прочие security rules исходного ТЗ ещё не реализованы.
