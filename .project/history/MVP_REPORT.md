# FastAPI MVP: результат первого этапа

> Исторический отчёт до перехода на Pydantic. Текущее устройство и результаты
> проверок записаны в `../CONTEXT.md` и `../STATE.md`.

Реализован первый этап ТЗ. Другие framework extractors относятся к следующим этапам.

## Структура

```text
pyproject.toml, uv.lock, README.md, main.py
src/adscan/
  __init__.py, __main__.py, cli.py, config.py, scanner.py
  models/__init__.py
  detector/{project,language,framework}.py
  parsers/python.py
  extractors/{base,fastapi}.py, __init__.py (registry)
  analysis/{sources,sinks,auth,dataflow,scoring}.py
  rules/__init__.py
  output/{terminal,json}.py
tests/
  test_detection.py, test_extraction.py, test_dataflow.py
  test_scoring.py, test_cli.py, test_config.py
  fixtures/{fastapi_basic,fastapi_vulnerable,fastapi_routers}/
docs/{MVP_REPORT.md,example-report.json}
```

## Архитектурные решения

- Python 3.13+, стандартный AST, argparse, dataclasses, tomllib; runtime dependencies отсутствуют.
- Раздельные detection, parsing, extraction, flow analysis, rules, scoring и renderers.
- Extractor выбирается через registry. Префиксы строятся по графу include_router.
- Анализируется тело handler; helpers записываются в called_functions без межпроцедурного flow.
- HTTP sources отслеживаются до command/file/HTTP sinks с записью locations и шагов.
- Severity findings и priority endpoints разделены; каждый фактор score имеет объяснение.
- JSON schema 1.0 детерминированна и использует относительные пути.
- Пропуски и parser errors диагностируются с -v/--debug, не прерывая весь анализ.

## CLI help

```text
usage: adscan [-h] [--format {terminal,json}] [--output OUTPUT]
              [--severity {INFO,LOW,MEDIUM,HIGH,CRITICAL}] [--method METHOD]
              [--show-code] [--no-color] [--framework {fastapi}]
              [--language {python}] [--include-tests] [-v] [--debug]
              [--version]
              path [{scan,endpoints,findings,endpoint}] [endpoint_path]

Offline static security triage for FastAPI source code.

positional arguments:
  path                  project source directory
  {scan,endpoints,findings,endpoint}
  endpoint_path         exact route path for the endpoint command

options:
  -h, --help            show this help message and exit
  --format {terminal,json}
                        stdout format (default: terminal)
  --output OUTPUT       save JSON report; stdout keeps the selected format
  --severity {INFO,LOW,MEDIUM,HIGH,CRITICAL}
                        minimum finding severity / endpoint priority
  --method METHOD       filter HTTP method, e.g. GET or POST
  --show-code           show source around findings
  --no-color            disable terminal ANSI colors
  --framework {fastapi}
                        force FastAPI extraction
  --language {python}   select the implemented Python analyzer
  --include-tests       include nested test directories and test_*.py
  -v, --verbose         show parser and scanner diagnostics on stderr
  --debug               show diagnostics and traceback on unexpected errors
  --version             show program's version number and exit

Examples: adscan ./service; adscan ./service endpoint '/files/{name}'; adscan
./service --output report.json. Findings are heuristic and require manual
review.
```

## Запуск fixture

```bash
adscan tests/fixtures/fastapi_vulnerable --no-color
```

```text
ADScan 0.1.0

Project:
  Languages: Python
  Frameworks: FastAPI
  Entry points: main.py

Files scanned: 2; Python files parsed: 1
Endpoints: 9
Findings: 7

Priority endpoints:

CRITICAL   95  POST    /run
               Command Injection
               main.py:38

HIGH       80  POST    /body-proxy
               SSRF
               main.py:43

HIGH       80  POST    /json-proxy
               SSRF
               main.py:48

HIGH       80  GET     /proxy
               SSRF
               main.py:33

HIGH       80  POST    /upload
               Path Traversal
               main.py:64

HIGH       70  GET     /files/{filename}
               Path Traversal
               main.py:27

HIGH       60  GET     /private/files/{filename}
               Path Traversal
               main.py:53

INFO        0  GET     /health
               main.py:22

INFO        0  GET     /users/{id}
               main.py:58

Heuristic analysis: findings require manual review.
```

JSON того же сканирования: [example-report.json](../../docs/example-report.json).

## Подробности endpoint

```bash
adscan tests/fixtures/fastapi_vulnerable endpoint "/files/{filename}"
```

```text
GET /files/{filename}
  Location: main.py:27
  Handler: read_file
  Authentication: not recognized
  Priority: HIGH; score: 70

Parameters:
  filename: path, str, required=True

Score reasons:
  +20 file sink receives HTTP input
  +25 client-controlled value reaches a sink
  +15 intra-procedural data flow
  +10 authentication dependency not recognized

Called functions (calls are not followed in this MVP):
  open
  local.handle.read

Findings:
HIGH Path Traversal
  GET /files/{filename}
  main.py:28
  Confidence: HIGH
  Source: path parameter 'filename'
  HTTP input influences a filesystem path. Review canonicalization and directory containment.
  Data flow:
    filename (main.py:27)
    -> '/tmp/' + filename (main.py:28)
    -> open('/tmp/' + filename) (main.py:28)
```

## Проверки

Локальная среда: Windows, Python 3.13.13. Linux/macOS локально не запускались.

```text
python -m pytest -q
84 passed in 0.37s

ruff check src tests main.py
All checks passed!

ruff format --check src tests main.py
32 files already formatted

python -m mypy src/adscan
Success: no issues found in 25 source files
```

Покрыты detection, routes, nested/repeated prefixes, parameters, auth evidence,
request sources, sink selection, taint assignments/branches/loops/mutations,
negative cases, scoring, configuration, JSON и CLI subprocess integration.

Собран wheel `dist/adscan-0.1.0-py3-none-any.whl`. Он установлен через
`uv pip install --offline --no-deps` в отдельное окружение без FastAPI, requests
и development dependencies. `python -I -m adscan` из этого окружения успешно
проанализировал fixture: 9 endpoints, 7 findings. Код сервиса не импортировался.
Build backend использован из уже имеющегося локального cache.

Синтетическая проверка производительности: 100005 lines; 2.276 seconds; 1 endpoint; 0 findings.
Пример содержит один handler и много недостижимых helper functions. Он проверяет
обход/AST parsing и выбор handlers, но не гарантирует время анализа реального
репозитория или большого количества endpoints.

## Границы этапа

Finding требует ручной проверки. Runtime-generated routes, сложные scopes,
полный call graph, SQLi/IDOR/SSTI, другие framework extractors, OpenAPI, Semgrep
и secret scanning пока не реализованы. Ограничения и установка — в [README](../../README.md).
