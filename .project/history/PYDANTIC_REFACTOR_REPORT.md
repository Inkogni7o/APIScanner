# Текущее состояние

Состояние на 2026-10-08. Выполнен FastAPI MVP и последующий рефакторинг по указаниям пользователя.

## Изменения

- Все модели и внутренние структуры переведены с dataclasses на Pydantic v2.
  Зависимость `pydantic>=2.11,<3` добавлена в pyproject/uv.lock.
- JSON сериализуется самим Report; прежний контракт schema version 1.0 сохранён.
- Ручная проверка типов конфигурации заменена Pydantic validation.
- Удалены универсальный обработчик CLI, перехваты RecursionError/LookupError,
  ограничения расширения/симлинка/output manifest, защитные fallback при чтении snippets
  и произвольное ограничение глубины router graph. Проверка циклов сохранена.
- README сокращён до пользовательского руководства; контекст, исходное ТЗ и история
  находятся в `.project/`, навигация и правила — в `AGENTS.md`.
- Служебные файлы исключены из project scanner и source distribution.

## Проверки

После окончательных правок:

- `pytest -q`: **90 passed in 0.73s**.
- `ruff check .`: All checks passed.
- `ruff format --check .`: 35 files already formatted.
- `mypy src/adscan`: 25 source files без ошибок, strict mode.
- `uv build --offline --cache-dir .uv-cache`: wheel и sdist успешно пересобраны.
- Состав sdist проверен: README включён, `.project/` и `AGENTS.md` исключены.
- Проверен импорт ADScan непосредственно из wheel и CLI с Pydantic окружения:
  9 endpoints, 7 findings; dependency metadata содержит `pydantic>=2.11,<3`.
- `uv lock --check --offline --cache-dir .uv-cache`: lock актуален, 18 packages.
- Проверены прежний JSON contract/round-trip, Unicode, копирование report при фильтрации,
  проброс неожиданных ошибок и запись output с произвольным расширением.

CLI и сериализация проверены на fixture `fastapi_vulnerable`: 9 endpoints и 7 findings;
/run CRITICAL 95, /proxy HIGH 80, /files/{filename} HIGH 70, /health INFO 0.

Локальные проверки выполняются на Windows/Python 3.13.13.
Предыдущая синтетическая проверка: 100005 lines, один handler, 2.276 seconds;
это результат до перехода на Pydantic, не актуальная performance гарантия.

## Рабочие команды

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\ruff.exe check src tests main.py
.\.venv\Scripts\ruff.exe format --check src tests main.py
.\.venv\Scripts\python.exe -m mypy src/adscan
.\.venv\Scripts\adscan.exe tests/fixtures/fastapi_vulnerable --no-color
```

Для uv в ограниченной среде можно направить cache в `.uv-cache` внутри проекта.
Сеть нужна для установки отсутствующих dependencies, а не для сканирования.
Runtime зависимость теперь Pydantic 2.11+ (в проверенном окружении — 2.13.5).
Используется `model_dump_json(indent=2)` с поддержкой Unicode по умолчанию;
`ensure_ascii` не передаётся, поскольку этот аргумент добавлен только в 2.12.
Артефакты в dist пересобраны с текущими моделями, dependency metadata и пользовательским README.
