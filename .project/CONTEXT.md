# Контекст проекта для агента

## Назначение и текущая граница

ADScan — локальный CLI для первичного security triage веб-сервисов Attack/Defense.
Полное исходное ТЗ находится в `SPEC.md` (61 раздел). Реализованы extractors FastAPI,
Flask, Django/DRF, Express, Fastify, NestJS, Hono, Elysia, Spring MVC/Boot,
Gin/Echo/Fiber, Go net/http/Chi/Gorilla Mux и Rust Axum/Actix Web/Rocket,
а также опциональный локальный Semgrep. Наличие finding — повод для ручной проверки,
а не доказательство уязвимости.

Последнее решение пользователя: Pydantic для моделей; служебные записи отдельно
от README; без перестраховочных обработок маловероятных ошибок.
Для нового набора правил Semgrep пользователь явно выбрал: «Только с флагом --semgrep».
Обычный scan не запускает Semgrep; существующие явные config/binary flags также включают его.
Это заменяет первоначальное решение использовать dataclasses и отсутствие runtime dependencies.

## Архитектура

Pipeline: project detection → Python AST / Tree-sitter indexes → extractor registries →
Python / CST handler dataflow + helper reachability → optional Semgrep snapshot scan →
normalized/correlated findings → scoring → terminal/JSON.

- `models/`: Pydantic-модели публичного отчёта.
- `config.py`: TOML конфигурация; значения валидируются Pydantic.
- `detector/`: детерминированный обход исходников/manifest files и определение стека.
- `parsers/python.py`: AST, imports/reexports, простые константы и function references.
- `parsers/cst.py`: Tree-sitter JS/TS/TSX/Java/Go/Rust, imports, scoped constants,
  local functions, receiver types, TS named reexports/tsconfig paths, Go go.mod
  packages, Rust use aliases/module paths/turbofish. `.mts`/`.cts` — TypeScript.
- `analysis/cst_dataflow.py`: Pydantic CSTFlow/Value, HTTP collections/extractors,
  assignments/transforms, body binding, branches, command builders/HTTP clients,
  resolved helper arguments/returns. Java здесь пропускается: security через Semgrep.
- `extractors/`: Python `BaseExtractor`, `CSTExtractor` и отдельные registries.
  `ExtractedEndpoint.handler=None` для inherited DRF методов внешнего framework:
  у них реальное имя метода/строка класса, но не выдуманное тело функции.
- `analysis/`: HTTP sources, sink catalog, dependencies/auth evidence, flow и score.
- `analysis/reachability.py`: spans со строками/колонками, helper chains, cycle guard.
- `analysis/semgrep.py`: subprocess runner, Pydantic JSON, normalize/correlate.
- `rules/`: Command Injection, Path Traversal, SSRF, шесть собственных Semgrep rules
  и third_party snapshot (48 GitLab + 27 njsscan); default_rule_files перечисляет YAML локально.
- `output/`: terminal summary/detail и `Report.model_dump_json()`.
- `cli.py`: argparse, выбор режима и фильтров, обработка ожидаемых input/I/O ошибок.
- Внутренние записи (`Flow`, `PythonModule`, `Router`, etc.) тоже Pydantic BaseModel.
  AST-модели используют `arbitrary_types_allowed`; каталоги правил/sinks — `frozen=True`.
- Изменённая копия модели создаётся `model_copy(update=...)`; модель не содержит AST в JSON.

## Контракты

JSON schema version `1.1`: project, endpoints, diagnostics, unmatched_findings,
schema_version, tool_version. Старые 1.0 читаются с default unmatched_findings=[].
Endpoint включает параметры, auth, called_functions, sinks, findings, score, priority,
score_reasons. Finding включает source, sink, confidence и dataflow.
Semgrep Finding: rule_id="semgrep:<check_id>", source/sink=null, dataflow — helper chain
и место операции. Unmatched Finding имеет endpoint="". Колонки — во внутренних spans.
Пути в отчёте относительные; timestamp отсутствует; порядок детерминирован.
Пример для пользователя: `docs/example-report.json`.

`--output` пишет JSON по указанному пути независимо от расширения.
Stdout сохраняет выбранный формат. `--severity` фильтрует endpoint priority в сводке
и finding severity в режиме findings; фильтры не пересчитывают score.
`-v`/`--debug` включают scanner/parser diagnostics в stderr и JSON.
Неожиданные ошибки реализации не перехватываются универсальным обработчиком.
Коды CLI: 0 — завершённый scan, 1 — I/O error, 2 — ошибочный ввод/конфигурация/no match
либо явно запрошенный Semgrep scan не завершился. Общий except Exception не добавлять.

## Реализованная семантика

Routes: HTTP decorators, api_route, add_api_route; статические imports, aliases,
router prefixes, nested/repeated includes, trailing slash.
Inputs: signature parameters, Annotated/FastAPI markers, Pydantic body models,
Request collections и json/body/form.
Auth evidence наследуется от app/router/include/route; Depends(database) не auth.
Flow intra-procedural: assignments, transformations, collection access/mutations,
branches, loops, with, await. Flask request.args/form/json/files, Django GET/POST/FILES/body,
DRF data/query_params — sources. Встроенный taint остаётся внутри Python handler;
helper bodies Python обходятся для связи Semgrep Finding с endpoint.
Константный URL с user query options не SSRF; фиксированный executable с user argv
без shell не Command Injection. Path normalization снижает confidence.

JS/TS, Go и Rust: встроенные Command Injection/Path Traversal/SSRF теперь работают
без Semgrep. Taint проходит через простые локальные helpers с фактическими аргументами,
включая импорты; рекурсивные вызовы ограничены стеком текущего пути, без произвольного
лимита глубины. Неизвестные преобразования сохраняют taint, константное присваивание
его убирает; file write content и fixed URL payload сами по себе не создают finding.
Go sources: framework context, net/http Request, Chi URLParam/Mux Vars,
BindJSON/BodyParser и json.NewDecoder(...).Decode(&body). Rust sources: Path/Query/
Json/Form/Multipart, Actix HttpRequest, Rocket path/query bindings. Rust Command
поддерживает let + arg/args mutation chains и output/status/spawn; Go Command —
Run/Output/etc., JS child_process — exec/spawn/execFile. Shell interpreter argv
анализируются отдельно от безопасного fixed executable + user argv.

Rust macro token_tree разбирается как expression view файла, без выполнения macros.
Одна дополнительная Tree на файл, исходные byte/line positions сохранены; этот view
используют flow и helper reachability. format! поддерживает implicit captures `{name}`.
Cycle keys для router expressions включают start И end byte: receiver chains
часто имеют общий start byte, что иначе теряло предыдущие маршруты.
Scoped constants предотвращают смешение одноимённых app/router в разных factories.

Go registration helpers получают router prefix/auth из фактического аргумента,
включая Chi Route/Group callbacks и вызовы из локальных пакетов. TS Express/Fastify
получают virtual routers для registration/plugin parameters; Express follows
статический returned router и .bind обработчика. Hono/Elysia builders учитывают
basePath/prefix/group/route/use и исключают unmounted дубли inline plugins.
Сканируется каталог или отдельный source file; для file contents ограничены им одним,
config/show-code/Semgrep relative paths используют его parent directory.
Пустое извлечение Rust/Go/TS сообщает diagnostic вместо молчаливого отсутствия routes.

Score: +20 за вид sink с HTTP input, +25 input reaches sink, +15 recognized static flow,
+10 auth dependency не распознана (при finding), +10 dynamic outbound URL,
+25 shell/code execution, +10 за дополнительную операцию (до +20), +10 upload.
Пороги: INFO 0–19, LOW 20–39, MEDIUM 40–59, HIGH 60–89, CRITICAL 90+.
Semgrep задаёт минимум score по severity (0/20/40/60/90), если встроенный score ниже;
не добавляет недоказанные HTTP source/sink факторы и не раздувает score дублями.

Semgrep выключен по умолчанию, executable — optional extra [semgrep]. CLI --semgrep,
--semgrep-config (repeatable, заменяет defaults), --semgrep-binary включают его.
Config [semgrep]: enabled/configs/binary/timeout_seconds.
Runner копирует только selected contents в temporary snapshot с relative paths;
local configs, metrics/version-check off, scan (не ci), без builds/service execution.
Settings/logs тоже временные, токен аккаунта не используется. Default selection — 81 правило:
шесть ADScan, 48 GitLab SAST rules (commit 53bf5cf6df3c51b6c02110f5a638b5e6213666cd),
27 njsscan (4137df39e743e07e912a31ca7dab19633f40324a). YAML скопированы без изменений;
provenance.json содержит upstream paths, IDs и SHA-256; лицензии входят в пакет.
GitLab MIT, Go headers gosec Apache-2.0; njsscan LGPL-3.0 с полным GPL-3.0 текстом.
Не использовать remote registry defaults. Semgrep Rules License основной semgrep-rules
имеет ограничения non-competing; этот источник и AGPL Trail of Bits не включены.
Покрытие third-party: Python/Go/Java/JS/TS, SQL/NoSQL/XSS/XXE/SSTI/SSRF/path traversal/
deserialization/TLS/JWT; для Rust сохранено своё process-execution правило.
Есть taint rules и audit patterns, finding не доказывает эксплуатируемость.
Normalizer понимает GitLab metadata security-severity и shortDescription, явные severity/title
сохраняют приоритет. Обрабатываются ожидаемые внешние ошибки Semgrep.
Воспроизведение vendoring: .project/vendor_semgrep.py читает pinned source archives и
дополнительные лицензии из игнорируемого .project/vendor-cache, сеть не использует;
ruamel.yaml доступен из optional Semgrep dependency. Runner этот helper не вызывает.

## Ограничения и дальнейшие этапы

Route extraction есть для всех стеков первого этапа ТЗ и Rust.
Встроенный dataflow — Python/JS/TS/Go/Rust; Java security требует Semgrep.
Unattached routers — кандидаты с собственным prefix. Runtime registration, wildcard
imports, сложные factories/scopes могут пропускаться. Автоматические docs routes
не добавляются. Branches объединяются консервативно, loops обходятся один раз;
неизвестные transformations сохраняют taint.

Не полностью разрешаются сложные runtime factories, DI, global hooks/guards,
middleware order, wildcard reexports, Spring security chains, stateful methods,
captures сложных closures, Go Mount с произвольным Handler factory, tsconfig extends,
Rust procedural macros и сложные inline module/reexport arrangements.
Django re_path хранится как regex:..., неизвестный HTTP метод — ANY. Неявные HEAD/OPTIONS
не добавляются. Dynamic prefixes/paths диагностируются, не подменяются пустым prefix.

Следующие этапы ТЗ: дополнительные Python rules, interprocedural taint, IDOR,
OpenAPI, secrets. Полный interprocedural engine всё ещё не реализован.
Не создавать заглушки
или неработающие CLI flags ради покрытия следующих этапов.

## Источники решений

Исходное ТЗ: `SPEC.md`. Первоначальный отчёт: `history/MVP_REPORT.md` — исторический,
предшествует переходу на Pydantic. Актуальные результаты — `STATE.md`.
Pydantic API: https://docs.pydantic.dev/latest/concepts/models/
и https://docs.pydantic.dev/latest/concepts/serialization/.
`model_dump_json` используется без `ensure_ascii` для совместимости с минимальной 2.11;
источник версии добавления аргумента: https://pydantic.dev/articles/pydantic-v2-12-release.
FastAPI семантика: https://fastapi.tiangolo.com/tutorial/bigger-applications/,
https://fastapi.tiangolo.com/tutorial/body/,
https://fastapi.tiangolo.com/tutorial/security/first-steps/.

Новые первичные источники: https://tree-sitter.github.io/py-tree-sitter/,
https://flask.palletsprojects.com/en/stable/blueprints/,
https://docs.djangoproject.com/en/5.2/topics/http/urls/,
https://www.django-rest-framework.org/api-guide/routers/,
https://expressjs.com/en/guide/routing/, https://docs.nestjs.com/controllers,
https://fastify.dev/docs/latest/Reference/Routes/,
https://docs.spring.io/spring-framework/reference/web/webmvc/mvc-controller/ann-requestmapping.html,
https://docs.gofiber.io/api/app/, https://docs.semgrep.dev/cli-reference,
https://docs.semgrep.dev/semgrep-appsec-platform/json-and-sarif,
https://docs.semgrep.dev/writing-rules/rule-syntax.
Env settings дополнительно сверены с установленным semgrep/env.py.

Источники расширения Rust/Go/TS: https://docs.rs/axum/latest/axum/,
https://actix.rs/docs/url-dispatch/, https://rocket.rs/guide/v0.5/requests/,
https://go.dev/blog/routing-enhancements, https://github.com/go-chi/chi,
https://github.com/gorilla/mux, https://hono.dev/docs/api/routing,
https://elysiajs.com/essential/route.

Источники сторонних Semgrep rules:
https://gitlab.com/gitlab-org/security-products/sast-rules,
https://gitlab.com/gitlab-org/security-products/sast-rules/-/raw/main/LICENSE,
https://github.com/ajinabraham/njsscan и /blob/master/LICENSE,
https://github.com/securego/gosec/blob/master/LICENSE.txt,
https://www.gnu.org/licenses/gpl-3.0.txt.

Tree-sitter runtime ограничен `>=0.25,<0.26`, uv.lock — 0.25.2.
На Windows/Python 3.13 воспроизведено native heap crash с 0.26.0 после Rust helper
в format! и последующего AST обхода. На 0.25.2 этот repro и полный suite проходят.
Не маскировать crash исключениями или subprocess fallback; 0.26 не повышать без
проверки test_rust_helper_in_a_macro и bad_source на всех языках. Связанные upstream
сообщения (не доказательство той же причины):
https://github.com/tree-sitter/py-tree-sitter/issues/435,
https://github.com/tree-sitter/py-tree-sitter/issues/487.
