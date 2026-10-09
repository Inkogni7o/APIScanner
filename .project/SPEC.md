# Техническое задание

## 1. Название проекта

Рабочее название: `adscan`

Необходимо разработать локальный CLI-инструмент для быстрого первичного анализа исходного кода неизвестных веб-сервисов в соревнованиях формата Attack/Defense.

Инструмент получает путь к директории с исходным кодом сервиса, автоматически определяет используемые языки и веб-фреймворки, извлекает HTTP API endpoints, определяет связанные обработчики, параметры, механизмы аутентификации и потенциально опасные участки кода, после чего ранжирует endpoints по приоритету ручной проверки.

Основная цель инструмента — не доказательство наличия уязвимости, а максимально быстрое построение карты поверхности атаки сервиса и указание endpoint'ов, которые необходимо проверить в первую очередь.

Инструмент должен работать полностью локально, без обращения к облачным сервисам, LLM или внешним API.

---

# 2. Основной сценарий использования

Пользователь получает неизвестный репозиторий веб-сервиса и запускает:

```bash
adscan ./service
```

Инструмент должен:

1. Найти файлы проекта.
2. Определить используемые языки.
3. Определить используемые web-фреймворки.
4. Найти HTTP-маршруты.
5. Сопоставить каждый маршрут с handler'ом.
6. Определить принимаемые параметры.
7. По возможности определить authentication/authorization middleware.
8. Выполнить статический анализ обработчиков и вызываемых ими функций.
9. Найти потенциально опасные source → sink цепочки.
10. Рассчитать risk score для каждого endpoint.
11. Отсортировать endpoints по приоритету.
12. Вывести компактный отчет в терминал.
13. Позволить получить подробную информацию об отдельном endpoint.
14. Поддерживать экспорт результатов в JSON.
15. В дальнейшем поддерживать экспорт OpenAPI.

Пример:

```text
$ adscan ./service

Project
  Languages: Python
  Frameworks: FastAPI
  Entry points:
    app/main.py

Endpoints: 19
Findings: 8

CRITICAL  POST   /api/admin/import
          SSRF, Command Injection
          app/admin.py:82

HIGH      GET    /api/files/{filename}
          Path Traversal
          app/files.py:41

HIGH      POST   /api/proxy
          SSRF
          app/proxy.py:17

MEDIUM    GET    /api/users/{id}
          Potential IDOR
          app/users.py:31

INFO      GET    /health
          app/main.py:12
```

---

# 3. Основные требования

## 3.1. Общие требования

Язык самого `adscan`:

```text
Python 3.13+
```

CLI должен работать в Linux и macOS.

Желательно обеспечить работоспособность и в Windows, если это не требует существенного усложнения архитектуры.

Инструмент не должен требовать:

- запуска анализируемого приложения;
- установки зависимостей анализируемого проекта;
- подключения к интернету;
- подключения к LLM;
- компиляции анализируемого проекта.

Статический режим должен быть основным.

---

# 4. Архитектура

Использовать модульную архитектуру.

Ориентировочная структура:

```text
adscan/
├── pyproject.toml
├── README.md
├── src/
│   └── adscan/
│       ├── __init__.py
│       ├── cli.py
│       │
│       ├── models/
│       │   ├── project.py
│       │   ├── endpoint.py
│       │   ├── parameter.py
│       │   ├── finding.py
│       │   └── dataflow.py
│       │
│       ├── detector/
│       │   ├── language.py
│       │   ├── framework.py
│       │   └── project.py
│       │
│       ├── parsers/
│       │   ├── base.py
│       │   ├── python.py
│       │   ├── javascript.py
│       │   ├── typescript.py
│       │   ├── java.py
│       │   └── go.py
│       │
│       ├── extractors/
│       │   ├── base.py
│       │   ├── fastapi.py
│       │   ├── flask.py
│       │   ├── django.py
│       │   ├── express.py
│       │   ├── nestjs.py
│       │   ├── spring.py
│       │   ├── gin.py
│       │   └── echo.py
│       │
│       ├── analysis/
│       │   ├── sources.py
│       │   ├── sinks.py
│       │   ├── dataflow.py
│       │   ├── auth.py
│       │   ├── calls.py
│       │   └── scoring.py
│       │
│       ├── rules/
│       │   ├── base.py
│       │   ├── command_injection.py
│       │   ├── sqli.py
│       │   ├── path_traversal.py
│       │   ├── ssrf.py
│       │   ├── deserialization.py
│       │   ├── file_upload.py
│       │   ├── ssti.py
│       │   ├── auth.py
│       │   └── idor.py
│       │
│       └── output/
│           ├── terminal.py
│           ├── json.py
│           └── openapi.py
│
└── tests/
```

Архитектура может быть скорректирована, если будет предложен более удобный вариант, но необходимо сохранить четкое разделение:

```text
project detection
→ framework detection
→ route extraction
→ static analysis
→ findings
→ scoring
→ output
```

---

# 5. Унифицированные модели данных

Все framework-specific extractors должны преобразовывать данные в единые модели.

Пример модели endpoint:

```python
@dataclass
class Endpoint:
    method: str
    path: str

    handler_name: str | None
    file: Path
    line: int

    framework: str

    parameters: list[Parameter]
    auth: list[AuthInfo]

    called_functions: list[FunctionReference]

    findings: list[Finding]

    score: int = 0
```

Parameter:

```python
@dataclass
class Parameter:
    name: str
    location: str

    # path, query, body, header, cookie, file

    type: str | None = None
    required: bool | None = None
```

Finding:

```python
@dataclass
class Finding:
    rule_id: str

    title: str

    severity: str

    file: Path
    line: int

    description: str

    source: Source | None
    sink: Sink | None

    confidence: str

    endpoint: str | None
```

Допускается использование Pydantic вместо dataclass, если это упростит сериализацию.

---

# 6. Определение языков

Необходимо определять язык проекта как минимум по:

```text
*.py
pyproject.toml
requirements.txt

*.js
*.jsx
package.json

*.ts
*.tsx

*.java
pom.xml
build.gradle
build.gradle.kts

*.go
go.mod

*.rs
Cargo.toml

*.cs
*.csproj

*.php
composer.json
```

Проект может одновременно содержать несколько языков.

Например:

```text
frontend: TypeScript
backend: Python
```

Необходимо анализировать backend-код, но не считать frontend API calls серверными endpoint'ами.

---

# 7. Определение framework

Первая версия должна определять:

## Python

```text
FastAPI
Flask
Django
Django REST Framework
```

## JavaScript / TypeScript

```text
Express
NestJS
Fastify
```

## Java

```text
Spring Boot
Spring MVC
```

## Go

```text
Gin
Echo
Fiber
```

Следующая очередь:

```text
ASP.NET Core
Axum
Actix Web
Rocket
Ktor
Laravel
Symfony
Rails
```

Framework необходимо определять не только по импортам, но и по dependency files.

Например:

```text
requirements.txt
pyproject.toml
package.json
pom.xml
go.mod
Cargo.toml
```

---

# 8. Route extraction

Для каждого framework необходимо создать отдельный extractor.

Extractor должен возвращать как минимум:

```text
HTTP method
path
handler
source file
source line
parameters
authentication information
```

Пример FastAPI:

```python
@app.get("/users/{id}")
def get_user(id: int):
    ...
```

Результат:

```text
GET /users/{id}

handler:
    get_user

location:
    app/users.py:31

parameters:
    id
        path
        int
```

Поддержать:

```python
@app.get(...)
@app.post(...)
@app.put(...)
@app.patch(...)
@app.delete(...)

router.get(...)
router.post(...)
...
```

Необходимо учитывать:

```python
APIRouter(prefix="/api")
```

и:

```python
app.include_router(router, prefix="/v1")
```

Итоговый маршрут должен правильно собираться:

```text
/v1 + /api + /users/{id}
=
/v1/api/users/{id}
```

---

# 9. Flask

Поддерживать:

```python
@app.route(...)
@app.get(...)
@app.post(...)
blueprint.route(...)
```

Учитывать:

```python
Blueprint(
    ...,
    url_prefix="/api"
)
```

---

# 10. Django / DRF

Поддерживать:

```text
urlpatterns
path()
re_path()
include()

APIView
ViewSet
ModelViewSet
@api_view
@action
routers
```

Необходимо пытаться связать:

```text
URL
→ view
→ method handler
```

Например:

```text
/users/<int:pk>/
→ UserViewSet.retrieve()
```

---

# 11. Express

Поддерживать:

```javascript
app.get()
app.post()
app.put()
app.patch()
app.delete()

router.get()
router.post()
...
```

Учитывать:

```javascript
app.use("/api", router)
```

и вложенные routers.

Например:

```javascript
app.use("/api", usersRouter)

usersRouter.get("/:id", getUser)
```

Должно быть:

```text
GET /api/:id
```

или соответствующий корректный полный путь.

---

# 12. NestJS

Поддерживать:

```typescript
@Controller()
@Get()
@Post()
@Put()
@Patch()
@Delete()
```

Учитывать:

```typescript
@Controller("/users")
```

+

```typescript
@Get(":id")
```

=

```text
GET /users/:id
```

Извлекать:

```text
@Param
@Query
@Body
@Headers
@UploadedFile
@UploadedFiles
```

А также guards:

```text
@UseGuards(...)
```

---

# 13. Spring

Поддерживать:

```java
@RequestMapping
@GetMapping
@PostMapping
@PutMapping
@PatchMapping
@DeleteMapping
```

Учитывать mapping на уровне класса.

Например:

```java
@RestController
@RequestMapping("/api/users")
class UserController {

    @GetMapping("/{id}")
}
```

Результат:

```text
GET /api/users/{id}
```

Извлекать:

```text
@PathVariable
@RequestParam
@RequestBody
@RequestHeader
@CookieValue
@RequestPart
```

---

# 14. Go

Поддержать как минимум Gin:

```go
r.GET(...)
r.POST(...)
r.PUT(...)
r.PATCH(...)
r.DELETE(...)
```

и route groups:

```go
api := r.Group("/api")
users := api.Group("/users")

users.GET("/:id", getUser)
```

Результат:

```text
GET /api/users/:id
```

Аналогичным образом реализовать Echo.

---

# 15. Парсер исходного кода

По возможности использовать AST/CST, а не regex.

Предпочтительный вариант:

```text
tree-sitter
```

Regex допустим только:

- для первоначального fallback;
- для определения framework;
- для простых случаев;
- там, где полноценный AST-анализ неоправданно сложен.

Необходимо спроектировать систему так, чтобы добавление нового языка не требовало изменения основного analyzer.

---

# 16. Источники пользовательских данных

Ввести понятие `Source`.

Source — значение, поступающее от HTTP-клиента.

Поддерживать как минимум:

```text
path parameters
query parameters
request body
JSON fields
form fields
headers
cookies
uploaded files
```

Пример:

```python
def download(filename: str):
```

`filename` считается Source.

Также:

```python
filename = request.args["filename"]
```

Source.

И:

```javascript
const url = req.body.url;
```

Source.

---

# 17. Dangerous sinks

Ввести каталог опасных функций.

Каталог должен быть framework/language-aware.

## Command Execution

Python:

```text
os.system
os.popen
subprocess.run
subprocess.call
subprocess.Popen
eval
exec
```

JavaScript:

```text
child_process.exec
execSync
spawn
spawnSync
eval
```

Java:

```text
Runtime.exec
ProcessBuilder
```

Go:

```text
exec.Command
```

---

# 18. SQL

Искать потенциально опасные SQL операции.

Примеры:

Python:

```text
cursor.execute
connection.execute
raw
extra
```

Java:

```text
Statement.execute
Statement.executeQuery
createNativeQuery
```

Node:

```text
query
execute
raw
```

Приоритет повышать, если SQL строится через:

```text
string concatenation
f-string
format()
template literals
sprintf-like formatting
```

Например:

```python
query = f"SELECT * FROM users WHERE id={user_id}"
cursor.execute(query)
```

должно быть помечено значительно выше, чем:

```python
cursor.execute(
    "SELECT * FROM users WHERE id=%s",
    [user_id],
)
```

---

# 19. File operations

Искать:

```text
open
read
write
unlink
remove
rename
copy

send_file
send_from_directory

fs.readFile
fs.writeFile

FileInputStream
FileOutputStream

os.Open
os.ReadFile

archive extraction
```

Особое внимание:

```text
user input
→ filesystem path
→ read/write/delete/extract
```

---

# 20. SSRF

Искать цепочки:

```text
HTTP input
→ URL
→ HTTP client
```

Python:

```text
requests
httpx
urllib
aiohttp
```

JavaScript:

```text
fetch
axios
http
https
got
request
```

Java:

```text
HttpClient
RestTemplate
WebClient
URL.openConnection
```

Go:

```text
http.Get
http.Post
http.Client.Do
```

Пример:

```python
@app.post("/proxy")
def proxy(url: str):
    return requests.get(url).text
```

должен получить HIGH/CRITICAL priority.

---

# 21. Unsafe deserialization

Искать как минимум:

Python:

```text
pickle.loads
pickle.load
yaml.load
marshal.loads
```

Java:

```text
ObjectInputStream
readObject
```

PHP:

```text
unserialize
```

Node:

потенциально опасные deserialize-библиотеки при наличии известных patterns.

---

# 22. Template injection

Искать пользовательские данные, используемые непосредственно при создании шаблона.

Пример:

```python
render_template_string(user_input)
```

или:

```python
Template(user_input)
```

Помечать как возможный SSTI.

---

# 23. File upload

Endpoint автоматически должен получать повышенный интерес, если принимает файл.

Определять:

```text
multipart/form-data
UploadFile
MultipartFile
req.file
req.files
FormFile
```

Проверять последующий data flow:

```text
filename
content
extension
destination path
archive extraction
shell processing
```

Особенно выделять:

```text
original filename
→ filesystem path
```

---

# 24. Path traversal

Искать цепочку:

```text
HTTP input
→ path construction
→ filesystem operation
```

Например:

```python
path = "/uploads/" + filename
return open(path).read()
```

Помечать:

```text
Potential Path Traversal
```

Если присутствует нормализация и проверка пути, confidence должен снижаться.

---

# 25. IDOR heuristic

Реализовать эвристический анализ.

Endpoint считается интересным, если:

```text
/users/{id}
/profile/{id}
/orders/{id}
/messages/{id}
/files/{id}
```

и значение ID используется для получения объекта:

```text
get(id)
findById(id)
filter(id=id)
query(...id...)
```

но рядом не обнаружена проверка ownership:

```text
current_user
request.user
user_id
owner
owner_id
created_by
principal
session user
```

Такой finding должен иметь:

```text
type:
    potential_idor

confidence:
    low или medium
```

Не утверждать наличие IDOR наверняка.

---

# 26. Authentication / Authorization

Необходимо определять наличие механизмов аутентификации на endpoint.

Примеры:

FastAPI:

```text
Depends(get_current_user)
Depends(auth)
Security(...)
```

Flask:

```text
@login_required
@jwt_required
```

Django:

```text
permission_classes
authentication_classes
@login_required
```

NestJS:

```text
@UseGuards
AuthGuard
RolesGuard
```

Spring:

```text
@PreAuthorize
@Secured
SecurityFilterChain
```

Express:

```text
router.get(path, authMiddleware, handler)
```

Если опасный endpoint не имеет обнаруженной аутентификации, его score повышается.

Не считать отсутствие распознанного middleware доказательством отсутствия аутентификации.

---

# 27. Data flow analysis

Для MVP не требуется полноценный interprocedural taint engine уровня CodeQL.

Необходимо реализовать сначала:

```text
intra-procedural analysis
```

То есть внутри функции:

```text
source
→ assignment
→ transformation
→ sink
```

Например:

```python
@app.get("/file")
def file(name: str):
    path = "/tmp/" + name
    return open(path).read()
```

Необходимо получить:

```text
name
↓
path
↓
open()
```

Следующий этап:

```text
limited interprocedural analysis
```

Например:

```python
@app.get("/file")
def file(name: str):
    return read_file(name)


def read_file(name):
    return open(name).read()
```

Необходимо связать:

```text
GET /file
→ file()
→ read_file()
→ open()
```

Ограничить глубину анализа вызовов параметром, например:

```text
default max depth = 5
```

Не выполнять бесконечный анализ рекурсивных вызовов.

---

# 28. Severity

Использовать:

```text
INFO
LOW
MEDIUM
HIGH
CRITICAL
```

Severity finding и priority endpoint должны быть разделены.

Например endpoint может иметь:

```text
3 MEDIUM findings
```

и получить HIGH endpoint priority.

---

# 29. Risk scoring

Сделать score объяснимым.

Пример базовой модели:

```text
dangerous sink:
    +30

user-controlled value reaches sink:
    +30

direct flow:
    +20

unauthenticated:
    +15

file upload:
    +10

dynamic command:
    +20

shell=True:
    +25

dynamic SQL:
    +20

dynamic URL:
    +15

potential ownership issue:
    +10
```

Значения можно скорректировать.

Приоритеты:

```text
0–19    INFO
20–39   LOW
40–59   MEDIUM
60–89   HIGH
90+     CRITICAL
```

Для каждого score необходимо хранить причины.

Например:

```text
Score: 105

+30 command execution sink
+30 request parameter reaches sink
+20 direct data flow
+25 shell=True
```

---

# 30. Терминальный вывод

Основной вывод должен быть компактным.

Пример:

```text
ADScan 0.1

Project:
  Languages: Python
  Framework: FastAPI

Files analyzed: 73
Endpoints: 26
Findings: 11

Priority endpoints:

CRITICAL  115  POST  /api/convert
               Command Injection
               app/convert.py:51

HIGH       82  GET   /api/files/{name}
               Path Traversal
               app/files.py:33

HIGH       71  POST  /api/proxy
               SSRF
               app/proxy.py:18

MEDIUM     48  GET   /api/users/{id}
               Potential IDOR
               app/users.py:72

INFO        0  GET   /health
               app/main.py:12
```

Использовать цветной вывод, но предусмотреть:

```bash
--no-color
```

---

# 31. Просмотр endpoint

Поддержать:

```bash
adscan ./service endpoint "/api/files/{name}"
```

или иной удобный синтаксис.

Вывод:

```text
GET /api/files/{name}

Location:
  app/files.py:33

Handler:
  download_file

Authentication:
  JWT

Parameters:

  name
    location: path
    type: string

Call chain:

  download_file()
      ↓
  get_file_path()
      ↓
  open()

Findings:

HIGH Potential Path Traversal

Source:
  path parameter "name"

Data flow:
  name
    ↓
  os.path.join(upload_dir, name)
    ↓
  open(path)

Sink:
  app/files.py:41

Confidence:
  HIGH
```

---

# 32. Просмотр файла и строки

В терминальном отчете всегда показывать:

```text
relative/path.py:123
```

Не использовать абсолютные пути без необходимости.

Добавить возможность:

```bash
adscan ./service --show-code
```

чтобы выводить небольшой фрагмент кода вокруг finding:

```text
119 | filename = request.args["filename"]
120 | path = os.path.join(UPLOAD_DIR, filename)
121 |
122 | with open(path, "rb") as f:
123 |     return f.read()
```

---

# 33. JSON export

Поддержать:

```bash
adscan ./service --format json
```

или:

```bash
adscan ./service --output report.json
```

JSON должен содержать:

```text
project metadata
languages
frameworks
endpoints
parameters
auth
findings
scores
locations
data flows
```

Формат должен быть стабильным и покрываться тестами.

---

# 34. OpenAPI export

На следующем этапе реализовать:

```bash
adscan ./service --format openapi
```

или:

```bash
adscan ./service --openapi openapi.json
```

Генерировать OpenAPI 3.1.

Использовать только достоверно найденную информацию.

Если request/response schema определить нельзя, не выдумывать ее.

Например:

```yaml
paths:
  /users/{id}:
    get:
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: string
```

Основная задача инструмента — security triage, а OpenAPI является дополнительным форматом вывода.

---

# 35. Поддержка существующего OpenAPI

Во время анализа проекта искать:

```text
openapi.json
openapi.yaml
swagger.json
swagger.yaml
```

Если схема найдена:

1. распарсить ее;
2. использовать как дополнительный источник endpoint'ов;
3. объединить ее со статически найденными маршрутами;
4. сообщить о расхождениях.

Например:

```text
Static-only endpoint:
  POST /internal/debug

OpenAPI-only endpoint:
  GET /legacy/users
```

Это представляет особый интерес.

---

# 36. Semgrep integration

Semgrep не должен быть обязательной зависимостью.

Если бинарник `semgrep` существует, позволить:

```bash
adscan ./service --semgrep
```

или автоматически использовать его при соответствующей настройке.

Semgrep findings необходимо:

```text
parse
normalize
correlate with endpoint
```

Например Semgrep сообщает:

```text
Possible command injection
utils.py:78
```

Если:

```text
POST /convert
→ convert()
→ utils.execute()
→ utils.py:78
```

то finding должен отображаться в контексте:

```text
POST /convert
    Command Injection
    utils.py:78
```

Основная логика `adscan` не должна зависеть от Semgrep.

---

# 37. Secret scanning

Добавить базовый поиск:

```text
password
secret
api_key
token
JWT secret
private key
database DSN
AWS-like credentials
```

Не выводить целиком потенциальные secrets.

Например:

```text
Hardcoded JWT secret
config.py:18
value: "supe********"
```

Показывать только замаскированное значение.

---

# 38. Конфигурация

Поддержать файл:

```text
.adscan.toml
```

Пример:

```toml
[analysis]
max_call_depth = 5
include_tests = false

[output]
color = true

[severity]
minimum = "medium"

[ignore]
paths = [
    "node_modules",
    ".venv",
    "vendor",
    "dist",
    "build"
]
```

---

# 39. Игнорируемые директории

По умолчанию не анализировать:

```text
.git
.venv
venv
node_modules
vendor
dist
build
target
__pycache__
coverage
.idea
.vscode
```

Тестовые директории по умолчанию можно либо исключать, либо анализировать только для определения framework. Решение зафиксировать в README.

---

# 40. Производительность

Инструмент предназначен для соревнования, поэтому скорость является важным требованием.

Цель:

репозиторий до примерно 100 000 строк исходного backend-кода должен анализироваться за разумное время на обычном ноутбуке.

Не выполнять тяжелый анализ всего call graph без необходимости.

Предпочитать:

```text
routes first
→ reachable handlers
→ reachable functions
```

То есть сначала определить endpoints, а затем углубленно анализировать только код, достижимый от них.

---

# 41. Confidence

Все findings должны иметь confidence:

```text
LOW
MEDIUM
HIGH
```

Например:

```text
HTTP parameter → subprocess.run(shell=True)

severity:
    CRITICAL

confidence:
    HIGH
```

А:

```text
/users/{id}
+
lookup by id
+
ownership check not discovered
```

должно быть:

```text
Potential IDOR

severity:
    MEDIUM

confidence:
    LOW
```

Важно избегать формулировок, будто эвристика гарантированно обнаружила уязвимость.

---

# 42. Ошибки анализа

Парсер не должен завершать весь анализ из-за одного некорректного файла.

Например:

```text
[WARN] Failed to parse src/legacy/broken.py
```

и продолжить работу.

Все parser errors выводить только при:

```bash
-v
```

или:

```bash
--debug
```

---

# 43. CLI

Предлагаемый интерфейс:

```bash
adscan PATH
```

Дополнительные параметры:

```bash
adscan PATH --format terminal
adscan PATH --format json
adscan PATH --format openapi

adscan PATH --output report.json

adscan PATH --severity high

adscan PATH --show-code

adscan PATH --no-color

adscan PATH --debug

adscan PATH --framework fastapi

adscan PATH --language python

adscan PATH --max-call-depth 5

adscan PATH --semgrep
```

Также:

```bash
adscan PATH endpoints
```

для вывода всех маршрутов.

И:

```bash
adscan PATH findings
```

для вывода только findings.

---

# 44. Команда endpoints

Пример:

```text
$ adscan . endpoints

METHOD  PATH                     AUTH      HANDLER
GET     /health                  —         main.py:10
POST    /login                   —         auth.py:31
GET     /users/{id}              JWT       users.py:42
POST    /files                   JWT       files.py:19
GET     /files/{filename}        JWT       files.py:51
POST    /admin/import            ADMIN     admin.py:74
```

---

# 45. Команда findings

Пример:

```text
$ adscan . findings

CRITICAL Command Injection
POST /convert
src/converter.py:55

HIGH Path Traversal
GET /files/{filename}
src/files.py:61

HIGH SSRF
POST /proxy
src/proxy.py:24
```

---

# 46. Тестирование

Использовать:

```text
pytest
```

Необходимо покрыть unit-тестами:

```text
language detection
framework detection
route extraction
prefix composition
parameter extraction
authentication detection
source detection
sink detection
simple data flow
risk scoring
JSON serialization
```

---

# 47. Fixture projects

Создать:

```text
tests/fixtures/
```

с небольшими намеренно созданными примерами приложений.

Например:

```text
fixtures/
├── fastapi_basic/
├── fastapi_vulnerable/
├── flask_basic/
├── django_basic/
├── express_basic/
├── nestjs_basic/
├── spring_basic/
└── gin_basic/
```

Пример `fastapi_vulnerable` должен содержать:

```text
safe endpoint
command injection-like flow
path traversal-like flow
SSRF-like flow
IDOR-like flow
file upload
authenticated endpoint
unauthenticated endpoint
```

Не требуется создавать рабочие эксплуатационные payload'ы. Fixtures нужны исключительно для проверки статического анализа.

---

# 48. Acceptance tests для FastAPI MVP

Следующий пример:

```python
from fastapi import FastAPI

import requests
import subprocess

app = FastAPI()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/files/{filename}")
def read_file(filename: str):
    with open("/tmp/" + filename) as f:
        return f.read()


@app.get("/proxy")
def proxy(url: str):
    return requests.get(url).text


@app.post("/run")
def run(command: str):
    return subprocess.run(
        command,
        shell=True,
        capture_output=True,
    ).stdout
```

должен приводить как минимум к обнаружению:

```text
GET /health
    INFO

GET /files/{filename}
    Path Traversal
    HIGH

GET /proxy
    SSRF
    HIGH

POST /run
    Command Injection
    CRITICAL
```

---

# 49. Приоритет реализации

Не пытаться сразу реализовать все перечисленные языки.

Разрабатывать по этапам.

## Этап 1

Рабочий каркас CLI.

Реализовать:

```text
project scanner
language detection
framework detection
models
terminal output
JSON output
```

Framework:

```text
FastAPI
```

Analysis:

```text
route extraction
parameters
simple source tracking
file sinks
HTTP sinks
command sinks
```

Rules:

```text
Command Injection
Path Traversal
SSRF
```

После этого проект уже должен быть полностью запускаемым.

---

# 50. Этап 2

Добавить Python frameworks:

```text
Flask
Django
Django REST Framework
```

Добавить:

```text
SQLi
unsafe deserialization
file upload
SSTI
authentication detection
```

---

# 51. Этап 3

Добавить:

```text
Express
NestJS
Fastify
```

---

# 52. Этап 4

Добавить:

```text
Spring
Gin
Echo
Fiber
```

---

# 53. Этап 5

Добавить:

```text
limited interprocedural dataflow
IDOR heuristics
OpenAPI export
OpenAPI discovery
Semgrep integration
secret scanning
```

---

# 54. Критически важный принцип разработки

После каждого этапа проект должен оставаться:

```text
запускаемым
тестируемым
документированным
```

Не создавать сразу большое количество заглушек без работающей основной цепочки.

Приоритет:

```text
рабочий вертикальный MVP
```

вместо:

```text
большая архитектура без работающего анализа
```

---

# 55. Требования к качеству кода

Использовать:

```text
Python 3.13+
type hints
pytest
ruff
```

Желательно:

```text
mypy или pyright
```

Публичные классы и сложные функции должны иметь docstrings.

Не использовать чрезмерно сложные абстракции.

Framework-specific код должен находиться в framework-specific модулях.

Основное ядро не должно содержать большое количество конструкций вида:

```python
if framework == "fastapi":
    ...
elif framework == "flask":
    ...
elif framework == "spring":
    ...
```

Использовать registry/plugin-like architecture.

---

# 56. Расширяемость

Добавление нового framework должно сводиться примерно к:

```python
class AxumExtractor(BaseExtractor):
    ...
```

и регистрации extractor.

Например:

```python
EXTRACTORS = {
    "fastapi": FastAPIExtractor,
    "flask": FlaskExtractor,
    "express": ExpressExtractor,
}
```

или использовать автоматический registry.

---

# 57. README

README должен содержать:

```text
назначение проекта
ограничения
установку
примеры запуска
поддерживаемые языки
поддерживаемые frameworks
поддерживаемые security rules
описание severity
описание confidence
пример отчета
```

Обязательно явно указать:

```text
ADScan выполняет эвристический статический анализ.
Finding не является доказательством наличия уязвимости.
```

---

# 58. Ожидаемый конечный пользовательский сценарий

После получения неизвестного сервиса пользователь должен выполнить:

```bash
adscan ./service
```

и через короткое время получить:

```text
1. Какой это стек.
2. Какие HTTP endpoints существуют.
3. Где находится код каждого endpoint.
4. Какие endpoints требуют проверки в первую очередь.
5. Почему конкретный endpoint получил высокий priority.
6. Какие пользовательские данные попадают в потенциально опасные операции.
```

Основной UX необходимо оптимизировать именно под быстрое использование во время Attack/Defense.

---

# 59. Что не требуется

На данном этапе НЕ нужно:

```text
автоматически эксплуатировать найденные уязвимости;
генерировать exploit-код;
автоматически отправлять атакующие HTTP-запросы;
автоматически изменять исходный код анализируемого сервиса;
использовать LLM во время анализа;
полагаться на интернет;
строить полноценный аналог CodeQL;
гарантировать отсутствие false positive/false negative.
```

Основная задача — triage.

---

# 60. Первая задача для реализации

Начни разработку с полностью работающего FastAPI MVP.

Не переходи к другим framework, пока не работает следующая цепочка:

```text
adscan tests/fixtures/fastapi_vulnerable
```

и инструмент:

1. определяет Python;
2. определяет FastAPI;
3. извлекает все routes;
4. находит их handlers;
5. извлекает path/query/body parameters;
6. обнаруживает прямые source → sink цепочки;
7. обнаруживает:
   - command execution;
   - filesystem access;
   - outbound HTTP requests;
8. определяет потенциальные:
   - Command Injection;
   - Path Traversal;
   - SSRF;
9. рассчитывает score;
10. сортирует endpoints;
11. выводит терминальный отчет;
12. может сохранить тот же результат в JSON;
13. имеет unit и integration tests.

После завершения FastAPI MVP покажи:

```text
структуру проекта
архитектурные решения
CLI help
пример вывода
результаты тестов
```

Только после этого переходи к следующему этапу.

---

# 61. Требования к работе над задачей

При разработке самостоятельно принимай разумные технические решения, если они не противоречат этому ТЗ.

Не останавливай реализацию из-за небольших неоднозначностей. Выбирай наиболее простой и расширяемый вариант.

Не заменяй реальную реализацию TODO-заглушками там, где функциональность входит в текущий этап.

После каждой существенной реализации:

```text
запускай тесты;
исправляй найденные ошибки;
проверяй CLI на fixture project.
```

Если архитектурное решение необходимо изменить для сохранения расширяемости, допускается отклонение от предложенной структуры директорий, но итоговая архитектура должна сохранять разделение ответственности.

Первый приоритет — получить рабочий FastAPI MVP, которым уже можно пользоваться на реальном репозитории.