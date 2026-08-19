# AsyncBlock

CLI-утилита и небольшая библиотека на Python для статического анализа asyncio-кода. AsyncBlock обходит Python-файлы проекта, строит AST и находит подозрительные **синхронные** вызовы внутри `async def` — типичный источник блокировок event loop в FastAPI, aiohttp и других async-приложениях.

## Установка

```bash
pip install asyncblock
```

Для красивого табличного вывода в терминале (опционально):

```bash
pip install "asyncblock[rich]"
```

Из исходников:

```bash
git clone https://github.com/your-org/asyncblock.git
cd asyncblock
pip install -e ".[dev]"
```

## Быстрый старт

```bash
# Сканировать текущую директорию
asyncblock scan

# Сканировать конкретный путь
asyncblock scan ./src

# JSON-вывод для CI или скриптов
asyncblock scan ./app --json

# Формат file:line:col для grep, pre-commit и IDE
asyncblock scan ./app --format unix

# GitHub Actions workflow commands — аннотации в PR и CI
asyncblock scan ./app --format github

# Анализ кода из stdin (удобно в пайплайнах и pre-commit)
cat handlers.py | asyncblock scan -

# Исключить тесты и миграции
asyncblock scan . --exclude "tests/*" --exclude "**/migrations/*"

# Или положить постоянные исключения в .asyncblockignore в корне проекта
asyncblock scan .

# Сканировать только исходники приложения
asyncblock scan . --include "src/**/*.py" --include "app/**/*.py"

# Показывать только findings уровня error
asyncblock scan . --severity error

# Сканировать только определённые правила (можно повторять флаг)
asyncblock scan . --rule BLOCK_SLEEP --rule BLOCK_HTTP

# Посмотреть встроенные правила детекции
asyncblock rules

# Сканировать с краткой сводкой по правилам и severity
asyncblock scan . --summary

# JSON-каталог правил для документации или CI
asyncblock rules --json
```

### Пример вывода

Таблица (по умолчанию):

```
Location                          Rule             Message                                      Suggestion
app/handlers.py:42                BLOCK_SLEEP      Blocking time.sleep() inside async code    Use asyncio.sleep() or anyio.sleep()
app/db.py:18                      BLOCK_DB         Blocking sqlite3.connect() inside async…   Use aiosqlite.connect() or an async ORM driver
```

Формат `--format unix` (одна строка на finding, удобно для CI и `grep`):

```
app/handlers.py:42:5: BLOCK_SLEEP: Blocking time.sleep() inside async code
app/db.py:18:12: BLOCK_DB: Blocking sqlite3.connect() inside async code
```

Формат `--format github` (workflow commands для аннотаций в GitHub Actions):

```
::error file=app/handlers.py,line=42,col=5,title=BLOCK_SLEEP::Blocking time.sleep() inside async code — Use asyncio.sleep() or anyio.sleep()
::error file=app/db.py,line=18,col=12,title=BLOCK_DB::Blocking sqlite3.connect() inside async code — Use aiosqlite.connect() or an async ORM driver
```

В GitHub Actions вывод попадает в Annotations на странице workflow run и в diff PR:

```yaml
- name: Check blocking calls in async code
  run: asyncblock scan ./src --format github
```

Код выхода: `0` — проблем не найдено (или только warning), `1` — есть findings уровня **error**.

С флагом `--summary` после таблицы выводится краткая сводка: число findings, затронутых файлов, разбивка по severity и по правилам. В режиме `--json` сводка печатается в stderr одной JSON-строкой, чтобы stdout оставался массивом findings.

### Команда `rules`

Показывает все встроенные правила с паттернами вызовов, уровнем severity и рекомендациями — удобно при настройке CI или при добавлении своих правил:

```
Rule              Patterns                                      Severity  Suggestion
BLOCK_SLEEP       time.sleep()                                  error     Use asyncio.sleep() or anyio.sleep()
BLOCK_HTTP        requests.get(), requests.post(), …            error     Use httpx.AsyncClient or aiohttp.ClientSession
```

## Встроенные правила

| ID | Что ловит | Рекомендация |
|----|-----------|--------------|
| `BLOCK_SLEEP` | `time.sleep` | `asyncio.sleep` / `anyio.sleep` |
| `BLOCK_HTTP` | `requests.get/post/...` | `httpx.AsyncClient` / `aiohttp` |
| `BLOCK_FILE` | `open()` | `aiofiles.open` |
| `BLOCK_SUBPROCESS` | `subprocess.run/call/...` | `asyncio.create_subprocess_exec` |
| `BLOCK_SOCKET` | `socket.socket/create_connection` | asyncio streams |
| `BLOCK_DB` | `sqlite3.connect`, `psycopg2.connect` | async-драйверы |

Правила срабатывают **только** если вызов находится внутри `async def`, включая вложенные синхронные функции, объявленные внутри async-функции.

## Подавление срабатываний

Иногда блокирующий вызов оправдан (legacy-обёртка, тестовый код, осознанный компромисс). Подавите предупреждение inline-комментарием:

```python
async def handler():
    time.sleep(0.1)  # asyncblock: ignore

    # asyncblock: ignore-next-line
    subprocess.run(["echo", "ok"])

    open("cache.txt")  # asyncblock: ignore BLOCK_FILE
```

- `# asyncblock: ignore` — игнорировать все правила на этой строке
- `# asyncblock: ignore-next-line` — игнорировать все правила на следующей строке
- `# asyncblock: ignore BLOCK_SLEEP` — игнорировать только указанные rule ID (можно перечислить несколько)

Директива работает и при анализе через CLI, и при вызове `analyze_file()` / `analyze_source()` из Python.

## Файл `.asyncblockignore`

Чтобы не передавать одни и те же `--exclude` в CI и локально, создайте в корне проекта файл `.asyncblockignore` с glob-паттернами (по одному на строку, `#` — комментарий):

```
tests/**
**/migrations/**
legacy/**
```

При `asyncblock scan` паттерны из `.asyncblockignore` автоматически объединяются с `--exclude`. Файлы ищутся от каталога сканирования вверх по дереву — можно держать один ignore-файл в корне репозитория. В Python API те же паттерны подхватывает `analyze_tree()`; отдельно их можно прочитать через `load_ignore_patterns()`.

## Использование как библиотеки

```python
from asyncblock import analyze_file, analyze_source, analyze_tree, Finding, list_rules, load_ignore_patterns, summarize_findings

findings: list[Finding] = analyze_file("app/handlers.py")
summary = summarize_findings(findings)
print(f"{summary.total} issues in {summary.files} files")
for rule_id, count in summary.by_rule:
    print(f"  {rule_id}: {count}")

# Анализ строки с кодом без записи во временный файл
snippet_findings = analyze_source(
    "async def f():\n    time.sleep(1)\n",
    filename="handlers.py",
)

all_findings = analyze_tree("./src", exclude=["tests/*"])

# Только файлы, попадающие под glob-паттерны
src_findings = analyze_tree("./", include=["src/**/*.py"])

# Только findings по выбранным правилам
db_findings = analyze_tree("./src", rule_ids=["BLOCK_DB"])

for rule in list_rules():
    print(rule.rule_id, rule.patterns)
```

## Как добавить своё правило

Отредактируйте `asyncblock/rules.py` и добавьте новый объект `Rule`:

```python
Rule(
    rule_id="BLOCK_REDIS",
    module="redis",
    attr="Redis",
    message="Blocking redis.Redis() inside async code",
    suggestion="Use redis.asyncio.Redis or aioredis",
    severity="error",  # или "warning"
)
```

Поля:

- `module` + `attr` — для вызовов вида `module.attr()` (с учётом `import module as alias`)
- `builtin` — для встроенных функций, например `open`
- `severity` — `"error"` (влияет на exit code) или `"warning"`

Можно передать свой набор правил напрямую в `analyze_file(path, rules=...)`.

## Ограничения

AsyncBlock — лёгкий AST-анализатор, а не полноценный linter:

- **Не видит блокировки через C-расширения** — если синхронный код спрятан в `.so`/`.pyd`, AST его не покажет.
- **Нет inter-procedural analysis** — вызов `sync_helper()` внутри async не анализируется, если `sync_helper` определён в другом файле.
- **Нет data-flow** — `getattr(requests, "get")()` не будет пойман.
- **Только явные паттерны** — правила основаны на известных API, а не на эвристиках.

Для production-проектов AsyncBlock удобен как быстрый pre-commit / CI чек рядом с pytest и ruff.

## Разработка

```bash
pip install -e ".[dev]"
pytest
ruff check .
```

## Лицензия

MIT — см. [LICENSE](LICENSE).
