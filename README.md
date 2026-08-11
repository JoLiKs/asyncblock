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

# Анализ кода из stdin (удобно в пайплайнах и pre-commit)
cat handlers.py | asyncblock scan -

# Исключить тесты и миграции
asyncblock scan . --exclude "tests/*" --exclude "**/migrations/*"

# Сканировать только исходники приложения
asyncblock scan . --include "src/**/*.py" --include "app/**/*.py"

# Показывать только findings уровня error
asyncblock scan . --severity error

# Сканировать только определённые правила (можно повторять флаг)
asyncblock scan . --rule BLOCK_SLEEP --rule BLOCK_HTTP

# Посмотреть встроенные правила детекции
asyncblock rules

# JSON-каталог правил для документации или CI
asyncblock rules --json
```

### Пример вывода

```
Location                          Rule             Message                                      Suggestion
app/handlers.py:42                BLOCK_SLEEP      Blocking time.sleep() inside async code    Use asyncio.sleep() or anyio.sleep()
app/db.py:18                      BLOCK_DB         Blocking sqlite3.connect() inside async…   Use aiosqlite.connect() or an async ORM driver
```

Код выхода: `0` — проблем не найдено (или только warning), `1` — есть findings уровня **error**.

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

## Использование как библиотеки

```python
from asyncblock import analyze_file, analyze_source, analyze_tree, Finding, list_rules

findings: list[Finding] = analyze_file("app/handlers.py")
for finding in findings:
    print(f"{finding.location} [{finding.rule_id}] {finding.message}")

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
