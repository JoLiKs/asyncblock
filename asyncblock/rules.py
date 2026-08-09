"""Built-in detection rules for blocking synchronous calls."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Severity = Literal["warning", "error"]


@dataclass(frozen=True, slots=True)
class Rule:
    """A rule that matches a blocking call pattern."""

    rule_id: str
    message: str
    suggestion: str
    severity: Severity = "error"
    module: str | None = None
    attr: str | None = None
    builtin: str | None = None


RULES: tuple[Rule, ...] = (
    Rule(
        rule_id="BLOCK_SLEEP",
        module="time",
        attr="sleep",
        message="Blocking time.sleep() inside async code",
        suggestion="Use asyncio.sleep() or anyio.sleep()",
    ),
    Rule(
        rule_id="BLOCK_HTTP",
        module="requests",
        attr="get",
        message="Blocking requests.get() inside async code",
        suggestion="Use httpx.AsyncClient or aiohttp.ClientSession",
    ),
    Rule(
        rule_id="BLOCK_HTTP",
        module="requests",
        attr="post",
        message="Blocking requests.post() inside async code",
        suggestion="Use httpx.AsyncClient or aiohttp.ClientSession",
    ),
    Rule(
        rule_id="BLOCK_HTTP",
        module="requests",
        attr="put",
        message="Blocking requests.put() inside async code",
        suggestion="Use httpx.AsyncClient or aiohttp.ClientSession",
    ),
    Rule(
        rule_id="BLOCK_HTTP",
        module="requests",
        attr="patch",
        message="Blocking requests.patch() inside async code",
        suggestion="Use httpx.AsyncClient or aiohttp.ClientSession",
    ),
    Rule(
        rule_id="BLOCK_HTTP",
        module="requests",
        attr="delete",
        message="Blocking requests.delete() inside async code",
        suggestion="Use httpx.AsyncClient or aiohttp.ClientSession",
    ),
    Rule(
        rule_id="BLOCK_HTTP",
        module="requests",
        attr="head",
        message="Blocking requests.head() inside async code",
        suggestion="Use httpx.AsyncClient or aiohttp.ClientSession",
    ),
    Rule(
        rule_id="BLOCK_HTTP",
        module="requests",
        attr="options",
        message="Blocking requests.options() inside async code",
        suggestion="Use httpx.AsyncClient or aiohttp.ClientSession",
    ),
    Rule(
        rule_id="BLOCK_HTTP",
        module="requests",
        attr="request",
        message="Blocking requests.request() inside async code",
        suggestion="Use httpx.AsyncClient or aiohttp.ClientSession",
    ),
    Rule(
        rule_id="BLOCK_FILE",
        builtin="open",
        message="Blocking open() inside async code",
        suggestion="Use aiofiles.open()",
    ),
    Rule(
        rule_id="BLOCK_SUBPROCESS",
        module="subprocess",
        attr="run",
        message="Blocking subprocess.run() inside async code",
        suggestion="Use asyncio.create_subprocess_exec() or asyncio.create_subprocess_shell()",
    ),
    Rule(
        rule_id="BLOCK_SUBPROCESS",
        module="subprocess",
        attr="call",
        message="Blocking subprocess.call() inside async code",
        suggestion="Use asyncio.create_subprocess_exec() or asyncio.create_subprocess_shell()",
    ),
    Rule(
        rule_id="BLOCK_SUBPROCESS",
        module="subprocess",
        attr="check_call",
        message="Blocking subprocess.check_call() inside async code",
        suggestion="Use asyncio.create_subprocess_exec() or asyncio.create_subprocess_shell()",
    ),
    Rule(
        rule_id="BLOCK_SUBPROCESS",
        module="subprocess",
        attr="check_output",
        message="Blocking subprocess.check_output() inside async code",
        suggestion="Use asyncio.create_subprocess_exec() or asyncio.create_subprocess_shell()",
    ),
    Rule(
        rule_id="BLOCK_SUBPROCESS",
        module="subprocess",
        attr="Popen",
        message="Blocking subprocess.Popen() inside async code",
        suggestion="Use asyncio.create_subprocess_exec() or asyncio.create_subprocess_shell()",
    ),
    Rule(
        rule_id="BLOCK_SOCKET",
        module="socket",
        attr="socket",
        message="Blocking socket.socket() inside async code",
        suggestion="Use asyncio.open_connection() or asyncio streams",
    ),
    Rule(
        rule_id="BLOCK_SOCKET",
        module="socket",
        attr="create_connection",
        message="Blocking socket.create_connection() inside async code",
        suggestion="Use asyncio.open_connection() or asyncio streams",
    ),
    Rule(
        rule_id="BLOCK_DB",
        module="sqlite3",
        attr="connect",
        message="Blocking sqlite3.connect() inside async code",
        suggestion="Use aiosqlite.connect() or an async ORM driver",
    ),
    Rule(
        rule_id="BLOCK_DB",
        module="psycopg2",
        attr="connect",
        message="Blocking psycopg2.connect() inside async code",
        suggestion="Use asyncpg.connect() or psycopg (v3) async API",
    ),
)
