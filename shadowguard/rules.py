"""ShadowGuard-Agent — Deterministic rules engine.

This module implements all static analysis rules using Python's built-in
``ast`` module and ``re`` patterns. Every detection is 100% deterministic
with zero LLM involvement, ensuring reproducible audit results.

Supported languages:
- Python: Full AST-based analysis via ``ast.parse()``.
- TypeScript/JavaScript: Regex-based pattern matching (no AST parser needed
  for the target anti-patterns; framework directive detection via line scanning).
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import Literal


# ---------------------------------------------------------------------------
# Secret / Credential Detection Patterns
# ---------------------------------------------------------------------------

# Each pattern is a tuple of (compiled_regex, rule_id, rule_name, message)
# These are applied to ALL languages.

SECRET_PATTERNS: list[tuple[re.Pattern[str], str, str, str]] = [
    (
        re.compile(
            r"""(?:secret[_-]?key|service[_-]?role[_-]?key|api[_-]?key|access[_-]?key|auth[_-]?token|jwt[_-]?secret|private[_-]?key)\s*[:=]\s*['\"][A-Za-z0-9+/=_\-\.]{20,}['\"]""",
            re.IGNORECASE,
        ),
        "SEC-001",
        "Hardcoded Secret or API Key",
        "A secret key, API key, or service credential is hardcoded in source code. "
        "This will be exposed in version control and potentially in client bundles.",
    ),
    (
        re.compile(
            r"""eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"""
        ),
        "SEC-002",
        "Embedded JWT Token",
        "A JWT token is embedded directly in source code. JWTs should be loaded "
        "from environment variables or a secure vault at runtime.",
    ),
    (
        re.compile(
            r"""(?:postgresql|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s'\"]{10,}""",
            re.IGNORECASE,
        ),
        "SEC-003",
        "Hardcoded Database Connection String",
        "A database connection URI with embedded credentials is hardcoded. "
        "Use environment variables or a secrets manager.",
    ),
    (
        re.compile(
            r"""(?:AKIA|ASIA)[A-Z0-9]{16}"""
        ),
        "SEC-004",
        "AWS Access Key ID",
        "An AWS access key ID is hardcoded in source code. "
        "Use IAM roles, instance profiles, or environment variables instead.",
    ),
    (
        re.compile(
            r"""sk-proj-[A-Za-z0-9]{20,}"""
        ),
        "SEC-005",
        "OpenAI / LLM Provider API Key",
        "An LLM provider API key (e.g., OpenAI) is hardcoded in source code.",
    ),
    (
        re.compile(
            r"""localStorage\.setItem\s*\(\s*['\"](?:auth|token|password|secret|key|jwt|session)['\"]\s*,""",
            re.IGNORECASE,
        ),
        "SEC-006",
        "Sensitive Data Stored in localStorage",
        "Sensitive data (auth tokens, passwords, secrets) is being stored in "
        "localStorage, which is accessible to any JavaScript on the page including XSS payloads.",
    ),
]


# ---------------------------------------------------------------------------
# SQL Injection Detection Patterns
# ---------------------------------------------------------------------------

SQL_INJECTION_PATTERNS: list[tuple[re.Pattern[str], str, str, str]] = [
    (
        re.compile(
            r"""f['\"]\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\s+.*\{.*\}""",
            re.IGNORECASE | re.DOTALL,
        ),
        "SQL-001",
        "SQL Injection via F-String",
        "SQL query is constructed using Python f-string interpolation with "
        "user-controlled variables. Use parameterized queries instead.",
    ),
    (
        re.compile(
            r"""['\"]\s*(?:SELECT|INSERT|UPDATE|DELETE)\s+.*%s""",
            re.IGNORECASE,
        ),
        "SQL-002",
        "SQL Injection via %-Formatting",
        "SQL query uses %-style string formatting. Use parameterized queries.",
    ),
    (
        re.compile(
            r"""['\"]\s*(?:SELECT|INSERT|UPDATE|DELETE)\s+.*\+\s*['\"]?""",
            re.IGNORECASE,
        ),
        "SQL-003",
        "SQL Injection via String Concatenation",
        "SQL query is built using string concatenation, which is vulnerable "
        "to SQL injection. Use parameterized queries.",
    ),
    (
        re.compile(
            r"""(?:select|where|from|values)\s+.*\$\{.*\}""",
            re.IGNORECASE,
        ),
        "SQL-004",
        "SQL Injection via Template Literal",
        "SQL query uses JavaScript/TypeScript template literal interpolation "
        "with user input. Use parameterized queries or a query builder.",
    ),
]


# ---------------------------------------------------------------------------
# Client-Side Data Fetching Anti-Pattern Detection (TS/JS specific)
# ---------------------------------------------------------------------------

CLIENT_SIDE_PATTERNS: list[tuple[re.Pattern[str], str, str, str]] = [
    (
        re.compile(
            r"""(?:supabase|firebase|prisma|knex|sequelize|typeorm|drizzle)\s*[\.\(].*(?:from|select|insert|update|delete|query|collection)""",
            re.IGNORECASE,
        ),
        "ARCH-001",
        "Direct Database Query in Client Component",
        "A database client (Supabase/Firebase/ORM) is being called directly "
        "from a client-side component. Database queries must be routed through "
        "server-side API routes or server actions.",
    ),
    (
        re.compile(
            r"""fetch\s*\(.*\/rest\/v1\/""",
            re.IGNORECASE,
        ),
        "ARCH-002",
        "Direct REST API Call to Database Service from Client",
        "A direct fetch() call to a database REST API (e.g., Supabase REST) "
        "is made from client code. This bypasses server-side authorization and RLS.",
    ),
]


# ---------------------------------------------------------------------------
# Python-Specific AST Detectors
# ---------------------------------------------------------------------------


@dataclass
class ViolationRecord:
    """Internal representation of a detected violation."""

    rule_id: str
    rule_name: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    line_number: int
    column: int
    snippet: str
    message: str
    suggested_fix: str = ""


@dataclass
class RulesEngine:
    """Deterministic rules engine for detecting architectural anti-patterns.

    This engine uses Python's ``ast`` module for Python files and regex
    pattern matching for TypeScript/JavaScript files. Every detection is
    100% deterministic — no LLM calls are made.
    """

    excluded_globs: list[str] = field(default_factory=lambda: [
        "**/test/**",
        "**/tests/**",
        "**/__tests__/**",
        "**/__mocks__/**",
        "**/*.test.*",
        "**/*.spec.*",
    ])

    def analyze(self, source: str, file_path: str, language: str, execution_context: str) -> list[ViolationRecord]:
        """Run all applicable rules against the given source code.

        Args:
            source: The raw source code content.
            file_path: Path to the file (for context and exclusion matching).
            language: One of 'python', 'typescript', 'javascript', 'unknown'.
            execution_context: One of 'client', 'server', 'ambiguous'.

        Returns:
            A list of ViolationRecord objects, one per detected violation.
        """
        violations: list[ViolationRecord] = []
        lines = source.splitlines()

        # --- Universal rules (all languages) ---
        violations.extend(self._check_secret_patterns(source, lines))
        violations.extend(self._check_sql_injection_patterns(source, lines))

        # --- Client-side specific rules (TS/JS only, in client context) ---
        if language in ("typescript", "javascript") and execution_context in ("client", "ambiguous"):
            violations.extend(self._check_client_side_patterns(source, lines, execution_context))

        # --- Python-specific AST rules ---
        if language == "python":
            violations.extend(self._check_python_ast(source, lines))

        return violations

    def _check_secret_patterns(
        self, source: str, lines: list[str]
    ) -> list[ViolationRecord]:
        """Scan source code for hardcoded secrets using regex patterns."""
        violations: list[ViolationRecord] = []
        for pattern, rule_id, rule_name, message in SECRET_PATTERNS:
            for match in pattern.finditer(source):
                line_num = source[:match.start()].count("\n") + 1
                snippet = lines[line_num - 1].strip() if line_num <= len(lines) else match.group()
                violations.append(
                    ViolationRecord(
                        rule_id=rule_id,
                        rule_name=rule_name,
                        severity="CRITICAL",
                        line_number=line_num,
                        column=match.start() - source.rfind("\n", 0, match.start()) - 1,
                        snippet=snippet,
                        message=message,
                        suggested_fix=(
                            "Move this credential to an environment variable "
                            "(e.g., `os.environ['KEY']` or `process.env.KEY`) "
                            "and load it at runtime via a secrets manager."
                        ),
                    )
                )
        return violations

    def _check_sql_injection_patterns(
        self, source: str, lines: list[str]
    ) -> list[ViolationRecord]:
        """Detect SQL injection vulnerabilities via string interpolation."""
        violations: list[ViolationRecord] = []
        for pattern, rule_id, rule_name, message in SQL_INJECTION_PATTERNS:
            for match in pattern.finditer(source):
                line_num = source[:match.start()].count("\n") + 1
                snippet = lines[line_num - 1].strip() if line_num <= len(lines) else match.group()
                violations.append(
                    ViolationRecord(
                        rule_id=rule_id,
                        rule_name=rule_name,
                        severity="HIGH",
                        line_number=line_num,
                        column=match.start() - source.rfind("\n", 0, match.start()) - 1,
                        snippet=snippet,
                        message=message,
                        suggested_fix=(
                            "Use parameterized queries with placeholders "
                            "(e.g., `cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))`) "
                            "instead of string interpolation."
                        ),
                    )
                )
        return violations

    def _check_client_side_patterns(
        self, source: str, lines: list[str], execution_context: str
    ) -> list[ViolationRecord]:
        """Detect client-side database query anti-patterns in TS/JS."""
        violations: list[ViolationRecord] = []
        severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] = (
            "CRITICAL" if execution_context == "client" else "MEDIUM"
        )
        for pattern, rule_id, rule_name, message in CLIENT_SIDE_PATTERNS:
            for match in pattern.finditer(source):
                line_num = source[:match.start()].count("\n") + 1
                snippet = lines[line_num - 1].strip() if line_num <= len(lines) else match.group()
                violations.append(
                    ViolationRecord(
                        rule_id=rule_id,
                        rule_name=rule_name,
                        severity=severity,
                        line_number=line_num,
                        column=match.start() - source.rfind("\n", 0, match.start()) - 1,
                        snippet=snippet,
                        message=(
                            message
                            + (" (File is in 'ambiguous' context — add 'use server' directive "
                               "or move to a server route to suppress this warning.)"
                               if execution_context == "ambiguous" else "")
                        ),
                        suggested_fix=(
                            "Move this database query to a server-side API route, "
                            "Server Action ('use server'), or a server component. "
                            "Call the server endpoint from the client instead."
                        ),
                    )
                )
        return violations

    def _check_python_ast(
        self, source: str, lines: list[str]
    ) -> list[ViolationRecord]:
        """Run Python-specific AST-based checks.

        Detects:
        - SQL injection via f-strings in ``cursor.execute()`` calls.
        - Missing input validation (raw ``request.json()`` without Pydantic).
        - N+1 query patterns (``cursor.execute()`` inside ``for`` loops).
        - Logging of sensitive data (``print()`` with password/secret/token).
        """
        violations: list[ViolationRecord] = []
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return violations  # Parse errors are handled by the IngestorNode

        for node in ast.walk(tree):
            # --- Detect cursor.execute() with f-string or %-format ---
            if isinstance(node, ast.Call):
                violations.extend(
                    self._check_cursor_execute(node, lines)
                )

            # --- Detect raw request.json() without validation ---
            if isinstance(node, ast.AsyncFunctionDef) or isinstance(node, ast.FunctionDef):
                violations.extend(
                    self._check_unvalidated_request_body(node, source, lines)
                )

            # --- Detect N+1 query: cursor.execute() inside for-loop ---
            if isinstance(node, ast.For) or isinstance(node, ast.AsyncFor):
                violations.extend(
                    self._check_n_plus_one(node, lines)
                )

            # --- Detect print() with sensitive variable names ---
            if isinstance(node, ast.Call):
                violations.extend(
                    self._check_sensitive_logging(node, source, lines)
                )

        return violations

    def _check_cursor_execute(
        self, node: ast.Call, lines: list[str]
    ) -> list[ViolationRecord]:
        """Detect cursor.execute() calls with interpolated SQL strings."""
        violations: list[ViolationRecord] = []
        # Check if this is a method call like cursor.execute(...)
        if not (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "execute"
            and node.args
        ):
            return violations

        first_arg = node.args[0]

        # Check for f-string: JoinedStr node
        if isinstance(first_arg, ast.JoinedStr):
            snippet = lines[node.lineno - 1].strip() if node.lineno <= len(lines) else "<unavailable>"
            violations.append(
                ViolationRecord(
                    rule_id="SQL-AST-001",
                    rule_name="SQL Injection via F-String in execute()",
                    severity="CRITICAL",
                    line_number=node.lineno,
                    column=node.col_offset,
                    snippet=snippet,
                    message=(
                        "cursor.execute() is called with an f-string, allowing "
                        "arbitrary SQL injection. Use parameterized queries."
                    ),
                    suggested_fix=(
                        "Replace f-string with parameterized query: "
                        "cursor.execute('SELECT * FROM t WHERE id = ?', (value,))"
                    ),
                )
            )

        # Check for variable reference (query built elsewhere via f-string)
        if isinstance(first_arg, ast.Name):
            snippet = lines[node.lineno - 1].strip() if node.lineno <= len(lines) else "<unavailable>"
            violations.append(
                ViolationRecord(
                    rule_id="SQL-AST-002",
                    rule_name="SQL Query Passed as Variable to execute()",
                    severity="HIGH",
                    line_number=node.lineno,
                    column=node.col_offset,
                    snippet=snippet,
                    message=(
                        "cursor.execute() receives a variable-constructed query. "
                        "If this variable is built via string interpolation, it is "
                        "vulnerable to SQL injection. Use parameterized queries."
                    ),
                    suggested_fix=(
                        "Ensure the query uses parameterized placeholders: "
                        "cursor.execute('SELECT ... WHERE id = ?', (param,))"
                    ),
                )
            )

        return violations

    def _check_unvalidated_request_body(
        self,
        node: ast.AsyncFunctionDef | ast.FunctionDef,
        source: str,
        lines: list[str],
    ) -> list[ViolationRecord]:
        """Detect FastAPI/Flask handlers that consume raw request.json() without Pydantic models."""
        violations: list[ViolationRecord] = []
        has_request_param = any(
            (isinstance(arg.annotation, ast.Attribute) and arg.annotation.attr == "Request")
            or (isinstance(arg.annotation, ast.Name) and arg.annotation.id == "Request")
            for arg in node.args.args
            if arg.annotation is not None
        )
        if not has_request_param:
            return violations

        # Walk the function body for `request.json()` or `await request.json()`
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                if (
                    isinstance(child.func, ast.Attribute)
                    and child.func.attr == "json"
                    and isinstance(child.func.value, ast.Name)
                    and child.func.value.id == "request"
                ):
                    snippet = lines[child.lineno - 1].strip() if child.lineno <= len(lines) else "<unavailable>"
                    violations.append(
                        ViolationRecord(
                            rule_id="VAL-001",
                            rule_name="Unvalidated Request Body",
                            severity="HIGH",
                            line_number=child.lineno,
                            column=child.col_offset,
                            snippet=snippet,
                            message=(
                                "request.json() is called without schema validation. "
                                "Raw JSON input should be validated against a Pydantic "
                                "model to prevent injection and type-confusion attacks."
                            ),
                            suggested_fix=(
                                "Define a Pydantic BaseModel for the expected request body "
                                "and use it as a FastAPI dependency: "
                                "async def handler(body: MyModel): ..."
                            ),
                        )
                    )
        return violations

    def _check_n_plus_one(
        self, node: ast.For | ast.AsyncFor, lines: list[str]
    ) -> list[ViolationRecord]:
        """Detect N+1 query patterns: cursor.execute() inside a for-loop."""
        violations: list[ViolationRecord] = []
        for child in ast.walk(node):
            if (
                isinstance(child, ast.Call)
                and isinstance(child.func, ast.Attribute)
                and child.func.attr == "execute"
                and child is not node  # Don't match the for-loop itself
            ):
                snippet = lines[child.lineno - 1].strip() if child.lineno <= len(lines) else "<unavailable>"
                violations.append(
                    ViolationRecord(
                        rule_id="PERF-001",
                        rule_name="N+1 Query Pattern",
                        severity="MEDIUM",
                        line_number=child.lineno,
                        column=child.col_offset,
                        snippet=snippet,
                        message=(
                            "A database query is executed inside a loop, causing an "
                            "N+1 query performance anti-pattern. Each iteration sends "
                            "a separate query to the database."
                        ),
                        suggested_fix=(
                            "Refactor to use a single JOINed query or batch operation: "
                            "SELECT users.*, teams.* FROM users JOIN teams ON ..."
                        ),
                    )
                )
        return violations

    def _check_sensitive_logging(
        self, node: ast.Call, source: str, lines: list[str]
    ) -> list[ViolationRecord]:
        """Detect print()/logging calls that include sensitive variable names."""
        violations: list[ViolationRecord] = []
        # Check if this is print() or logging.info/warning/error/debug
        is_print = isinstance(node.func, ast.Name) and node.func.id == "print"
        is_logging = (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in ("info", "warning", "error", "debug", "critical")
        )
        if not (is_print or is_logging):
            return violations

        # Check if any argument contains sensitive keywords
        sensitive_keywords = {"password", "secret", "token", "key", "credential", "auth"}
        node_source = ast.get_source_segment(source, node)
        if node_source is None:
            return violations

        node_lower = node_source.lower()
        matched_keywords = [kw for kw in sensitive_keywords if kw in node_lower]
        if matched_keywords:
            snippet = lines[node.lineno - 1].strip() if node.lineno <= len(lines) else "<unavailable>"
            violations.append(
                ViolationRecord(
                    rule_id="LOG-001",
                    rule_name="Sensitive Data in Log Output",
                    severity="HIGH",
                    line_number=node.lineno,
                    column=node.col_offset,
                    snippet=snippet,
                    message=(
                        f"Sensitive data ({', '.join(matched_keywords)}) is being logged "
                        f"via print()/logging. This may expose credentials in log files, "
                        f"stdout, or monitoring systems."
                    ),
                    suggested_fix=(
                        "Remove sensitive data from log statements. Log only "
                        "non-sensitive identifiers (e.g., user ID, request ID)."
                    ),
                )
            )
        return violations


# ---------------------------------------------------------------------------
# Utility: Detect execution context from source directives
# ---------------------------------------------------------------------------


def detect_execution_context(
    source: str, file_path: str
) -> Literal["client", "server", "ambiguous"]:
    """Infer whether a file executes on the client or server.

    Heuristics:
    1. Explicit ``"use client"`` or ``'use client'`` directive → client.
    2. Explicit ``"use server"`` or ``'use server'`` directive → server.
    3. File path patterns:
       - ``app/api/``, ``pages/api/``, ``+server``, ``route.ts`` → server.
       - Python files (``.py``) → server.
    4. Otherwise → ambiguous.
    """
    # Check first 10 lines for framework directives
    first_lines = "\n".join(source.splitlines()[:10])
    if re.search(r"""['\"]use client['\"]""", first_lines):
        return "client"
    if re.search(r"""['\"]use server['\"]""", first_lines):
        return "server"

    # File path heuristics
    path_lower = file_path.replace("\\", "/").lower()
    server_patterns = [
        "/api/",
        "/server/",
        "+server.",
        "route.ts",
        "route.js",
        "+page.server.",
    ]
    if any(pat in path_lower for pat in server_patterns):
        return "server"

    # Python files are always server-side
    if path_lower.endswith(".py"):
        return "server"

    return "ambiguous"


def detect_language(
    file_path: str,
) -> Literal["python", "typescript", "javascript", "unknown"]:
    """Detect the programming language from the file extension."""
    path_lower = file_path.lower()
    if path_lower.endswith(".py"):
        return "python"
    if path_lower.endswith((".ts", ".tsx")):
        return "typescript"
    if path_lower.endswith((".js", ".jsx")):
        return "javascript"
    return "unknown"
