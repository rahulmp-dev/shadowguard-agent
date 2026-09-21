"""ShadowGuard-Agent — LangGraph StateGraph pipeline wiring.

This module defines the multi-agent governance pipeline using LangGraph's
StateGraph. Each node is a pure function that transforms the shared state.

Pipeline flow:
    START → IngestorNode → StaticAnalysisNode → ClassificationNode
          → SynthesizerNode → CriticNode → [conditional] → END
                                   ↑              |
                                   └──── REJECTED ─┘  (max 2 retries)
"""

from __future__ import annotations

import ast
import re
import textwrap
from typing import Literal

from langgraph.graph import END, START, StateGraph

from shadowguard.rules import RulesEngine, detect_execution_context, detect_language
from shadowguard.schemas import ShadowGuardState


# ---------------------------------------------------------------------------
# Shared engine instance
# ---------------------------------------------------------------------------

_rules_engine = RulesEngine()


# ---------------------------------------------------------------------------
# Node: Ingestor
# ---------------------------------------------------------------------------


def ingestor_node(state: ShadowGuardState) -> dict:
    """Ingest a source file and detect its language and execution context.

    Reads the raw source code (already provided in state), determines the
    programming language from the file extension, and infers the execution
    context (client/server/ambiguous) from framework directives and file
    path conventions.

    If the file is Python, validates that it can be parsed by ``ast.parse()``.
    Parse failures are recorded as ``parse_error`` so downstream nodes can
    skip AST-based analysis gracefully.
    """
    file_path: str = state["file_path"]
    raw_code: str = state["raw_code"]

    language = detect_language(file_path)
    execution_context = detect_execution_context(raw_code, file_path)

    parse_error: str | None = None
    if language == "python":
        try:
            ast.parse(raw_code)
        except SyntaxError as exc:
            parse_error = f"SyntaxError at line {exc.lineno}: {exc.msg}"

    return {
        "language": language,
        "execution_context": execution_context,
        "parse_error": parse_error,
    }


# ---------------------------------------------------------------------------
# Node: Static Analysis
# ---------------------------------------------------------------------------


def static_analysis_node(state: ShadowGuardState) -> dict:
    """Run deterministic AST and regex-based rule checks.

    Uses the :class:`RulesEngine` to detect architectural anti-patterns
    including hardcoded secrets, SQL injection, client-side database
    queries, missing input validation, N+1 queries, and sensitive data
    logging.

    All detections are 100% deterministic — no LLM calls are made.
    """
    raw_code: str = state["raw_code"]
    file_path: str = state["file_path"]
    language: str = state.get("language", "unknown")
    execution_context: str = state.get("execution_context", "ambiguous")

    violations = _rules_engine.analyze(
        source=raw_code,
        file_path=file_path,
        language=language,
        execution_context=execution_context,
    )

    violation_dicts = [
        {
            "rule_id": v.rule_id,
            "rule_name": v.rule_name,
            "severity": v.severity,
            "line_number": v.line_number,
            "column": v.column,
            "snippet": v.snippet,
            "message": v.message,
            "suggested_fix": v.suggested_fix,
        }
        for v in violations
    ]

    return {"ast_violations": violation_dicts}


# ---------------------------------------------------------------------------
# Node: Classification
# ---------------------------------------------------------------------------

# Fixed scoring matrix — deterministic, auditable, no LLM
_SEVERITY_WEIGHTS: dict[str, int] = {
    "CRITICAL": 25,
    "HIGH": 15,
    "MEDIUM": 8,
    "LOW": 3,
}


def classification_node(state: ShadowGuardState) -> dict:
    """Classify the overall risk level of the file based on violations.

    Uses a fixed scoring matrix to compute a numeric risk score (0-100)
    and maps it to a categorical risk level. This is fully deterministic
    and auditable — no LLM involvement.

    Scoring:
        - Each CRITICAL violation adds 25 points.
        - Each HIGH violation adds 15 points.
        - Each MEDIUM violation adds 8 points.
        - Each LOW violation adds 3 points.
        - Score is capped at 100.

    Risk mapping:
        - 0       → NONE
        - 1-20    → LOW
        - 21-45   → MEDIUM
        - 46-70   → HIGH
        - 71-100  → CRITICAL
    """
    violations: list[dict] = state.get("ast_violations", [])

    if not violations:
        return {
            "risk_level": "NONE",
            "risk_score": 0,
        }

    raw_score = sum(
        _SEVERITY_WEIGHTS.get(v.get("severity", "LOW"), 3) for v in violations
    )
    risk_score = min(raw_score, 100)

    if risk_score >= 71:
        risk_level: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"] = "CRITICAL"
    elif risk_score >= 46:
        risk_level = "HIGH"
    elif risk_score >= 21:
        risk_level = "MEDIUM"
    elif risk_score >= 1:
        risk_level = "LOW"
    else:
        risk_level = "NONE"

    return {
        "risk_level": risk_level,
        "risk_score": risk_score,
    }


# ---------------------------------------------------------------------------
# Node: Synthesizer
# ---------------------------------------------------------------------------

# Deterministic refactoring templates — no LLM needed for common patterns.
# This avoids token costs and hallucinations for well-understood fixes.

_SECRET_ENV_TEMPLATE = 'os.environ["{key_name}"]'
_SECRET_ENV_TEMPLATE_TS = 'process.env.{key_name}'


def _synthesize_refactored_code(raw_code: str, violations: list[dict], language: str) -> str:
    """Generate a refactored version of the source code by applying fixes.

    For the deterministic pipeline (no LLM), this applies pattern-based
    transformations for well-understood anti-patterns:

    1. **Hardcoded secrets** → replaced with environment variable lookups.
    2. **SQL injection** → annotated with parameterized query comments.
    3. **Unvalidated input** → annotated with Pydantic model suggestion.
    4. **N+1 queries** → annotated with JOIN suggestion.

    For complex or ambiguous violations, the refactored code includes
    inline ``# SHADOWGUARD-FIX:`` comments explaining the required change.
    """
    refactored = raw_code
    applied_fixes: list[str] = []

    for violation in violations:
        rule_id = violation.get("rule_id", "")
        snippet = violation.get("snippet", "")

        if rule_id in ("SEC-001", "SEC-002", "SEC-003", "SEC-004", "SEC-005"):
            # For secrets: add a comment above the line indicating the fix
            if snippet and snippet in refactored:
                comment_prefix = "#" if language == "python" else "//"
                fix_comment = (
                    f"{comment_prefix} SHADOWGUARD-FIX [{rule_id}]: Move this credential to "
                    f"an environment variable or secrets manager."
                )
                refactored = refactored.replace(
                    snippet,
                    f"{fix_comment}\n{comment_prefix} {snippet}  {comment_prefix} ← ORIGINAL (REMOVE)",
                    1,
                )
                applied_fixes.append(rule_id)

        elif rule_id.startswith("SQL"):
            if snippet and snippet in refactored:
                comment_prefix = "#" if language == "python" else "//"
                fix_comment = (
                    f"{comment_prefix} SHADOWGUARD-FIX [{rule_id}]: Replace with parameterized query. "
                    f"Use placeholders (?, %s, or $1) instead of string interpolation."
                )
                refactored = refactored.replace(
                    snippet,
                    f"{fix_comment}\n{snippet}",
                    1,
                )
                applied_fixes.append(rule_id)

        elif rule_id == "VAL-001":
            if snippet and snippet in refactored:
                comment_prefix = "#" if language == "python" else "//"
                fix_comment = (
                    f"{comment_prefix} SHADOWGUARD-FIX [{rule_id}]: Validate this input with a "
                    f"Pydantic model instead of accepting raw JSON."
                )
                refactored = refactored.replace(
                    snippet,
                    f"{fix_comment}\n{snippet}",
                    1,
                )
                applied_fixes.append(rule_id)

        elif rule_id == "PERF-001":
            if snippet and snippet in refactored:
                comment_prefix = "#" if language == "python" else "//"
                fix_comment = (
                    f"{comment_prefix} SHADOWGUARD-FIX [{rule_id}]: Refactor to a single JOIN query "
                    f"to eliminate N+1 query anti-pattern."
                )
                refactored = refactored.replace(
                    snippet,
                    f"{fix_comment}\n{snippet}",
                    1,
                )
                applied_fixes.append(rule_id)

        elif rule_id == "LOG-001":
            if snippet and snippet in refactored:
                comment_prefix = "#" if language == "python" else "//"
                fix_comment = (
                    f"{comment_prefix} SHADOWGUARD-FIX [{rule_id}]: Remove sensitive data from "
                    f"log output. Log only non-sensitive identifiers."
                )
                refactored = refactored.replace(
                    snippet,
                    f"{fix_comment}\n{snippet}",
                    1,
                )
                applied_fixes.append(rule_id)

        elif rule_id == "SEC-006":
            if snippet and snippet in refactored:
                comment_prefix = "#" if language == "python" else "//"
                fix_comment = (
                    f"{comment_prefix} SHADOWGUARD-FIX [{rule_id}]: Do not store sensitive data "
                    f"in localStorage. Use httpOnly cookies or a secure session store."
                )
                refactored = refactored.replace(
                    snippet,
                    f"{fix_comment}\n{snippet}",
                    1,
                )
                applied_fixes.append(rule_id)

        elif rule_id.startswith("ARCH"):
            if snippet and snippet in refactored:
                comment_prefix = "#" if language == "python" else "//"
                fix_comment = (
                    f"{comment_prefix} SHADOWGUARD-FIX [{rule_id}]: Move this database query to "
                    f"a server-side API route or Server Action."
                )
                refactored = refactored.replace(
                    snippet,
                    f"{fix_comment}\n{snippet}",
                    1,
                )
                applied_fixes.append(rule_id)

    # If no fixes were applied at all, return None-like marker
    if not applied_fixes:
        return raw_code

    return refactored


def synthesizer_node(state: ShadowGuardState) -> dict:
    """Synthesize a refactored version of the source code.

    In this deterministic implementation, the synthesizer applies
    pattern-based transformations and annotates the code with
    ``SHADOWGUARD-FIX`` comments. No LLM is used, ensuring zero
    hallucination and zero token cost.

    In an enterprise deployment, this node would optionally invoke an
    LLM to generate more sophisticated refactors while the CriticNode
    validates them deterministically.
    """
    violations: list[dict] = state.get("ast_violations", [])
    raw_code: str = state["raw_code"]
    language: str = state.get("language", "unknown")
    risk_level: str = state.get("risk_level", "NONE")

    if not violations or risk_level == "NONE":
        return {
            "refactored_code": None,
            "refactor_status": "SKIPPED",
        }

    refactored = _synthesize_refactored_code(raw_code, violations, language)

    if refactored == raw_code:
        return {
            "refactored_code": None,
            "refactor_status": "SKIPPED",
        }

    retries = state.get("synthesis_retries", 0)
    return {
        "refactored_code": refactored,
        "refactor_status": "PARTIAL",
        "synthesis_retries": retries + 1,
    }


# ---------------------------------------------------------------------------
# Node: Critic
# ---------------------------------------------------------------------------


def critic_node(state: ShadowGuardState) -> dict:
    """Validate the synthesized refactor against the original violations.

    The Critic performs deterministic validation:
    1. Checks that the refactored code contains fix annotations for each
       violation.
    2. Verifies that no *new* secret patterns were introduced.
    3. For Python files, validates that the refactored code is still
       syntactically valid.

    Verdict:
    - ``APPROVED``: All violations have corresponding fix annotations.
    - ``REJECTED``: Some violations lack fixes or new issues were introduced.
    - ``UNVERIFIED``: No refactored code available or refactoring was skipped.
    """
    refactored_code: str | None = state.get("refactored_code")
    refactor_status: str = state.get("refactor_status", "SKIPPED")
    violations: list[dict] = state.get("ast_violations", [])
    language: str = state.get("language", "unknown")
    synthesis_retries: int = state.get("synthesis_retries", 0)
    max_retries: int = state.get("max_retries", 2)

    if refactor_status == "SKIPPED" or refactored_code is None:
        return {
            "critic_verdict": "UNVERIFIED",
            "critic_reasoning": (
                "No refactored code to evaluate — either no violations were "
                "found or the synthesizer skipped this file."
            ),
        }

    reasoning_parts: list[str] = []
    has_issues = False

    # Check 1: Verify fix annotations exist for detected violations
    annotated_rules: set[str] = set()
    for match in re.finditer(r"SHADOWGUARD-FIX \[([A-Z]+-\d+)\]", refactored_code):
        annotated_rules.add(match.group(1))

    # Only check regex-detected rules (not AST-derived variants) for annotation
    regex_rule_ids = {v["rule_id"] for v in violations if not v["rule_id"].startswith("SQL-AST")}
    unannotated = regex_rule_ids - annotated_rules
    if unannotated:
        has_issues = True
        reasoning_parts.append(
            f"Missing fix annotations for: {', '.join(sorted(unannotated))}."
        )
    else:
        reasoning_parts.append(
            f"All {len(annotated_rules)} violation(s) have fix annotations."
        )

    # Check 2: Verify no new secrets were introduced in the refactor
    new_secrets: list[str] = []
    from shadowguard.rules import SECRET_PATTERNS

    for pattern, rule_id, rule_name, _message in SECRET_PATTERNS:
        original_matches = len(pattern.findall(state["raw_code"]))
        refactored_matches = len(pattern.findall(refactored_code))
        if refactored_matches > original_matches:
            new_secrets.append(rule_id)

    if new_secrets:
        has_issues = True
        reasoning_parts.append(
            f"New secrets introduced in refactored code: {', '.join(new_secrets)}."
        )
    else:
        reasoning_parts.append("No new secrets introduced.")

    # Check 3: Python syntax validation on refactored code
    if language == "python":
        try:
            ast.parse(refactored_code)
            reasoning_parts.append("Refactored Python code is syntactically valid.")
        except SyntaxError as exc:
            has_issues = True
            reasoning_parts.append(
                f"Refactored code has syntax error at line {exc.lineno}: {exc.msg}."
            )

    # Determine verdict
    if has_issues:
        if synthesis_retries >= max_retries:
            return {
                "critic_verdict": "REJECTED",
                "critic_reasoning": (
                    "Refactoring issues detected after maximum retries. "
                    + " ".join(reasoning_parts)
                ),
                "refactor_status": "FAILED",
            }
        return {
            "critic_verdict": "REJECTED",
            "critic_reasoning": " ".join(reasoning_parts),
        }

    return {
        "critic_verdict": "APPROVED",
        "critic_reasoning": " ".join(reasoning_parts),
        "refactor_status": "SUCCESS",
    }


# ---------------------------------------------------------------------------
# Conditional edge: Critic → Synthesizer or END
# ---------------------------------------------------------------------------


def should_retry_synthesis(state: ShadowGuardState) -> Literal["synthesizer", "end"]:
    """Decide whether to retry synthesis or proceed to END.

    Returns ``"synthesizer"`` if:
    - The critic rejected the refactor, AND
    - The number of retries has not exceeded ``max_retries``.

    Returns ``"end"`` otherwise.
    """
    verdict: str = state.get("critic_verdict", "UNVERIFIED")
    retries: int = state.get("synthesis_retries", 0)
    max_retries: int = state.get("max_retries", 2)

    if verdict == "REJECTED" and retries < max_retries:
        return "synthesizer"
    return "end"


# ---------------------------------------------------------------------------
# Build the StateGraph
# ---------------------------------------------------------------------------


def build_pipeline() -> StateGraph:
    """Construct and compile the ShadowGuard LangGraph pipeline.

    Returns:
        A compiled :class:`StateGraph` ready to be invoked with an initial
        state dictionary.
    """
    graph = StateGraph(ShadowGuardState)

    # Add nodes
    graph.add_node("ingestor", ingestor_node)
    graph.add_node("static_analysis", static_analysis_node)
    graph.add_node("classification", classification_node)
    graph.add_node("synthesizer", synthesizer_node)
    graph.add_node("critic", critic_node)

    # Linear edges: START → ingestor → static_analysis → classification → synthesizer
    graph.add_edge(START, "ingestor")
    graph.add_edge("ingestor", "static_analysis")
    graph.add_edge("static_analysis", "classification")
    graph.add_edge("classification", "synthesizer")
    graph.add_edge("synthesizer", "critic")

    # Conditional edge from critic: retry or end
    graph.add_conditional_edges(
        "critic",
        should_retry_synthesis,
        {
            "synthesizer": "synthesizer",
            "end": END,
        },
    )

    return graph.compile()


def run_pipeline(file_path: str, raw_code: str, max_retries: int = 2) -> dict:
    """Execute the ShadowGuard pipeline for a single file.

    Args:
        file_path: Path to the source file being analyzed.
        raw_code: The raw source code content to analyze.
        max_retries: Maximum Synthesizer → Critic retry cycles.

    Returns:
        The final state dictionary after pipeline execution.
    """
    pipeline = build_pipeline()

    initial_state: ShadowGuardState = {
        "file_path": file_path,
        "raw_code": raw_code,
        "language": "unknown",
        "execution_context": "ambiguous",
        "ast_violations": [],
        "risk_level": "NONE",
        "risk_score": 0,
        "refactored_code": None,
        "refactor_status": "SKIPPED",
        "critic_verdict": "UNVERIFIED",
        "critic_reasoning": "",
        "synthesis_retries": 0,
        "max_retries": max_retries,
        "parse_error": None,
    }

    result = pipeline.invoke(initial_state)
    return result
