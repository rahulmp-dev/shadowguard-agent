"""ShadowGuard-Agent — Pydantic v2 models and LangGraph state definitions.

This module defines the core data models used throughout the ShadowGuard
multi-agent governance pipeline. All models use strict Pydantic v2 validation
with explicit type annotations.
"""

from __future__ import annotations

import operator
from typing import Annotated, Literal

from pydantic import BaseModel, Field
from typing_extensions import TypedDict


# ---------------------------------------------------------------------------
# Pydantic v2 Models (for validation and serialization)
# ---------------------------------------------------------------------------


class Violation(BaseModel):
    """A single detected architectural anti-pattern violation."""

    rule_id: str = Field(
        description="Unique identifier for the rule that was violated, e.g. 'SEC-001'."
    )
    rule_name: str = Field(
        description="Human-readable name of the violated rule."
    )
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] = Field(
        description="Severity level of the violation."
    )
    line_number: int = Field(
        ge=1,
        description="1-based line number where the violation was detected."
    )
    column: int = Field(
        ge=0,
        description="0-based column offset where the violation starts."
    )
    snippet: str = Field(
        description="The offending code snippet (the exact line or expression)."
    )
    message: str = Field(
        description="Detailed explanation of why this code is a violation."
    )
    suggested_fix: str = Field(
        default="",
        description="A brief textual description of how to fix this violation."
    )


class FileAnalysisResult(BaseModel):
    """Complete analysis result for a single source file."""

    file_path: str = Field(
        description="Absolute or relative path to the analyzed file."
    )
    language: Literal["python", "typescript", "javascript", "unknown"] = Field(
        description="Detected programming language of the file."
    )
    execution_context: Literal["client", "server", "ambiguous"] = Field(
        default="ambiguous",
        description=(
            "Inferred runtime execution context. 'client' for browser-executed code, "
            "'server' for backend-only code, 'ambiguous' when it cannot be determined."
        ),
    )
    raw_code: str = Field(
        description="Original source code content of the file."
    )
    violations: list[Violation] = Field(
        default_factory=list,
        description="List of all detected violations in this file."
    )
    risk_level: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"] = Field(
        default="NONE",
        description="Overall risk classification for this file."
    )
    risk_score: int = Field(
        default=0,
        ge=0,
        le=100,
        description="Numeric risk score from 0 (no risk) to 100 (maximum risk)."
    )
    refactored_code: str | None = Field(
        default=None,
        description="LLM-synthesized refactored version of the source code, if available."
    )
    refactor_status: Literal["SUCCESS", "PARTIAL", "FAILED", "SKIPPED"] = Field(
        default="SKIPPED",
        description="Status of the refactoring attempt."
    )
    critic_verdict: Literal["APPROVED", "REJECTED", "UNVERIFIED"] = Field(
        default="UNVERIFIED",
        description="The Critic agent's verdict on the synthesized refactor."
    )
    critic_reasoning: str = Field(
        default="",
        description="The Critic agent's explanation for its verdict."
    )
    synthesis_retries: int = Field(
        default=0,
        ge=0,
        description="Number of Synthesizer → Critic retry cycles completed."
    )
    max_retries: int = Field(
        default=2,
        ge=0,
        description="Maximum allowed Synthesizer → Critic retry cycles."
    )
    parse_error: str | None = Field(
        default=None,
        description="If AST parsing failed, the error message. None if parsing succeeded."
    )


class PipelineReport(BaseModel):
    """Aggregate report for the entire ShadowGuard pipeline run."""

    files_scanned: int = Field(
        default=0,
        ge=0,
        description="Total number of files scanned."
    )
    files_with_violations: int = Field(
        default=0,
        ge=0,
        description="Number of files with at least one violation."
    )
    total_violations: int = Field(
        default=0,
        ge=0,
        description="Total number of violations across all files."
    )
    critical_count: int = Field(default=0, ge=0)
    high_count: int = Field(default=0, ge=0)
    medium_count: int = Field(default=0, ge=0)
    low_count: int = Field(default=0, ge=0)
    results: list[FileAnalysisResult] = Field(
        default_factory=list,
        description="Per-file analysis results."
    )


# ---------------------------------------------------------------------------
# LangGraph State (TypedDict with annotated reducers)
# ---------------------------------------------------------------------------


class ShadowGuardState(TypedDict, total=False):
    """LangGraph state schema for the ShadowGuard pipeline.

    Reducer semantics:
    - ``ast_violations``: uses ``operator.add`` (appends new violations).
    - All other fields: last-write-wins (default LangGraph behavior).
    """

    file_path: str
    raw_code: str
    language: Literal["python", "typescript", "javascript", "unknown"]
    execution_context: Literal["client", "server", "ambiguous"]
    ast_violations: Annotated[list[dict], operator.add]
    risk_level: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]
    risk_score: int
    refactored_code: str | None
    refactor_status: Literal["SUCCESS", "PARTIAL", "FAILED", "SKIPPED"]
    critic_verdict: Literal["APPROVED", "REJECTED", "UNVERIFIED"]
    critic_reasoning: str
    synthesis_retries: int
    max_retries: int
    parse_error: str | None
