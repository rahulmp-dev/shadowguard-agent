"""ShadowGuard-Agent — CLI runner with Rich formatting.

This module provides a polished terminal interface for running the
ShadowGuard governance pipeline against target source files. It uses
Rich for formatted, color-coded output including violation tables,
risk gauges, and side-by-side refactoring diffs.

Usage:
    python -m shadowguard.main [file1] [file2] ...
    python shadowguard/main.py                         # scans examples/

If no files are specified, it scans the ``examples/`` directory.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from shadowguard.graph import run_pipeline
from shadowguard.schemas import FileAnalysisResult, PipelineReport, Violation


console = Console()

# ---------------------------------------------------------------------------
# Color mappings for severity / risk levels
# ---------------------------------------------------------------------------

_SEVERITY_COLORS: dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH": "bold yellow",
    "MEDIUM": "yellow",
    "LOW": "dim cyan",
    "NONE": "green",
}

_RISK_EMOJIS: dict[str, str] = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "NONE": "🟢",
}

_VERDICT_STYLES: dict[str, str] = {
    "APPROVED": "bold green",
    "REJECTED": "bold red",
    "UNVERIFIED": "dim yellow",
}


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------


def _render_header() -> None:
    """Print the ShadowGuard banner."""
    banner = Text()
    banner.append("╔═══════════════════════════════════════════════════════════════╗\n", style="bold cyan")
    banner.append("║              ", style="bold cyan")
    banner.append("ShadowGuard-Agent v1.0.0", style="bold white")
    banner.append("                        ║\n", style="bold cyan")
    banner.append("║    ", style="bold cyan")
    banner.append("Autonomous AI Code Governance Pipeline", style="italic cyan")
    banner.append("               ║\n", style="bold cyan")
    banner.append("║    ", style="bold cyan")
    banner.append("By Rahul M P                              ", style="dim white")
    banner.append("              ║\n", style="bold cyan")
    banner.append("╚═══════════════════════════════════════════════════════════════╝", style="bold cyan")
    console.print(banner)
    console.print()


def _render_file_header(file_path: str, language: str, context: str) -> None:
    """Print the file analysis header."""
    console.rule(f"[bold white] Analyzing: {escape(file_path)} ", style="cyan")
    console.print(
        f"  Language: [bold]{language}[/bold]  |  "
        f"Execution Context: [bold]{context}[/bold]"
    )
    console.print()


def _render_violations_table(violations: list[dict]) -> None:
    """Render a Rich table of all detected violations."""
    if not violations:
        console.print("  [green]✓ No violations detected.[/green]\n")
        return

    table = Table(
        title="Detected Violations",
        box=box.ROUNDED,
        show_lines=True,
        title_style="bold white",
        border_style="cyan",
        expand=True,
    )
    table.add_column("#", style="dim", width=3, justify="right")
    table.add_column("Rule", style="bold", width=12)
    table.add_column("Severity", width=10, justify="center")
    table.add_column("Line", width=5, justify="right")
    table.add_column("Rule Name", width=30)
    table.add_column("Message", ratio=2)

    for idx, v in enumerate(violations, 1):
        severity = v.get("severity", "LOW")
        color = _SEVERITY_COLORS.get(severity, "white")
        table.add_row(
            str(idx),
            v.get("rule_id", "???"),
            Text(severity, style=color),
            str(v.get("line_number", "?")),
            v.get("rule_name", "Unknown"),
            v.get("message", ""),
        )

    console.print(table)
    console.print()


def _render_risk_assessment(risk_level: str, risk_score: int) -> None:
    """Render the risk gauge."""
    emoji = _RISK_EMOJIS.get(risk_level, "⚪")
    color = _SEVERITY_COLORS.get(risk_level, "white")

    # Build a simple progress bar
    filled = risk_score // 5
    empty = 20 - filled
    if risk_score >= 71:
        bar_color = "red"
    elif risk_score >= 46:
        bar_color = "yellow"
    elif risk_score >= 21:
        bar_color = "dark_orange"
    else:
        bar_color = "green"

    bar = f"[{bar_color}]{'█' * filled}[/{bar_color}][dim]{'░' * empty}[/dim]"

    console.print(
        Panel(
            f"{emoji} Risk Level: [{color}]{risk_level}[/{color}]  •  "
            f"Score: [{color}]{risk_score}/100[/{color}]\n\n"
            f"  {bar}  {risk_score}%",
            title="[bold]Risk Assessment[/bold]",
            border_style="cyan",
        )
    )
    console.print()


def _render_refactor_status(
    refactor_status: str,
    critic_verdict: str,
    critic_reasoning: str,
    synthesis_retries: int,
    refactored_code: str | None,
    raw_code: str,
) -> None:
    """Render the refactoring status and critic verdict."""
    verdict_style = _VERDICT_STYLES.get(critic_verdict, "white")

    # Build status panel content
    lines: list[str] = [
        f"Refactor Status: [bold]{refactor_status}[/bold]",
        f"Critic Verdict:  [{verdict_style}]{critic_verdict}[/{verdict_style}]",
        f"Synthesis Retries: {synthesis_retries}",
        "",
        f"[dim]Reasoning: {escape(critic_reasoning)}[/dim]",
    ]

    console.print(
        Panel(
            "\n".join(lines),
            title="[bold]Refactoring & Critic Report[/bold]",
            border_style="cyan",
        )
    )

    # Show a snippet of the refactored code if available
    if refactored_code and refactored_code != raw_code:
        # Show only the lines that contain SHADOWGUARD-FIX markers
        fix_lines: list[str] = []
        for i, line in enumerate(refactored_code.splitlines(), 1):
            if "SHADOWGUARD-FIX" in line:
                fix_lines.append(f"  [bold green]+ L{i}:[/bold green] {escape(line.strip())}")
                # Also show the next line (the annotated original)
                next_lines = refactored_code.splitlines()
                if i < len(next_lines):
                    fix_lines.append(f"  [dim red]  L{i+1}:[/dim red] {escape(next_lines[i].strip())}")

        if fix_lines:
            console.print(
                Panel(
                    "\n".join(fix_lines[:30]),  # Cap at 30 lines for readability
                    title="[bold]Applied Fix Annotations (excerpt)[/bold]",
                    border_style="green",
                )
            )

    console.print()


def _render_summary(report: PipelineReport) -> None:
    """Render the final pipeline summary."""
    console.rule("[bold white] Pipeline Summary ", style="bold cyan")
    console.print()

    summary_table = Table(
        box=box.SIMPLE_HEAVY,
        show_header=False,
        border_style="cyan",
        padding=(0, 2),
    )
    summary_table.add_column("Metric", style="bold")
    summary_table.add_column("Value", justify="right")

    summary_table.add_row("Files Scanned", str(report.files_scanned))
    summary_table.add_row("Files with Violations", f"[bold red]{report.files_with_violations}[/bold red]")
    summary_table.add_row("Total Violations", f"[bold]{report.total_violations}[/bold]")
    summary_table.add_row("🔴 Critical", f"[bold red]{report.critical_count}[/bold red]")
    summary_table.add_row("🟠 High", f"[bold yellow]{report.high_count}[/bold yellow]")
    summary_table.add_row("🟡 Medium", f"[yellow]{report.medium_count}[/yellow]")
    summary_table.add_row("🔵 Low", f"[cyan]{report.low_count}[/cyan]")

    console.print(summary_table)
    console.print()


# ---------------------------------------------------------------------------
# Core scanning logic
# ---------------------------------------------------------------------------


def scan_file(file_path: str) -> FileAnalysisResult:
    """Scan a single file through the ShadowGuard pipeline.

    Args:
        file_path: Path to the source file to analyze.

    Returns:
        A :class:`FileAnalysisResult` with all violations and refactoring data.
    """
    abs_path = str(Path(file_path).resolve())

    with open(abs_path, encoding="utf-8", errors="replace") as f:
        raw_code = f.read()

    # Run the LangGraph pipeline
    result = run_pipeline(file_path=abs_path, raw_code=raw_code)

    # Convert violation dicts to Violation models
    violation_models = [
        Violation(**v) for v in result.get("ast_violations", [])
    ]

    return FileAnalysisResult(
        file_path=abs_path,
        language=result.get("language", "unknown"),
        execution_context=result.get("execution_context", "ambiguous"),
        raw_code=raw_code,
        violations=violation_models,
        risk_level=result.get("risk_level", "NONE"),
        risk_score=result.get("risk_score", 0),
        refactored_code=result.get("refactored_code"),
        refactor_status=result.get("refactor_status", "SKIPPED"),
        critic_verdict=result.get("critic_verdict", "UNVERIFIED"),
        critic_reasoning=result.get("critic_reasoning", ""),
        synthesis_retries=result.get("synthesis_retries", 0),
        max_retries=result.get("max_retries", 2),
        parse_error=result.get("parse_error"),
    )


def scan_directory(directory: str) -> list[FileAnalysisResult]:
    """Scan all supported files in a directory.

    Supported extensions: .py, .ts, .tsx, .js, .jsx

    Args:
        directory: Path to the directory to scan.

    Returns:
        A list of :class:`FileAnalysisResult` for each scanned file.
    """
    supported_extensions = {".py", ".ts", ".tsx", ".js", ".jsx"}
    results: list[FileAnalysisResult] = []

    dir_path = Path(directory)
    if not dir_path.exists():
        console.print(f"[red]Error: Directory '{directory}' does not exist.[/red]")
        return results

    for file_path in sorted(dir_path.rglob("*")):
        if file_path.suffix.lower() in supported_extensions and file_path.is_file():
            results.append(scan_file(str(file_path)))

    return results


def build_report(results: list[FileAnalysisResult]) -> PipelineReport:
    """Build an aggregate pipeline report from individual file results.

    Args:
        results: List of per-file analysis results.

    Returns:
        A :class:`PipelineReport` with aggregated statistics.
    """
    report = PipelineReport(
        files_scanned=len(results),
        results=results,
    )

    for result in results:
        if result.violations:
            report.files_with_violations += 1
        report.total_violations += len(result.violations)
        for v in result.violations:
            if v.severity == "CRITICAL":
                report.critical_count += 1
            elif v.severity == "HIGH":
                report.high_count += 1
            elif v.severity == "MEDIUM":
                report.medium_count += 1
            elif v.severity == "LOW":
                report.low_count += 1

    return report


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Run the ShadowGuard governance pipeline."""
    _render_header()

    # Determine target files
    args = sys.argv[1:]

    if args:
        target_files = args
    else:
        # Default: scan the examples/ directory relative to the project root
        # Try multiple candidate locations
        candidates = [
            Path(__file__).resolve().parent.parent / "examples",
            Path.cwd() / "examples",
        ]
        examples_dir = None
        for candidate in candidates:
            if candidate.exists():
                examples_dir = candidate
                break

        if examples_dir is None:
            console.print(
                "[red]No target files specified and no examples/ directory found.[/red]\n"
                "[dim]Usage: python -m shadowguard.main [file1] [file2] ...[/dim]"
            )
            sys.exit(1)

        target_files = [
            str(f) for f in sorted(examples_dir.rglob("*"))
            if f.suffix.lower() in {".py", ".ts", ".tsx", ".js", ".jsx"} and f.is_file()
        ]
        console.print(
            f"[dim]No files specified — scanning examples/ directory "
            f"({len(target_files)} file(s) found)[/dim]\n"
        )

    if not target_files:
        console.print("[red]No supported files found to scan.[/red]")
        sys.exit(1)

    # Scan all files
    start_time = time.perf_counter()
    results: list[FileAnalysisResult] = []

    for file_path in target_files:
        if not Path(file_path).exists():
            console.print(f"[red]Warning: File '{file_path}' not found, skipping.[/red]\n")
            continue

        result = scan_file(file_path)
        results.append(result)

        # Render results for this file
        _render_file_header(
            result.file_path, result.language, result.execution_context
        )

        if result.parse_error:
            console.print(
                f"  [yellow]⚠ Parse Error: {escape(result.parse_error)}[/yellow]\n"
            )

        _render_violations_table(
            [v.model_dump() for v in result.violations]
        )
        _render_risk_assessment(result.risk_level, result.risk_score)
        _render_refactor_status(
            result.refactor_status,
            result.critic_verdict,
            result.critic_reasoning,
            result.synthesis_retries,
            result.refactored_code,
            result.raw_code,
        )

    # Build and render aggregate report
    elapsed = time.perf_counter() - start_time
    report = build_report(results)
    _render_summary(report)

    console.print(f"[dim]Pipeline completed in {elapsed:.2f}s[/dim]\n")

    # Exit with non-zero code if critical violations found
    if report.critical_count > 0:
        console.print(
            "[bold red]⛔ CRITICAL violations detected — review required before merge.[/bold red]\n"
        )
        sys.exit(1)
    elif report.total_violations > 0:
        console.print(
            "[yellow]⚠ Violations detected — review recommended.[/yellow]\n"
        )
        sys.exit(0)
    else:
        console.print(
            "[green]✅ All files passed governance checks.[/green]\n"
        )
        sys.exit(0)


if __name__ == "__main__":
    main()
