# ShadowGuard-Agent

> **Autonomous AI Code Governance Pipeline**

Hey everyone! 👋 

I built **ShadowGuard-Agent** to be an autonomous DevSecOps CI/CD gatekeeper. 

Spending a lot of time analyzing enterprise architecture, I noticed a massive problem with the current wave of AI coding tools. Developers are using them to vibe-code at lightning speed, but these AI agents often hallucinate and confidently write vulnerable code—like hardcoding database keys or introducing massive SQL injections. If that code gets merged into a company's main branch, it's a disaster.

I built this tool to act as a strict, automated pipeline breaker. It scans incoming code, catches AI-generated vulnerabilities deterministically using an AST, and physically blocks the Git merge if the architecture violates security policies.

---

## 🛠️ The Tech Stack

I wanted to build something that could actually run in a real CI/CD environment without being painfully slow or expensive. Here is how I built it:

- **Python (AST)**: The core detection engine leverages Python's `ast` (Abstract Syntax Tree) module. Parsing the actual mathematical tree of the code is way faster and infinitely more accurate for finding architectural flaws than fragile regex.
- **LangGraph**: Orchestrates the multi-agent state machine. It cleanly routes the file data and risk payloads between different specialized agent "nodes".
- **Pydantic**: Enforces strict data validation and state schema definitions across the entire pipeline.
- **Rich**: Provides a beautiful, color-coded terminal interface with violation tables, risk gauges, and refactoring diffs.
- **Standard UNIX Exit Codes**: Uses `sys.exit(1)` to seamlessly communicate with the OS and physically block GitHub PRs or local commits.

---

## 🏗️ Quick Overview of the Architecture

The system is designed to be extremely fast and cost-effective. It's modeled as a **Directed Acyclic Graph (DAG)** with a single conditional back-edge for automated remediation.

Here is how the pipeline works:

1. **IngestorNode**: Automatically detects the context (e.g., figuring out if a file is a Python backend script or a React frontend file by checking for directives like `"use client"`).
2. **StaticAnalysisNode**: The AST parser walks the code tree to flag anti-patterns deterministically.
3. **ClassificationNode**: Evaluates the execution context and assigns a risk score based on violation severities.
4. **SynthesizerNode (Generative)**: An LLM-powered node that generates a refactored version of the code to resolve the detected violations. 
   *(Note: I intentionally mocked the LLM SynthesizerNode in this repository. Running live OpenAI/Anthropic API calls on every single CI/CD test run gets incredibly expensive. By mocking it, this entire pipeline runs locally in just 0.12 seconds!)*
5. **CriticNode**: Independently verifies the refactored code by re-running the deterministic static analysis. 
   - If the code passes, the pipeline succeeds.
   - If it fails, it loops back to the SynthesizerNode for a retry (capped at 2 retries).
   - If the critical risk threshold is met, the script intentionally crashes with an exit code 1 to kill the CI/CD job.

---

## 🚀 How to Run It Locally

You can test this right now on your machine. I've included an `examples/` folder with intentionally vulnerable code so you can see the pipeline catch the errors and block execution.

**1. Clone and Setup**
```bash
git clone https://github.com/rahulmp-dev/shadowguard-agent.git
cd shadowguard-agent
python -m venv .venv
```

**2. Activate the Virtual Environment**
```bash
# Windows:
.venv\Scripts\activate

# Mac/Linux:
source .venv/bin/activate
```

**3. Install Dependencies & Run**
```bash
pip install -e .
python shadowguard/main.py
```

*When you run this, you will see a red terminal output flagging the critical vulnerabilities in the example files, followed by a system-level pipeline block.*

---

*Built for learning, enterprise DevSecOps exploration, and keeping messy AI code out of production.*
