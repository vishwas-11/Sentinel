# Sentinel Backend

Sentinel is a continuous red-teaming and security-regression testing engine for LLM applications.

## Prerequisites

- Python 3.12+
- `uv` (recommended) or `pip`

## Quick Start (with `uv`)

1. Create a virtual environment:
   ```bash
   uv venv .venv
   ```

2. Activate the virtual environment:
   - **Windows (PowerShell)**:
     ```powershell
     .\.venv\Scripts\Activate.ps1
     ```
   - **Linux / macOS**:
     ```bash
     source .venv/bin/activate
     ```

3. Install dependencies in editable mode:
   ```bash
   uv pip install -e .[dev]
   ```

4. Run tests:
   ```bash
   uv run pytest
   ```

## Architecture

See shared project documentation in `../docs/` for overall requirements and ADRs.
Backend structure follows domain-first layering:
- `app/core/`: Configuration, logging, lifecycle utilities.
- `app/domain/`: Pure domain protocols and contracts (attacks, evaluation, scoring, gates).
- `app/infrastructure/`: Concrete adapters (REST targets, LLM providers, persistence).
- `app/api/`: Presentation layer (FastAPI endpoints).
