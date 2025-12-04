# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## General Development Principles

**IMPORTANT**: Always adhere to Python development and architecture best practices when working on this project.

This includes:

- **Code Quality**: Follow PEP 8 style guidelines, use type hints for function signatures, clear and descriptive naming conventions, and proper docstrings for modules, classes, and functions
- **Architecture**: Apply SOLID principles (Single Responsibility, Open/Closed, Liskov Substitution, Interface Segregation, Dependency Inversion), maintain separation of concerns, follow DRY (Don't Repeat Yourself), and use dependency injection and loose coupling
- **Testing**: Write unit tests for isolated logic, integration tests for database/filesystem operations, use parametrized tests for multiple input variations, and maintain high coverage on critical paths
- **Error Handling**: Use specific exception types, proper context managers for resources, and graceful degradation where appropriate
- **Performance**: Write efficient database queries, implement caching where beneficial, and avoid N+1 query patterns
- **Security**: Validate all inputs, use parameterized queries to prevent SQL injection, and prevent command injection vulnerabilities
- **Documentation**: Always update relevant documentation alongside code changes to keep everything synchronized and up-to-date automatically. This includes docstrings, CLAUDE.md, README.md, and any other relevant documentation files
- **Smoke Testing**: After completing ANY changes (code, documentation, configuration), ALWAYS provide a concise smoke test summary with manual testing steps the user can perform to verify the changes work correctly. Include specific commands, expected outputs, and edge cases to validate
- **Git Commit Messages**: After completing ANY changes, ALWAYS provide a concise one-line git commit message that accurately describes the change following conventional commit format (e.g., "feat: add user authentication", "fix: resolve parsing edge case", "docs: update installation guide", "refactor: extract validation logic"). Keep messages under 72 characters when possible

## Project Overview

**Mundane** is a Python CLI tool for reviewing Nessus vulnerability scan findings and orchestrating security tools (nmap, NetExec, Metasploit). It features a Rich-based TUI for interactive review, SQLite-backed persistence, and session state tracking.

**Core workflow**: Import `.nessus` files → Review findings in TUI → Run security tools → Track progress in database

**Target Python**: 3.11+ (3.8+ may work but not the target)

## Build & Development Commands

### Setup Development Environment

```bash
# Install package in editable mode with dev dependencies
pip install -e ".[dev]"

# Or install from requirements (production dependencies only)
pip install -r requirements.txt
```

### Running the Application

```bash
# Direct execution (development)
python mundane.py --help

# Installed command (after pip install)
mundane --help

# Common commands
mundane import scan.nessus          # Import Nessus scan
mundane review                      # Start interactive review
mundane list                        # List all scans
mundane delete-scan <scan_name>     # Delete scan from database
```

### Testing

```bash
# Run all tests with coverage
pytest

# Run with verbose coverage report
pytest --cov=mundane_pkg --cov-report=term-missing --cov-report=html

# Run specific test file
pytest tests/test_parsing.py

# Run by marker
pytest -m unit                      # Fast unit tests only
pytest -m integration               # Integration tests (DB, filesystem)
pytest -m "not slow"                # Skip slow tests

# Run specific test
pytest tests/test_parsing.py::TestSplitHostPort::test_ipv4_with_port

# Show test durations (find slow tests)
pytest --durations=10
```

**Coverage goals**: 85% overall, 90%+ for critical modules (database.py, models.py, parsing.py, nessus_import.py)

### Linting & Formatting

```bash
# Format code with black
black mundane.py mundane_pkg/ tests/

# Type checking with mypy
mypy mundane_pkg/
```

## Architecture

### Database-Only Design (v1.9.0+)

Mundane uses a **database-first architecture** with SQLite as the source of truth:

- **Location**: `~/.mundane/mundane.db` (global, cross-scan)
- **Schema version**: Tracked in `database.py:SCHEMA_VERSION` (current: 2)
- **Migrations**: `mundane_pkg/migrations/migration_XXX_*.py`
- `.txt` files are **reference only** - all data lives in database

**Key design principles**:
- Database is source of truth for review state, host:port data, session state
- File browsing queries database directly (no filesystem walks during review)
- Review state tracked in `plugin_files.review_state` column, synchronized to filename prefixes
- CVEs cached in `plugins.cves` JSON column after fetching from Tenable

### Module Structure

```
mundane.py                  # Main entry point (Typer CLI commands)
mundane_pkg/
  ├── database.py          # SQLite connection, schema, transactions
  ├── models.py            # ORM models (Scan, Plugin, PluginFile, Session, ToolExecution, Artifact)
  ├── nessus_import.py     # .nessus XML parsing and database import
  ├── parsing.py           # Host:port parsing (canonical parser, ParsedHostsPorts model)
  ├── analysis.py          # Cross-file comparison, superset analysis
  ├── session.py           # Review session state management
  ├── tools.py             # Tool execution (nmap, netexec, custom commands)
  ├── tool_registry.py     # ToolSpec registry pattern
  ├── render.py            # Rich UI rendering (tables, menus, pagination)
  ├── fs.py                # Filesystem operations (deprecated, DB-first now)
  ├── ops.py               # Command execution, sudo handling
  ├── workflow_mapper.py   # YAML workflow configuration
  ├── config.py            # YAML config file management
  ├── constants.py         # Global constants (paths, severities, NSE profiles)
  ├── ansi.py              # ANSI color helpers
  ├── logging_setup.py     # Loguru setup with rotation
  └── _version.py          # Version resolution (importlib.metadata → pyproject.toml)
```

### Core Data Flow

1. **Import**: `.nessus` XML → `nessus_import.py` → SQLite (`scans`, `plugins`, `plugin_files`, `plugin_file_hosts`)
2. **Review**: Database query → `render.py` tables → User actions → Update `review_state` column
3. **Tools**: TUI menu → `tools.py` → Execute command → `tool_executions` + `artifacts` tables
4. **Session**: Auto-save to `sessions` table (start time, duration, statistics)

### Parsing Architecture

**Canonical parser**: `parsing.py:parse_hosts_ports()` returns `ParsedHostsPorts` model:
- Stable host order (original order preserved)
- Unique, sorted ports
- Explicit `host:port` detection (IPv4, IPv6 with brackets)
- In-process LRU cache for performance

**Usage**: All host:port parsing must use `parse_hosts_ports()` to ensure consistency.

### Tool Registry Pattern

`tool_registry.py` defines `ToolSpec` with `builder: Callable[[dict], tuple[Any, dict]]`:
- Entries for `nmap`, `netexec`, legacy builders
- Decouples tool definitions from execution logic
- Enables adding new tools without modifying core code

### Database Schema

**Tables**:
- `scans`: Top-level scan metadata (scan_name, export_root, .nessus hash)
- `plugins`: Plugin metadata (plugin_id, severity, CVSS, CVEs, Metasploit modules)
- `plugin_files`: Findings per scan (scan_id + plugin_id, review_state, host_count, port_count)
- `plugin_file_hosts`: Host:port combinations (file_id, host, port, plugin_output)
- `sessions`: Review session tracking (start time, duration, statistics)
- `tool_executions`: Command history (tool_name, command_text, exit_code, duration, sudo usage)
- `artifacts`: Generated files (artifact_path, file_hash, file_size, metadata JSON)

**Views**: `v_review_progress`, `v_session_stats`, `v_tool_summary`, `v_artifact_storage`

**Schema changes**: Update `database.py:SCHEMA_SQL` AND create migration in `migrations/`

### Version Management

Version is defined in `pyproject.toml:project.version` (single source of truth).

`_version.py` resolves version with fallback chain:
1. `importlib.metadata.version("mundane")` (installed package)
2. Parse `pyproject.toml` (development mode)
3. "unknown" (fallback)

**When bumping version**: Update `pyproject.toml` only. Do NOT hardcode version elsewhere.

### Constants & Configuration

**Environment variables** (checked in `constants.py`):
- `MUNDANE_RESULTS_ROOT`: Artifact storage (default: `~/.mundane/artifacts`)
- `MUNDANE_USE_DB`: Enable database (default: `1`, always enabled)
- `MUNDANE_DB_ONLY`: Database-only mode (default: `1`, always enabled)
- `MUNDANE_LOG`: Log file path (default: `~/.mundane/mundane.log`)
- `MUNDANE_DEBUG`: Enable DEBUG logging (`1`, `true`, `on`)
- `MUNDANE_PROMPT`: Enable confirmation prompts (default: on)
- `MUNDANE_SUDO_PREFLIGHT`: Run sudo checks (default: on)

**Config file** (`~/.mundane/config.yaml`): Optional user preferences (paths, page sizes, defaults). CLI commands: `config-init`, `config-show`, `config-get`, `config-set`.

**NSE profiles** (`constants.py:NSE_PROFILES`): Pre-configured nmap script sets (SMB, SSL, HTTP, etc.)

### Workflow Mappings

`workflow_mappings.yaml`: Maps plugin IDs → verification workflows (YAML format).

**CLI options**:
- `--custom-workflows PATH`: Supplement bundled workflows (custom overrides on conflict)
- `--custom-workflows-only PATH`: Replace bundled workflows entirely

**Workflow features**:
- Multi-plugin workflows (comma-separated plugin IDs)
- Display-only (commands, notes, references)
- Press `[W]` in TUI to view workflow for current plugin

### Logging

**Backend**: Prefers loguru with rotation (1 MB, 7 days retention), falls back to stdlib logging.

**Decorators**: `@log_timing` logs execution duration at DEBUG level.

**Global exception hook**: Logs unhandled exceptions (Rich still shows pretty tracebacks).

**Shims**: `_log_info()`, `_log_debug()`, `_log_error()` keep code backend-agnostic.

## Development Patterns

### Data vs Render Separation

**Pattern**: Compute pure data first, then render with Rich.

**Example**: `analysis.py:build_compare_data()` returns data dict → `render_compare_table()` creates Rich table.

**Why**: Enables testing business logic without Rich rendering, keeps functions focused.

### Severity Handling

**Centralized helpers**:
- `_severity_color_name(severity_int: int) -> str`: Returns Rich color name
- `colorize_severity_label(label: str, severity_int: int) -> str`: ANSI-colored label
- `severity_style(severity_int: int) -> Style`: Rich Style object
- `pretty_severity_label(severity_int: int) -> str`: Formatted Rich text

**Mapping**: `0=Info, 1=Low, 2=Medium, 3=High, 4=Critical`

### Review State Management

**States**: `pending`, `reviewed`, `completed`, `skipped`

**Database-first**: Update `plugin_files.review_state` column → Sync to filename prefix (`[R]`, `[X]`, `[S]`).

**Reversible**: Press `[U]` to undo review-complete (multi-select support).

### Session Persistence

**Auto-save**: Review progress saved to `sessions` table (no `.mundane_session.json` files in DB-only mode).

**Resume prompt**: On startup, shows session details (reviewed/completed/skipped counts, session start time).

**Cleanup**: Auto-delete session after successful completion.

## Testing Practices

### Fixture Usage

**Database**: Use `temp_db` fixture (in-memory SQLite, schema initialized) for integration tests.

**Filesystem**: Use `temp_dir`, `sample_scan_dir`, `sample_plugin_file` fixtures (auto-cleanup).

**Nessus data**: Use `minimal_nessus_fixture` (3 plugins, 3 hosts) for fast tests, `goad_nessus_fixture` (74 plugins, 755 hosts) for slow tests.

### Test Markers

- `@pytest.mark.unit`: Fast, isolated (< 0.1s each)
- `@pytest.mark.integration`: DB or filesystem (< 1s each)
- `@pytest.mark.slow`: Large file processing (mark as slow)

### Parametrized Tests

Use `@pytest.mark.parametrize` for testing multiple input variations:

```python
@pytest.mark.parametrize("input_str,expected_host,expected_port", [
    ("192.168.1.1:80", "192.168.1.1", 80),
    ("[::1]:8080", "::1", 8080),
])
def test_split_host_port(input_str, expected_host, expected_port):
    host, port = split_host_port(input_str)
    assert host == expected_host
    assert port == expected_port
```

### Coverage Practices

- Run `pytest --cov-report=html` to identify untested branches
- Exclude boilerplate with `# pragma: no cover` sparingly
- Focus coverage on critical paths (DB ops, parsing, import)

## Common Tasks

### Adding a New Command

1. Add Typer command in `mundane.py` (use `@app.command()` decorator)
2. Import required functions from `mundane_pkg`
3. Add docstring for `--help` output
4. Test manually: `python mundane.py <command> --help`

### Adding a New Database Column

1. Update `database.py:SCHEMA_SQL` with new column
2. Update `schema.sql` (documentation reference)
3. Create migration in `mundane_pkg/migrations/migration_XXX_<name>.py`
4. Increment `database.py:SCHEMA_VERSION`
5. Update `models.py` dataclass if applicable
6. Test migration with `pytest tests/test_database.py`

### Adding a New Tool

1. Add tool spec to `tool_registry.py:TOOL_REGISTRY`
2. Implement builder function: `def build_<tool>_cmd(ctx: dict) -> tuple[Any, dict]`
3. Add tool-specific constants to `constants.py` if needed
4. Update `tools.py` to handle tool-specific prompts
5. Test in TUI: `mundane review` → Run tool → Verify command generation

### Updating Workflow Mappings

1. Edit `mundane_pkg/workflow_mappings.yaml` (or create custom YAML)
2. Follow schema: `version`, `workflows` list, each with `plugin_id`, `workflow_name`, `description`, `steps`, `references`
3. Test in TUI: `mundane review --custom-workflows <path>` → Press `[W]` on matching plugin

### Debugging Database Issues

```bash
# Enable DEBUG logging
export MUNDANE_DEBUG=1
mundane review
tail -f ~/.mundane/mundane.log

# Inspect database directly
sqlite3 ~/.mundane/mundane.db
sqlite> .schema
sqlite> SELECT * FROM scans;
sqlite> SELECT * FROM v_review_progress;
```

## Important Notes

- **Database migrations**: ALWAYS test migrations with existing database before release
- **Version bumps**: Update `pyproject.toml` version, create git tag, push tag for release workflow
- **Breaking changes**: Document in README "Database-Only Architecture" section if schema changes
- **Backward compatibility**: `.txt` files still created for human reference, but database is source of truth
- **CI/CD**: GitHub Actions runs tests on Python 3.11/3.12, Ubuntu/Windows/macOS (see `.github/workflows/test.yml`)
- **Dependencies**: Keep `requirements.txt` and `pyproject.toml:dependencies` in sync
- **Nessus XML parsing**: Based on DefensiveOrigins/NessusPluginHosts (respect attribution)
