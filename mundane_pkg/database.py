"""SQLite database connection and management for mundane.

This module provides SQLite connection management, schema initialization,
and transaction helpers for tracking findings, review state, tool executions,
and artifacts.

Database location: ~/.mundane/mundane.db (global, cross-scan queries)
"""

from __future__ import annotations

import hashlib
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Generator, Optional

from .logging_setup import log_error, log_info


# ========== Database Configuration ==========

def get_database_path() -> Path:
    """Get path to mundane database file.

    Returns:
        Path to ~/.mundane/mundane.db
    """
    db_dir = Path.home() / ".mundane"
    db_dir.mkdir(parents=True, exist_ok=True)
    return db_dir / "mundane.db"


DATABASE_PATH = get_database_path()
"""Global database path for all scans."""


# ========== Schema ==========

SCHEMA_VERSION = 5
"""Current schema version for migrations.

Version history:
- 0: Initial schema (no version tracking)
- 1: Added plugin_output column to plugin_file_hosts
- 2: Removed file_path and severity_dir columns from plugin_files (database-only mode)
- 3: Added foundation tables (severity_levels, artifact_types, audit_log) and audit triggers
- 4: Normalized hosts and ports into separate tables (cross-scan tracking)
- 5: Removed redundant columns and created views for computed statistics
"""

SCHEMA_SQL = """
-- See schema.sql for full documentation

CREATE TABLE IF NOT EXISTS scans (
    scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_name TEXT NOT NULL UNIQUE,
    nessus_file_path TEXT,
    nessus_file_hash TEXT,
    export_root TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_reviewed_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_scans_name ON scans(scan_name);

CREATE TABLE IF NOT EXISTS plugins (
    plugin_id INTEGER PRIMARY KEY,
    plugin_name TEXT NOT NULL,
    severity_int INTEGER NOT NULL,
    has_metasploit BOOLEAN DEFAULT 0,
    cvss3_score REAL,
    cvss2_score REAL,
    metasploit_names TEXT,
    cves TEXT,
    plugin_url TEXT,
    metadata_fetched_at TIMESTAMP,
    CONSTRAINT severity_range CHECK (severity_int BETWEEN 0 AND 4),
    FOREIGN KEY (severity_int) REFERENCES severity_levels(severity_int)
);

CREATE INDEX IF NOT EXISTS idx_plugins_severity ON plugins(severity_int);
CREATE INDEX IF NOT EXISTS idx_plugins_metasploit ON plugins(has_metasploit);

CREATE TABLE IF NOT EXISTS plugin_files (
    file_id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    plugin_id INTEGER NOT NULL,
    review_state TEXT DEFAULT 'pending',
    reviewed_at TIMESTAMP,
    reviewed_by TEXT,
    review_notes TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE,
    FOREIGN KEY (plugin_id) REFERENCES plugins(plugin_id),
    CONSTRAINT valid_review_state CHECK (review_state IN ('pending', 'reviewed', 'completed', 'skipped')),
    CONSTRAINT unique_scan_plugin UNIQUE (scan_id, plugin_id)
);

CREATE INDEX IF NOT EXISTS idx_plugin_files_scan ON plugin_files(scan_id);
CREATE INDEX IF NOT EXISTS idx_plugin_files_plugin ON plugin_files(plugin_id);
CREATE INDEX IF NOT EXISTS idx_plugin_files_review_state ON plugin_files(review_state);

CREATE TABLE IF NOT EXISTS plugin_file_hosts (
    pfh_id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id INTEGER NOT NULL,
    host_id INTEGER NOT NULL,
    port_number INTEGER,
    plugin_output TEXT,
    FOREIGN KEY (file_id) REFERENCES plugin_files(file_id) ON DELETE CASCADE,
    FOREIGN KEY (host_id) REFERENCES hosts(host_id),
    FOREIGN KEY (port_number) REFERENCES ports(port_number),
    CONSTRAINT unique_file_host_port UNIQUE (file_id, host_id, port_number)
);

CREATE INDEX IF NOT EXISTS idx_pfh_file ON plugin_file_hosts(file_id);
CREATE INDEX IF NOT EXISTS idx_pfh_host ON plugin_file_hosts(host_id);
CREATE INDEX IF NOT EXISTS idx_pfh_port ON plugin_file_hosts(port_number);

CREATE TABLE IF NOT EXISTS sessions (
    session_id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    session_start TIMESTAMP NOT NULL,
    session_end TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_sessions_scan ON sessions(scan_id);

CREATE TABLE IF NOT EXISTS tool_executions (
    execution_id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER,
    file_id INTEGER,
    tool_name TEXT NOT NULL,
    tool_protocol TEXT,
    command_text TEXT NOT NULL,
    command_args TEXT,
    executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    exit_code INTEGER,
    duration_seconds REAL,
    host_count INTEGER,
    sampled BOOLEAN DEFAULT 0,
    ports TEXT,
    used_sudo BOOLEAN DEFAULT 0,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE SET NULL,
    FOREIGN KEY (file_id) REFERENCES plugin_files(file_id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_tool_executions_session ON tool_executions(session_id);
CREATE INDEX IF NOT EXISTS idx_tool_executions_file ON tool_executions(file_id);
CREATE INDEX IF NOT EXISTS idx_tool_executions_tool ON tool_executions(tool_name);

CREATE TABLE IF NOT EXISTS artifacts (
    artifact_id INTEGER PRIMARY KEY AUTOINCREMENT,
    execution_id INTEGER,
    artifact_path TEXT NOT NULL UNIQUE,
    artifact_type_id INTEGER,
    file_size_bytes INTEGER,
    file_hash TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_accessed_at TIMESTAMP,
    metadata TEXT,
    FOREIGN KEY (execution_id) REFERENCES tool_executions(execution_id) ON DELETE SET NULL,
    FOREIGN KEY (artifact_type_id) REFERENCES artifact_types(artifact_type_id)
);

CREATE INDEX IF NOT EXISTS idx_artifacts_execution ON artifacts(execution_id);
CREATE INDEX IF NOT EXISTS idx_artifacts_type ON artifacts(artifact_type_id);

CREATE TABLE IF NOT EXISTS workflow_executions (
    workflow_execution_id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id INTEGER,
    workflow_name TEXT NOT NULL,
    executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed BOOLEAN DEFAULT 0,
    results TEXT,
    FOREIGN KEY (file_id) REFERENCES plugin_files(file_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_workflow_executions_file ON workflow_executions(file_id);

-- Severity levels lookup table (normalized reference data)
CREATE TABLE IF NOT EXISTS severity_levels (
    severity_int INTEGER PRIMARY KEY,
    severity_label TEXT NOT NULL,
    severity_order INTEGER NOT NULL,
    color_hint TEXT,
    CONSTRAINT unique_severity_label UNIQUE (severity_label)
);

-- Artifact types lookup table (enforces consistency)
CREATE TABLE IF NOT EXISTS artifact_types (
    artifact_type_id INTEGER PRIMARY KEY AUTOINCREMENT,
    type_name TEXT NOT NULL UNIQUE,
    file_extension TEXT,
    description TEXT,
    parser_module TEXT
);

-- Audit log for tracking changes to critical tables
CREATE TABLE IF NOT EXISTS audit_log (
    audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
    table_name TEXT NOT NULL,
    record_id INTEGER NOT NULL,
    action TEXT CHECK(action IN ('INSERT', 'UPDATE', 'DELETE')),
    changed_by TEXT,
    changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    old_values TEXT,
    new_values TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_table_record ON audit_log(table_name, record_id);
CREATE INDEX IF NOT EXISTS idx_audit_changed_at ON audit_log(changed_at);

-- Hosts table (normalized host data across scans)
CREATE TABLE IF NOT EXISTS hosts (
    host_id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_address TEXT NOT NULL UNIQUE,
    host_type TEXT CHECK(host_type IN ('ipv4', 'ipv6', 'hostname')) NOT NULL,
    reverse_dns TEXT,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_hosts_address ON hosts(host_address);
CREATE INDEX IF NOT EXISTS idx_hosts_type ON hosts(host_type);

-- Ports table (port metadata)
CREATE TABLE IF NOT EXISTS ports (
    port_number INTEGER PRIMARY KEY CHECK(port_number BETWEEN 1 AND 65535),
    service_name TEXT,
    description TEXT
);

-- Schema version tracking
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ========== VIEWS (Computed Statistics) ==========
-- Note: These views are created by migration_005 and may not exist in earlier schema versions

-- Plugin file statistics (replaces host_count, port_count columns)
CREATE VIEW IF NOT EXISTS v_plugin_file_stats AS
SELECT
    pf.file_id,
    pf.scan_id,
    pf.plugin_id,
    pf.review_state,
    pf.reviewed_at,
    pf.reviewed_by,
    pf.review_notes,
    COUNT(DISTINCT pfh.host_id) as host_count,
    COUNT(DISTINCT pfh.port_number) as port_count
FROM plugin_files pf
LEFT JOIN plugin_file_hosts pfh ON pf.file_id = pfh.file_id
GROUP BY pf.file_id, pf.scan_id, pf.plugin_id, pf.review_state,
         pf.reviewed_at, pf.reviewed_by, pf.review_notes;

-- Session statistics (replaces aggregate columns in sessions table)
CREATE VIEW IF NOT EXISTS v_session_stats AS
SELECT
    s.session_id,
    s.scan_id,
    s.session_start,
    s.session_end,
    (julianday(s.session_end) - julianday(s.session_start)) * 86400 AS duration_seconds,
    COUNT(DISTINCT CASE WHEN pf.review_state = 'reviewed' THEN pf.file_id END) as files_reviewed,
    COUNT(DISTINCT CASE WHEN pf.review_state = 'completed' THEN pf.file_id END) as files_completed,
    COUNT(DISTINCT CASE WHEN pf.review_state = 'skipped' THEN pf.file_id END) as files_skipped,
    COUNT(DISTINCT te.execution_id) as tools_executed,
    COUNT(DISTINCT CASE WHEN p.cves IS NOT NULL THEN p.plugin_id END) as cves_extracted
FROM sessions s
LEFT JOIN plugin_files pf ON s.scan_id = pf.scan_id
    AND pf.reviewed_at >= s.session_start
    AND (s.session_end IS NULL OR pf.reviewed_at <= s.session_end)
LEFT JOIN tool_executions te ON s.session_id = te.session_id
LEFT JOIN plugins p ON pf.plugin_id = p.plugin_id
GROUP BY s.session_id, s.scan_id, s.session_start, s.session_end;

-- Plugins with severity labels (replaces severity_label column in plugins)
CREATE VIEW IF NOT EXISTS v_plugins_with_severity AS
SELECT
    p.plugin_id,
    p.plugin_name,
    p.severity_int,
    sl.severity_label,
    sl.color_hint,
    p.has_metasploit,
    p.cvss3_score,
    p.cvss2_score,
    p.cves,
    p.metasploit_names,
    p.plugin_url,
    p.metadata_fetched_at
FROM plugins p
JOIN severity_levels sl ON p.severity_int = sl.severity_int;

-- Host findings summary (cross-scan tracking - new capability)
CREATE VIEW IF NOT EXISTS v_host_findings AS
SELECT
    h.host_id,
    h.host_address,
    h.host_type,
    h.first_seen,
    h.last_seen,
    COUNT(DISTINCT pf.scan_id) as scan_count,
    COUNT(DISTINCT pf.file_id) as finding_count,
    COUNT(DISTINCT pfh.port_number) as port_count,
    MAX(p.severity_int) as max_severity
FROM hosts h
LEFT JOIN plugin_file_hosts pfh ON h.host_id = pfh.host_id
LEFT JOIN plugin_files pf ON pfh.file_id = pf.file_id
LEFT JOIN plugins p ON pf.plugin_id = p.plugin_id
GROUP BY h.host_id, h.host_address, h.host_type, h.first_seen, h.last_seen;

-- Artifacts with type information (replaces artifact_type column)
CREATE VIEW IF NOT EXISTS v_artifacts_with_types AS
SELECT
    a.artifact_id,
    a.execution_id,
    a.artifact_path,
    at.type_name as artifact_type,
    at.file_extension,
    at.description as artifact_description,
    a.file_size_bytes,
    a.file_hash,
    a.created_at,
    a.last_accessed_at,
    a.metadata
FROM artifacts a
LEFT JOIN artifact_types at ON a.artifact_type_id = at.artifact_type_id;
"""


# ========== Connection Management ==========

def get_connection(database_path: Optional[Path] = None) -> sqlite3.Connection:
    """Get SQLite connection with optimizations enabled.

    Args:
        database_path: Path to database file (default: DATABASE_PATH)

    Returns:
        SQLite connection with WAL mode and foreign keys enabled
    """
    db_path = database_path or DATABASE_PATH

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row  # Enable dict-like access

    # Enable optimizations
    conn.execute("PRAGMA journal_mode=WAL")  # Write-Ahead Logging
    conn.execute("PRAGMA foreign_keys=ON")   # Referential integrity
    conn.execute("PRAGMA synchronous=NORMAL")  # Performance
    conn.execute("PRAGMA temp_store=MEMORY")  # Temp tables in memory
    conn.execute("PRAGMA cache_size=-64000")  # 64MB cache

    return conn


@contextmanager
def db_transaction(
    conn: Optional[sqlite3.Connection] = None,
    database_path: Optional[Path] = None
) -> Generator[sqlite3.Connection, None, None]:
    """Context manager for database transactions with auto-commit/rollback.

    Args:
        conn: Existing connection (if None, creates new connection)
        database_path: Path to database (only used if conn is None)

    Yields:
        SQLite connection

    Example:
        with db_transaction() as conn:
            conn.execute("INSERT INTO scans ...")
            conn.execute("INSERT INTO plugin_files ...")
        # Auto-committed on success, rolled back on exception
    """
    if conn is None:
        conn = get_connection(database_path)
        close_on_exit = True
    else:
        close_on_exit = False

    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        log_error(f"Database transaction failed: {e}")
        raise
    finally:
        if close_on_exit:
            conn.close()


# ========== Schema Initialization ==========

def initialize_database(database_path: Optional[Path] = None) -> bool:
    """Initialize database schema and run migrations.

    This function creates the base schema using CREATE TABLE IF NOT EXISTS,
    then applies any pending migrations to bring existing databases up to date.

    Args:
        database_path: Path to database file (default: DATABASE_PATH)

    Returns:
        True if initialization succeeded, False otherwise
    """
    db_path = database_path or DATABASE_PATH

    try:
        # Execute base schema in its own transaction
        with db_transaction(database_path=db_path) as conn:
            # Execute base schema (CREATE TABLE IF NOT EXISTS)
            conn.executescript(SCHEMA_SQL)

        # Get current schema version in separate transaction
        with db_transaction(database_path=db_path) as conn:
            cursor = conn.execute("SELECT version FROM schema_version ORDER BY version DESC LIMIT 1")
            row = cursor.fetchone()
            current_version = row[0] if row else 0
            log_info(f"Current database schema version: {current_version}")

        # Run pending migrations
        from .migrations import get_all_migrations
        all_migrations = get_all_migrations()
        pending_migrations = [m for m in all_migrations if m.version > current_version]

        if pending_migrations:
            log_info(f"Running {len(pending_migrations)} pending database migration(s)...")
            for migration in pending_migrations:
                log_info(f"  Applying migration {migration.version}: {migration.description}")

                # Run each migration in its own transaction
                # This prevents one failed migration from rolling back previous successful migrations
                try:
                    with db_transaction(database_path=db_path) as conn:
                        migration.upgrade(conn)

                        # Record migration as applied
                        conn.execute(
                            "INSERT OR REPLACE INTO schema_version (version) VALUES (?)",
                            (migration.version,)
                        )

                    log_info(f"  [OK] Migration {migration.version} completed successfully")

                except Exception as migration_error:
                    log_error(f"  [FAILED] Migration {migration.version} failed: {migration_error}")
                    log_error(f"  Stopping at migration {migration.version}. Previous migrations were applied successfully.")
                    log_error(f"  Current schema version: {migration.version - 1}")
                    return False

            final_version = pending_migrations[-1].version
            log_info(f"Database schema updated to version {final_version}")
        else:
            # No pending migrations - ensure version is recorded
            if current_version == 0:
                with db_transaction(database_path=db_path) as conn:
                    # Fresh database with no migrations to run - set to SCHEMA_VERSION
                    conn.execute(
                        "INSERT OR REPLACE INTO schema_version (version) VALUES (?)",
                        (SCHEMA_VERSION,)
                    )
                log_info(f"Database schema initialized (version {SCHEMA_VERSION})")
            else:
                log_info(f"Database schema is up to date (version {current_version})")

        return True

    except Exception as e:
        log_error(f"Failed to initialize database: {e}")
        return False


# ========== Utility Functions ==========

def compute_file_hash(file_path: Path) -> str:
    """Compute SHA256 hash of a file.

    Args:
        file_path: Path to file

    Returns:
        Hexadecimal SHA256 hash string
    """
    sha256 = hashlib.sha256()

    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            sha256.update(chunk)

    return sha256.hexdigest()


def query_one(
    conn: sqlite3.Connection,
    query: str,
    params: tuple[Any, ...] = ()
) -> Optional[sqlite3.Row]:
    """Execute query and return single row.

    Args:
        conn: Database connection
        query: SQL query
        params: Query parameters

    Returns:
        Single row or None if no results
    """
    cursor = conn.execute(query, params)
    return cursor.fetchone()


def query_all(
    conn: sqlite3.Connection,
    query: str,
    params: tuple[Any, ...] = ()
) -> list[sqlite3.Row]:
    """Execute query and return all rows.

    Args:
        conn: Database connection
        query: SQL query
        params: Query parameters

    Returns:
        List of rows
    """
    cursor = conn.execute(query, params)
    return cursor.fetchall()


# ========== Database Health Checks ==========

def check_database_health(database_path: Optional[Path] = None) -> bool:
    """Check database integrity and connectivity.

    Args:
        database_path: Path to database file (default: DATABASE_PATH)

    Returns:
        True if database is healthy, False otherwise
    """
    db_path = database_path or DATABASE_PATH

    try:
        with db_transaction(database_path=db_path) as conn:
            # Check integrity
            cursor = conn.execute("PRAGMA integrity_check")
            result = cursor.fetchone()

            if result and result[0] != "ok":
                log_error(f"Database integrity check failed: {result[0]}")
                return False

            # Check tables exist
            cursor = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='scans'"
            )
            if not cursor.fetchone():
                log_error("Database health check failed: missing required 'scans' table")
                log_error("This is non-fatal - initialization will attempt to repair the schema")
                return False

        return True

    except Exception as e:
        log_error(f"Database health check failed: {e}")
        return False


# ========== Auto-initialization ==========

# Initialize/update database on module import (handles both new and existing databases)
if DATABASE_PATH.exists():
    # Existing database - run health check, then initialize/update
    # Health check is informational only - initialization is idempotent and will repair issues
    if not check_database_health():
        log_error(f"Database at {DATABASE_PATH} failed health check - attempting repair...")

    # Always run initialization (idempotent - safe to run multiple times)
    initialize_database()  # Will run pending migrations if needed
else:
    # New database - create and initialize
    log_info(f"Creating new database at {DATABASE_PATH}")
    initialize_database()
