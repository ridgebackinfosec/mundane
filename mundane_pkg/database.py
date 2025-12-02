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

SCHEMA_VERSION = 1
"""Current schema version for migrations."""

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
    severity_label TEXT NOT NULL,
    has_metasploit BOOLEAN DEFAULT 0,
    cvss3_score REAL,
    cvss2_score REAL,
    metasploit_names TEXT,
    cves TEXT,
    plugin_url TEXT,
    metadata_fetched_at TIMESTAMP,
    CONSTRAINT severity_range CHECK (severity_int BETWEEN 0 AND 4)
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
    host_count INTEGER DEFAULT 0,
    port_count INTEGER DEFAULT 0,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE,
    FOREIGN KEY (plugin_id) REFERENCES plugins(plugin_id),
    CONSTRAINT valid_review_state CHECK (review_state IN ('pending', 'reviewed', 'completed', 'skipped')),
    CONSTRAINT unique_scan_plugin UNIQUE (scan_id, plugin_id)
);

CREATE INDEX IF NOT EXISTS idx_plugin_files_scan ON plugin_files(scan_id);
CREATE INDEX IF NOT EXISTS idx_plugin_files_plugin ON plugin_files(plugin_id);
CREATE INDEX IF NOT EXISTS idx_plugin_files_review_state ON plugin_files(review_state);

CREATE TABLE IF NOT EXISTS plugin_file_hosts (
    host_id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id INTEGER NOT NULL,
    host TEXT NOT NULL,
    port INTEGER,
    is_ipv4 BOOLEAN DEFAULT 0,
    is_ipv6 BOOLEAN DEFAULT 0,
    FOREIGN KEY (file_id) REFERENCES plugin_files(file_id) ON DELETE CASCADE,
    CONSTRAINT unique_file_host_port UNIQUE (file_id, host, port)
);

CREATE INDEX IF NOT EXISTS idx_plugin_file_hosts_file ON plugin_file_hosts(file_id);
CREATE INDEX IF NOT EXISTS idx_plugin_file_hosts_host ON plugin_file_hosts(host);

CREATE TABLE IF NOT EXISTS sessions (
    session_id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    session_start TIMESTAMP NOT NULL,
    session_end TIMESTAMP,
    duration_seconds INTEGER,
    files_reviewed INTEGER DEFAULT 0,
    files_completed INTEGER DEFAULT 0,
    files_skipped INTEGER DEFAULT 0,
    tools_executed INTEGER DEFAULT 0,
    cves_extracted INTEGER DEFAULT 0,
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
    artifact_type TEXT NOT NULL,
    file_size_bytes INTEGER,
    file_hash TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_accessed_at TIMESTAMP,
    metadata TEXT,
    FOREIGN KEY (execution_id) REFERENCES tool_executions(execution_id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_artifacts_execution ON artifacts(execution_id);
CREATE INDEX IF NOT EXISTS idx_artifacts_type ON artifacts(artifact_type);

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

-- Schema version tracking
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
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
    """Initialize database schema if not exists.

    Args:
        database_path: Path to database file (default: DATABASE_PATH)

    Returns:
        True if initialization succeeded, False otherwise
    """
    db_path = database_path or DATABASE_PATH

    try:
        with db_transaction(database_path=db_path) as conn:
            # Execute schema
            conn.executescript(SCHEMA_SQL)

            # Check/update schema version
            cursor = conn.execute("SELECT version FROM schema_version ORDER BY version DESC LIMIT 1")
            row = cursor.fetchone()
            current_version = row[0] if row else 0

            if current_version < SCHEMA_VERSION:
                conn.execute(
                    "INSERT OR REPLACE INTO schema_version (version) VALUES (?)",
                    (SCHEMA_VERSION,)
                )
                log_info(f"Database schema initialized (version {SCHEMA_VERSION})")

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
                log_error("Database missing required tables")
                return False

        return True

    except Exception as e:
        log_error(f"Database health check failed: {e}")
        return False


# ========== Auto-initialization ==========

# Initialize database on module import if it doesn't exist
if not DATABASE_PATH.exists():
    log_info(f"Creating new database at {DATABASE_PATH}")
    initialize_database()
elif not check_database_health():
    log_error(f"Database at {DATABASE_PATH} failed health check")
