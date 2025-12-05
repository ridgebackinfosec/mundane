"""Migration 003: Add foundation lookup tables (severity_levels, artifact_types, audit_log).

This migration adds normalized lookup tables that improve database design:
- severity_levels: Normalize severity metadata (removes duplication from plugins table)
- artifact_types: Enforce artifact type consistency
- audit_log: Track changes to critical tables

These tables are created alongside existing columns (dual-write pattern) to maintain
backward compatibility during the migration process.

IMPORTANT: This migration is idempotent - it checks both table existence AND population
to handle the case where SCHEMA_SQL creates empty tables before migrations run.
"""

import sqlite3
from . import Migration


class Migration003(Migration):
    """Add foundation lookup tables for better normalization."""

    @property
    def version(self) -> int:
        return 3

    @property
    def description(self) -> str:
        return "Add severity_levels, artifact_types, and audit_log tables"

    def upgrade(self, conn: sqlite3.Connection) -> None:
        """Create foundation lookup tables and populate with initial data.

        This migration is idempotent - it can be safely run multiple times.
        It checks both table existence AND population to handle the case where
        SCHEMA_SQL creates empty tables before migrations run.
        """

        # ========== Severity Levels Table ==========

        # Check if severity_levels table exists
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='severity_levels'"
        )
        severity_table_exists = cursor.fetchone() is not None

        if not severity_table_exists:
            print("  [OK] Creating severity_levels table...")
            conn.execute("""
                CREATE TABLE severity_levels (
                    severity_int INTEGER PRIMARY KEY,
                    severity_label TEXT NOT NULL,
                    severity_order INTEGER NOT NULL,
                    color_hint TEXT,
                    CONSTRAINT unique_severity_label UNIQUE (severity_label)
                )
            """)
            print("  [OK] Created severity_levels table")

        # Check if table is populated (idempotent check)
        cursor = conn.execute("SELECT COUNT(*) FROM severity_levels")
        row_count = cursor.fetchone()[0]

        if row_count == 0:
            print("  [OK] Populating severity_levels table...")
            conn.executemany(
                "INSERT INTO severity_levels (severity_int, severity_label, severity_order, color_hint) VALUES (?, ?, ?, ?)",
                [
                    (4, 'Critical', 4, '#8B0000'),
                    (3, 'High', 3, '#FF4500'),
                    (2, 'Medium', 2, '#FFA500'),
                    (1, 'Low', 1, '#FFD700'),
                    (0, 'Info', 0, '#4682B4'),
                ]
            )
            print("  [OK] Populated severity_levels table with 5 severity levels")
        else:
            print(f"  [OK] severity_levels table already populated ({row_count} rows)")

        # ========== Artifact Types Table ==========

        # Check if artifact_types table exists
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='artifact_types'"
        )
        artifact_table_exists = cursor.fetchone() is not None

        if not artifact_table_exists:
            print("  [OK] Creating artifact_types table...")
            conn.execute("""
                CREATE TABLE artifact_types (
                    artifact_type_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    type_name TEXT NOT NULL UNIQUE,
                    file_extension TEXT,
                    description TEXT,
                    parser_module TEXT
                )
            """)
            print("  [OK] Created artifact_types table")

        # Check if table is populated (idempotent check)
        cursor = conn.execute("SELECT COUNT(*) FROM artifact_types")
        row_count = cursor.fetchone()[0]

        if row_count == 0:
            print("  [OK] Populating artifact_types table...")
            conn.executemany(
                "INSERT INTO artifact_types (type_name, file_extension, description) VALUES (?, ?, ?)",
                [
                    ('nmap_xml', '.xml', 'Nmap XML output'),
                    ('nmap_gnmap', '.gnmap', 'Nmap greppable output'),
                    ('nmap_txt', '.txt', 'Nmap text output'),
                    ('netexec_txt', '.txt', 'NetExec text output'),
                    ('log', '.log', 'Tool execution log'),
                ]
            )
            print("  [OK] Populated artifact_types table with 5 artifact types")
        else:
            print(f"  [OK] artifact_types table already populated ({row_count} rows)")

        # ========== Audit Log Table ==========

        # Check if audit_log table exists
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='audit_log'"
        )
        audit_table_exists = cursor.fetchone() is not None

        if not audit_table_exists:
            print("  [OK] Creating audit_log table...")
            conn.execute("""
                CREATE TABLE audit_log (
                    audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    table_name TEXT NOT NULL,
                    record_id INTEGER NOT NULL,
                    action TEXT CHECK(action IN ('INSERT', 'UPDATE', 'DELETE')),
                    changed_by TEXT,
                    changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    old_values TEXT,
                    new_values TEXT
                )
            """)

            # Create indexes for efficient querying
            conn.execute("CREATE INDEX idx_audit_table_record ON audit_log(table_name, record_id)")
            conn.execute("CREATE INDEX idx_audit_changed_at ON audit_log(changed_at)")
            print("  [OK] Created audit_log table with indexes")
        else:
            # Ensure indexes exist (idempotent check)
            cursor = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index' AND name='idx_audit_table_record'"
            )
            if not cursor.fetchone():
                conn.execute("CREATE INDEX idx_audit_table_record ON audit_log(table_name, record_id)")
                print("  [OK] Created missing index idx_audit_table_record")

            cursor = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index' AND name='idx_audit_changed_at'"
            )
            if not cursor.fetchone():
                conn.execute("CREATE INDEX idx_audit_changed_at ON audit_log(changed_at)")
                print("  [OK] Created missing index idx_audit_changed_at")

            print("  [OK] audit_log table already exists")

        # ========== Audit Triggers ==========

        print("  [OK] Creating audit triggers...")

        # Check if trigger exists for plugin_files
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='trigger' AND name='audit_plugin_files_review_update'"
        )
        if not cursor.fetchone():
            conn.execute("""
                CREATE TRIGGER audit_plugin_files_review_update
                AFTER UPDATE OF review_state, reviewed_at ON plugin_files
                FOR EACH ROW
                WHEN OLD.review_state != NEW.review_state OR OLD.reviewed_at != NEW.reviewed_at
                BEGIN
                    INSERT INTO audit_log (table_name, record_id, action, old_values, new_values)
                    VALUES (
                        'plugin_files',
                        NEW.file_id,
                        'UPDATE',
                        json_object('review_state', OLD.review_state, 'reviewed_at', OLD.reviewed_at),
                        json_object('review_state', NEW.review_state, 'reviewed_at', NEW.reviewed_at)
                    );
                END
            """)
            print("  [OK] Created audit trigger for plugin_files review updates")
        else:
            print("  [OK] Audit trigger for plugin_files already exists")

        # Check if trigger exists for sessions
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='trigger' AND name='audit_sessions_insert'"
        )
        if not cursor.fetchone():
            conn.execute("""
                CREATE TRIGGER audit_sessions_insert
                AFTER INSERT ON sessions
                FOR EACH ROW
                BEGIN
                    INSERT INTO audit_log (table_name, record_id, action, new_values)
                    VALUES (
                        'sessions',
                        NEW.session_id,
                        'INSERT',
                        json_object('scan_id', NEW.scan_id, 'session_start', NEW.session_start)
                    );
                END
            """)
            print("  [OK] Created audit trigger for sessions inserts")
        else:
            print("  [OK] Audit trigger for sessions already exists")

        print("  [OK] Migration 003 completed successfully")

    def downgrade(self, conn: sqlite3.Connection) -> None:
        """Rollback migration by dropping foundation tables.

        This is safe as these tables are new and don't have dependencies yet.
        """
        print("  [OK] Rolling back migration 003...")

        # Drop triggers first
        conn.execute("DROP TRIGGER IF EXISTS audit_plugin_files_review_update")
        conn.execute("DROP TRIGGER IF EXISTS audit_sessions_insert")
        print("  [OK] Dropped audit triggers")

        # Drop tables (in reverse order of creation)
        conn.execute("DROP TABLE IF EXISTS audit_log")
        conn.execute("DROP TABLE IF EXISTS artifact_types")
        conn.execute("DROP TABLE IF EXISTS severity_levels")
        print("  [OK] Dropped foundation tables")

        print("  [OK] Migration 003 rollback completed")
