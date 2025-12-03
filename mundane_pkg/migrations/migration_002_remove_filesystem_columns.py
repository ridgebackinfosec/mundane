"""Migration 002: Remove file_path and severity_dir columns from plugin_files table.

These columns were filesystem-oriented and are no longer needed in database-only mode.
"""

import sqlite3
from . import Migration


class Migration002(Migration):
    """Remove file_path and severity_dir columns from plugin_files."""

    @property
    def version(self) -> int:
        return 2

    @property
    def description(self) -> str:
        return "Remove file_path and severity_dir columns from plugin_files table"

    def upgrade(self, conn: sqlite3.Connection) -> None:
        """Remove file_path and severity_dir columns if they exist."""
        # Check current columns
        cursor = conn.execute("PRAGMA table_info(plugin_files)")
        columns = [row[1] for row in cursor.fetchall()]

        if "file_path" not in columns and "severity_dir" not in columns:
            print("  [OK] Columns already removed")
            return

        # SQLite doesn't support DROP COLUMN directly (before 3.35.0)
        # Must recreate table without those columns
        print("  [OK] Recreating plugin_files table without filesystem columns...")

        # Create new table with desired schema
        conn.execute("""
            CREATE TABLE plugin_files_new (
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
            )
        """)

        # Copy data (omitting file_path and severity_dir)
        conn.execute("""
            INSERT INTO plugin_files_new (
                file_id, scan_id, plugin_id, review_state,
                reviewed_at, reviewed_by, review_notes,
                host_count, port_count
            )
            SELECT
                file_id, scan_id, plugin_id, review_state,
                reviewed_at, reviewed_by, review_notes,
                host_count, port_count
            FROM plugin_files
        """)

        # Drop old table
        conn.execute("DROP TABLE plugin_files")

        # Rename new table
        conn.execute("ALTER TABLE plugin_files_new RENAME TO plugin_files")

        # Recreate indexes
        conn.execute("CREATE INDEX IF NOT EXISTS idx_plugin_files_scan ON plugin_files(scan_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_plugin_files_plugin ON plugin_files(plugin_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_plugin_files_review_state ON plugin_files(review_state)")

        print("  [OK] Removed file_path and severity_dir columns")
