"""Migration 001: Add plugin_output column to plugin_file_hosts table.

This migration adds support for storing Nessus plugin output data per host.
"""

import sqlite3
from . import Migration


class Migration001(Migration):
    """Add plugin_output column to plugin_file_hosts."""

    @property
    def version(self) -> int:
        return 1

    @property
    def description(self) -> str:
        return "Add plugin_output column to plugin_file_hosts table"

    def upgrade(self, conn: sqlite3.Connection) -> None:
        """Add plugin_output column if it doesn't exist."""
        # Check if column exists
        cursor = conn.execute("PRAGMA table_info(plugin_file_hosts)")
        columns = [row[1] for row in cursor.fetchall()]

        if "plugin_output" not in columns:
            conn.execute(
                "ALTER TABLE plugin_file_hosts ADD COLUMN plugin_output TEXT"
            )
            print("  [OK] Added plugin_output column to plugin_file_hosts")
        else:
            print("  [OK] plugin_output column already exists")
