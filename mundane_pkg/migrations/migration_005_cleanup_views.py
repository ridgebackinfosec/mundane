"""Migration 005: Remove redundant columns and create views for computed statistics.

This migration normalizes the database schema by:
1. Removing redundant/derived columns from plugin_files, plugins, sessions, artifacts
2. Creating SQL views to compute statistics on-demand
3. Improving query efficiency and eliminating data duplication

IMPORTANT: This migration is idempotent - safe to run multiple times.
It checks for existing views and table schemas before making changes.
"""

import sqlite3
from . import Migration


class Migration005(Migration):
    """Remove redundant columns and create views for computed statistics."""

    @property
    def version(self) -> int:
        return 5

    @property
    def description(self) -> str:
        return "Remove redundant columns and create views for computed statistics"

    def upgrade(self, conn: sqlite3.Connection) -> None:
        """Remove redundant columns and create views (idempotent).

        This migration:
        1. Creates SQL views for computed statistics
        2. Migrates artifacts.artifact_type to artifact_type_id FK
        3. Recreates plugin_files without host_count/port_count
        4. Recreates plugins without severity_label
        5. Recreates sessions without aggregate columns
        """

        print("  Starting migration 005: Remove redundant columns and create views")

        # ========== Check if already completed ==========
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='plugin_files_v4_backup'"
        )
        if cursor.fetchone():
            print("  [OK] Migration 005 already completed")
            return

        # ========== Disable FK checks during migration ==========
        # Save current FK setting
        cursor = conn.execute("PRAGMA foreign_keys")
        fk_was_on = cursor.fetchone()[0] == 1
        conn.execute("PRAGMA foreign_keys=OFF")

        # ========== Step 1: Drop any existing views (will be recreated later) ==========
        print("  [1/6] Dropping any existing views (will recreate after table migrations)...")
        for view_name in ['v_plugin_file_stats', 'v_session_stats', 'v_plugins_with_severity',
                          'v_host_findings', 'v_artifacts_with_types']:
            conn.execute(f"DROP VIEW IF EXISTS {view_name}")

        # ========== Step 2: Migrate artifacts table ==========
        print("  [2/6] Migrating artifacts table to use artifact_type_id FK...")
        self._migrate_artifacts_table(conn)

        # ========== Step 3: Recreate plugin_files table ==========
        print("  [3/6] Recreating plugin_files table without host_count/port_count...")
        self._recreate_plugin_files_table(conn)

        # ========== Step 4: Recreate plugins table ==========
        print("  [4/6] Recreating plugins table without severity_label...")
        self._recreate_plugins_table(conn)

        # ========== Step 5: Recreate sessions table ==========
        print("  [5/6] Recreating sessions table without aggregate columns...")
        self._recreate_sessions_table(conn)

        # ========== Step 6: Create Views (after tables are migrated) ==========
        print("  [6/6] Creating SQL views for computed statistics...")
        self._create_views(conn)

        # ========== Re-enable FK checks ==========
        if fk_was_on:
            conn.execute("PRAGMA foreign_keys=ON")

        print("  [OK] Migration 005 completed successfully")

    def _create_views(self, conn: sqlite3.Connection) -> None:
        """Create SQL views for computed statistics (idempotent)."""

        # Check if views already exist
        cursor = conn.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='view' AND name IN "
            "('v_plugin_file_stats', 'v_session_stats', 'v_plugins_with_severity', "
            "'v_host_findings', 'v_artifacts_with_types')"
        )
        existing_views_count = cursor.fetchone()[0]

        if existing_views_count == 5:
            print("    [OK] All views already exist")
            return

        # Drop existing views (if partial migration)
        for view_name in ['v_plugin_file_stats', 'v_session_stats', 'v_plugins_with_severity',
                          'v_host_findings', 'v_artifacts_with_types']:
            conn.execute(f"DROP VIEW IF EXISTS {view_name}")

        # Create v_plugin_file_stats view
        conn.execute("""
            CREATE VIEW v_plugin_file_stats AS
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
                     pf.reviewed_at, pf.reviewed_by, pf.review_notes
        """)

        # Create v_session_stats view
        conn.execute("""
            CREATE VIEW v_session_stats AS
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
            GROUP BY s.session_id, s.scan_id, s.session_start, s.session_end
        """)

        # Create v_plugins_with_severity view
        conn.execute("""
            CREATE VIEW v_plugins_with_severity AS
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
            JOIN severity_levels sl ON p.severity_int = sl.severity_int
        """)

        # Create v_host_findings view (new capability)
        conn.execute("""
            CREATE VIEW v_host_findings AS
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
            GROUP BY h.host_id, h.host_address, h.host_type, h.first_seen, h.last_seen
        """)

        # Create v_artifacts_with_types view
        conn.execute("""
            CREATE VIEW v_artifacts_with_types AS
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
            LEFT JOIN artifact_types at ON a.artifact_type_id = at.artifact_type_id
        """)

        print("    [OK] Created 5 SQL views")

    def _migrate_artifacts_table(self, conn: sqlite3.Connection) -> None:
        """Migrate artifacts table to use artifact_type_id FK (idempotent)."""

        # Check if artifact_type_id column already exists
        cursor = conn.execute("PRAGMA table_info(artifacts)")
        columns = [row[1] for row in cursor.fetchall()]

        if 'artifact_type_id' in columns and 'artifact_type' not in columns:
            print("    [OK] Artifacts table already migrated")
            return

        # Create new artifacts table with artifact_type_id FK
        conn.execute("""
            CREATE TABLE artifacts_new (
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
            )
        """)

        # Migrate data: map artifact_type string to artifact_type_id
        conn.execute("""
            INSERT INTO artifacts_new (
                artifact_id, execution_id, artifact_path, artifact_type_id,
                file_size_bytes, file_hash, created_at, last_accessed_at, metadata
            )
            SELECT
                a.artifact_id,
                a.execution_id,
                a.artifact_path,
                at.artifact_type_id,
                a.file_size_bytes,
                a.file_hash,
                a.created_at,
                a.last_accessed_at,
                a.metadata
            FROM artifacts a
            LEFT JOIN artifact_types at ON a.artifact_type = at.type_name
        """)

        # Drop old table and rename new table
        conn.execute("DROP TABLE artifacts")
        conn.execute("ALTER TABLE artifacts_new RENAME TO artifacts")

        # Recreate indexes
        conn.execute("CREATE INDEX idx_artifacts_execution ON artifacts(execution_id)")
        conn.execute("CREATE INDEX idx_artifacts_type ON artifacts(artifact_type_id)")

        print("    [OK] Migrated artifacts table to use artifact_type_id FK")

    def _recreate_plugin_files_table(self, conn: sqlite3.Connection) -> None:
        """Recreate plugin_files table without host_count/port_count (idempotent)."""

        # Check if columns still exist
        cursor = conn.execute("PRAGMA table_info(plugin_files)")
        columns = [row[1] for row in cursor.fetchall()]

        if 'host_count' not in columns and 'port_count' not in columns:
            print("    [OK] plugin_files table already cleaned up")
            return

        # Create new table without redundant columns
        conn.execute("""
            CREATE TABLE plugin_files_new (
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
            )
        """)

        # Copy data (excluding host_count, port_count)
        conn.execute("""
            INSERT INTO plugin_files_new (
                file_id, scan_id, plugin_id, review_state, reviewed_at, reviewed_by, review_notes
            )
            SELECT
                file_id, scan_id, plugin_id, review_state, reviewed_at, reviewed_by, review_notes
            FROM plugin_files
        """)

        # Backup old table for safety
        conn.execute("ALTER TABLE plugin_files RENAME TO plugin_files_v4_backup")

        # Rename new table
        conn.execute("ALTER TABLE plugin_files_new RENAME TO plugin_files")

        # Recreate indexes
        conn.execute("CREATE INDEX idx_plugin_files_scan ON plugin_files(scan_id)")
        conn.execute("CREATE INDEX idx_plugin_files_plugin ON plugin_files(plugin_id)")
        conn.execute("CREATE INDEX idx_plugin_files_review_state ON plugin_files(review_state)")

        # Recreate audit trigger (if it exists)
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='trigger' AND name='audit_plugin_files_review_update'"
        )
        if cursor.fetchone():
            conn.execute("""
                CREATE TRIGGER audit_plugin_files_review_update
                AFTER UPDATE ON plugin_files
                FOR EACH ROW
                WHEN OLD.review_state != NEW.review_state
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

        print("    [OK] Recreated plugin_files table without host_count/port_count")

    def _recreate_plugins_table(self, conn: sqlite3.Connection) -> None:
        """Recreate plugins table without severity_label (idempotent)."""

        # Check if severity_label column still exists
        cursor = conn.execute("PRAGMA table_info(plugins)")
        columns = [row[1] for row in cursor.fetchall()]

        if 'severity_label' not in columns:
            print("    [OK] plugins table already cleaned up")
            return

        # Create new table without severity_label
        conn.execute("""
            CREATE TABLE plugins_new (
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
            )
        """)

        # Copy data (excluding severity_label)
        conn.execute("""
            INSERT INTO plugins_new (
                plugin_id, plugin_name, severity_int, has_metasploit, cvss3_score, cvss2_score,
                metasploit_names, cves, plugin_url, metadata_fetched_at
            )
            SELECT
                plugin_id, plugin_name, severity_int, has_metasploit, cvss3_score, cvss2_score,
                metasploit_names, cves, plugin_url, metadata_fetched_at
            FROM plugins
        """)

        # Drop old table and rename new table
        conn.execute("DROP TABLE plugins")
        conn.execute("ALTER TABLE plugins_new RENAME TO plugins")

        # Recreate indexes
        conn.execute("CREATE INDEX idx_plugins_severity ON plugins(severity_int)")
        conn.execute("CREATE INDEX idx_plugins_metasploit ON plugins(has_metasploit)")

        print("    [OK] Recreated plugins table without severity_label")

    def _recreate_sessions_table(self, conn: sqlite3.Connection) -> None:
        """Recreate sessions table without aggregate columns (idempotent)."""

        # Check if aggregate columns still exist
        cursor = conn.execute("PRAGMA table_info(sessions)")
        columns = [row[1] for row in cursor.fetchall()]

        aggregate_columns = ['duration_seconds', 'files_reviewed', 'files_completed',
                             'files_skipped', 'tools_executed', 'cves_extracted']
        if not any(col in columns for col in aggregate_columns):
            print("    [OK] sessions table already cleaned up")
            return

        # Create new table without aggregate columns
        conn.execute("""
            CREATE TABLE sessions_new (
                session_id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                session_start TIMESTAMP NOT NULL,
                session_end TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
            )
        """)

        # Copy data (excluding aggregate columns)
        conn.execute("""
            INSERT INTO sessions_new (session_id, scan_id, session_start, session_end)
            SELECT session_id, scan_id, session_start, session_end
            FROM sessions
        """)

        # Drop old table and rename new table
        conn.execute("DROP TABLE sessions")
        conn.execute("ALTER TABLE sessions_new RENAME TO sessions")

        # Recreate index
        conn.execute("CREATE INDEX idx_sessions_scan ON sessions(scan_id)")

        # Recreate audit trigger (if it exists)
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='trigger' AND name='audit_sessions_insert'"
        )
        if cursor.fetchone():
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

        print("    [OK] Recreated sessions table without aggregate columns")

    def downgrade(self, conn: sqlite3.Connection) -> None:
        """Rollback migration - restore original schema.

        WARNING: This is expensive as it requires repopulating columns from views.
        """

        print("  Rolling back migration 005...")

        # Check if backup exists
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='plugin_files_v4_backup'"
        )
        if not cursor.fetchone():
            print("  [SKIP] Migration 005 not applied, nothing to rollback")
            return

        # Drop views
        print("  [1/5] Dropping views...")
        for view_name in ['v_plugin_file_stats', 'v_session_stats', 'v_plugins_with_severity',
                          'v_host_findings', 'v_artifacts_with_types']:
            conn.execute(f"DROP VIEW IF EXISTS {view_name}")

        # Restore plugin_files from backup
        print("  [2/5] Restoring plugin_files table...")
        conn.execute("DROP TABLE plugin_files")
        conn.execute("ALTER TABLE plugin_files_v4_backup RENAME TO plugin_files")

        # Restore plugins table (add severity_label back)
        print("  [3/5] Restoring plugins table...")
        conn.execute("""
            CREATE TABLE plugins_old (
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
            )
        """)
        conn.execute("""
            INSERT INTO plugins_old
            SELECT p.*, sl.severity_label
            FROM plugins p
            JOIN severity_levels sl ON p.severity_int = sl.severity_int
        """)
        conn.execute("DROP TABLE plugins")
        conn.execute("ALTER TABLE plugins_old RENAME TO plugins")
        conn.execute("CREATE INDEX idx_plugins_severity ON plugins(severity_int)")
        conn.execute("CREATE INDEX idx_plugins_metasploit ON plugins(has_metasploit)")

        # Restore sessions table (add aggregate columns back)
        print("  [4/5] Restoring sessions table...")
        # Note: This is expensive - need to compute aggregates from data
        conn.execute("""
            CREATE TABLE sessions_old (
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
            )
        """)
        # Copy and compute aggregates (this will be slow for large databases)
        conn.execute("""
            INSERT INTO sessions_old
            SELECT
                s.session_id,
                s.scan_id,
                s.session_start,
                s.session_end,
                CAST((julianday(s.session_end) - julianday(s.session_start)) * 86400 AS INTEGER) as duration_seconds,
                COALESCE((SELECT COUNT(*) FROM plugin_files WHERE scan_id = s.scan_id AND review_state = 'reviewed'), 0),
                COALESCE((SELECT COUNT(*) FROM plugin_files WHERE scan_id = s.scan_id AND review_state = 'completed'), 0),
                COALESCE((SELECT COUNT(*) FROM plugin_files WHERE scan_id = s.scan_id AND review_state = 'skipped'), 0),
                COALESCE((SELECT COUNT(*) FROM tool_executions WHERE session_id = s.session_id), 0),
                0  -- cves_extracted (hard to recompute, set to 0)
            FROM sessions s
        """)
        conn.execute("DROP TABLE sessions")
        conn.execute("ALTER TABLE sessions_old RENAME TO sessions")
        conn.execute("CREATE INDEX idx_sessions_scan ON sessions(scan_id)")

        # Restore artifacts table (add artifact_type TEXT back)
        print("  [5/5] Restoring artifacts table...")
        conn.execute("""
            CREATE TABLE artifacts_old (
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
            )
        """)
        conn.execute("""
            INSERT INTO artifacts_old
            SELECT a.artifact_id, a.execution_id, a.artifact_path, at.type_name,
                   a.file_size_bytes, a.file_hash, a.created_at, a.last_accessed_at, a.metadata
            FROM artifacts a
            LEFT JOIN artifact_types at ON a.artifact_type_id = at.artifact_type_id
        """)
        conn.execute("DROP TABLE artifacts")
        conn.execute("ALTER TABLE artifacts_old RENAME TO artifacts")
        conn.execute("CREATE INDEX idx_artifacts_execution ON artifacts(execution_id)")
        conn.execute("CREATE INDEX idx_artifacts_type ON artifacts(artifact_type)")

        print("  [OK] Migration 005 rolled back successfully")
