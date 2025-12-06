"""Migration 004: Host and port normalization.

Eliminates host/port duplication and enables cross-scan tracking.

IMPORTANT: This migration is idempotent - safe to run multiple times.
It checks both table existence AND population to handle the case where
SCHEMA_SQL creates empty tables before migrations run.
"""

import sqlite3
from . import Migration


class Migration004(Migration):
    """Normalize hosts and ports into separate tables."""

    @property
    def version(self) -> int:
        return 4

    @property
    def description(self) -> str:
        return "Normalize hosts and ports into separate tables"

    def upgrade(self, conn: sqlite3.Connection) -> None:
        """Normalize host and port data (idempotent).

        This migration:
        1. Creates hosts table and populates from plugin_file_hosts
        2. Creates ports table and populates from plugin_file_hosts
        3. Creates new normalized junction table
        4. Migrates data using host_id foreign keys
        5. Swaps tables (preserves old as backup)
        """

        # Import detect_host_type from parsing module
        import sys
        from pathlib import Path
        mundane_pkg = Path(__file__).parent.parent
        if str(mundane_pkg) not in sys.path:
            sys.path.insert(0, str(mundane_pkg))
        from parsing import detect_host_type

        # ========== Check if already completed ==========
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='plugin_file_hosts_old'"
        )
        if cursor.fetchone():
            print("  [OK] Migration 004 already completed")
            return

        # ========== Create hosts table ==========
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='hosts'"
        )
        hosts_table_exists = cursor.fetchone() is not None

        if not hosts_table_exists:
            print("  [OK] Creating hosts table...")
            conn.execute("""
                CREATE TABLE hosts (
                    host_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_address TEXT NOT NULL UNIQUE,
                    host_type TEXT CHECK(host_type IN ('ipv4', 'ipv6', 'hostname')) NOT NULL,
                    reverse_dns TEXT,
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            print("  [OK] Created hosts table")

        # ========== Populate hosts (idempotent) ==========
        cursor = conn.execute("SELECT COUNT(*) FROM hosts")
        if cursor.fetchone()[0] == 0:
            print("  [OK] Extracting unique hosts from plugin_file_hosts...")

            # Check if old-style plugin_file_hosts exists (with 'host' column)
            cursor = conn.execute("PRAGMA table_info(plugin_file_hosts)")
            columns = [row[1] for row in cursor.fetchall()]

            if 'host' in columns:
                # Old schema - extract hosts
                cursor = conn.execute("""
                    SELECT DISTINCT host FROM plugin_file_hosts
                    WHERE host IS NOT NULL AND host != ''
                """)

                hosts_to_insert = []
                for row in cursor.fetchall():
                    host = row[0]
                    host_type = detect_host_type(host)
                    hosts_to_insert.append((host, host_type))

                if hosts_to_insert:
                    print(f"  [OK] Inserting {len(hosts_to_insert)} unique hosts...")
                    conn.executemany(
                        "INSERT OR IGNORE INTO hosts (host_address, host_type) VALUES (?, ?)",
                        hosts_to_insert
                    )
                    print(f"  [OK] Populated hosts table with {len(hosts_to_insert)} hosts")
                else:
                    print("  [OK] No hosts to migrate (empty database)")
            else:
                print("  [OK] plugin_file_hosts already normalized (skipping host extraction)")
        else:
            cursor = conn.execute("SELECT COUNT(*) FROM hosts")
            print(f"  [OK] hosts table already populated ({cursor.fetchone()[0]} hosts)")

        # ========== Create ports table ==========
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='ports'"
        )
        ports_table_exists = cursor.fetchone() is not None

        if not ports_table_exists:
            print("  [OK] Creating ports table...")
            conn.execute("""
                CREATE TABLE ports (
                    port_number INTEGER PRIMARY KEY CHECK(port_number BETWEEN 1 AND 65535),
                    service_name TEXT,
                    description TEXT
                )
            """)
            print("  [OK] Created ports table")

        # ========== Populate ports ==========
        cursor = conn.execute("SELECT COUNT(*) FROM ports")
        if cursor.fetchone()[0] == 0:
            # Check if old schema exists
            cursor = conn.execute("PRAGMA table_info(plugin_file_hosts)")
            columns = [row[1] for row in cursor.fetchall()]

            if 'port' in columns:
                print("  [OK] Extracting unique ports...")
                conn.execute("""
                    INSERT OR IGNORE INTO ports (port_number)
                    SELECT DISTINCT port
                    FROM plugin_file_hosts
                    WHERE port IS NOT NULL AND port BETWEEN 1 AND 65535
                """)
                cursor = conn.execute("SELECT COUNT(*) FROM ports")
                port_count = cursor.fetchone()[0]
                if port_count > 0:
                    print(f"  [OK] Populated ports table with {port_count} ports")
                else:
                    print("  [OK] No ports to migrate")
            else:
                print("  [OK] plugin_file_hosts already normalized (skipping port extraction)")
        else:
            cursor = conn.execute("SELECT COUNT(*) FROM ports")
            print(f"  [OK] ports table already populated ({cursor.fetchone()[0]} ports)")

        # ========== Create indexes on hosts ==========
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND name='idx_hosts_address'"
        )
        if not cursor.fetchone():
            conn.execute("CREATE INDEX idx_hosts_address ON hosts(host_address)")
            print("  [OK] Created index idx_hosts_address")

        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND name='idx_hosts_type'"
        )
        if not cursor.fetchone():
            conn.execute("CREATE INDEX idx_hosts_type ON hosts(host_type)")
            print("  [OK] Created index idx_hosts_type")

        # ========== Check if migration needed ==========
        # If plugin_file_hosts already has host_id column, it's already normalized
        cursor = conn.execute("PRAGMA table_info(plugin_file_hosts)")
        columns = [row[1] for row in cursor.fetchall()]

        if 'host_id' in columns:
            print("  [OK] plugin_file_hosts already normalized (has host_id column)")
            print("  [OK] Migration 004 completed successfully")
            return

        # ========== Create new junction table ==========
        print("  [OK] Creating new plugin_file_hosts_new table...")
        conn.execute("""
            CREATE TABLE plugin_file_hosts_new (
                pfh_id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id INTEGER NOT NULL,
                host_id INTEGER NOT NULL,
                port_number INTEGER,
                plugin_output TEXT,
                FOREIGN KEY (file_id) REFERENCES plugin_files(file_id) ON DELETE CASCADE,
                FOREIGN KEY (host_id) REFERENCES hosts(host_id),
                FOREIGN KEY (port_number) REFERENCES ports(port_number),
                CONSTRAINT unique_file_host_port UNIQUE (file_id, host_id, port_number)
            )
        """)
        print("  [OK] Created plugin_file_hosts_new table")

        # ========== Migrate data ==========
        print("  [OK] Migrating data to new schema...")
        conn.execute("""
            INSERT OR IGNORE INTO plugin_file_hosts_new (file_id, host_id, port_number, plugin_output)
            SELECT
                pfh.file_id,
                h.host_id,
                pfh.port,
                pfh.plugin_output
            FROM plugin_file_hosts pfh
            JOIN hosts h ON pfh.host = h.host_address
            WHERE pfh.host IS NOT NULL AND pfh.host != ''
        """)

        # Verify record count
        cursor = conn.execute("SELECT COUNT(*) FROM plugin_file_hosts_new")
        new_count = cursor.fetchone()[0]
        cursor = conn.execute("SELECT COUNT(*) FROM plugin_file_hosts WHERE host IS NOT NULL AND host != ''")
        old_count = cursor.fetchone()[0]
        print(f"  [OK] Migrated {new_count} host:port records (from {old_count} in old table)")

        if new_count < old_count:
            print(f"  [WARNING] {old_count - new_count} records not migrated (likely NULL or empty hosts)")

        # ========== Create indexes on new table ==========
        conn.execute("CREATE INDEX idx_pfh_file ON plugin_file_hosts_new(file_id)")
        conn.execute("CREATE INDEX idx_pfh_host ON plugin_file_hosts_new(host_id)")
        conn.execute("CREATE INDEX idx_pfh_port ON plugin_file_hosts_new(port_number)")
        print("  [OK] Created indexes on plugin_file_hosts_new")

        # ========== Swap tables ==========
        print("  [OK] Swapping tables...")
        conn.execute("ALTER TABLE plugin_file_hosts RENAME TO plugin_file_hosts_old")
        conn.execute("ALTER TABLE plugin_file_hosts_new RENAME TO plugin_file_hosts")
        print("  [OK] Swapped tables (old preserved as plugin_file_hosts_old)")

        print("  [OK] Migration 004 completed successfully")
        print("  [NOTE] Old table preserved as 'plugin_file_hosts_old' for safety")
        print("  [NOTE] You can drop it after verifying the migration: DROP TABLE plugin_file_hosts_old;")

    def downgrade(self, conn: sqlite3.Connection) -> None:
        """Rollback migration (testing only).

        Restores the old plugin_file_hosts schema and drops normalized tables.
        """
        print("  [OK] Rolling back migration 004...")

        # Check if old table exists
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='plugin_file_hosts_old'"
        )
        if not cursor.fetchone():
            print("  [WARNING] plugin_file_hosts_old not found - nothing to rollback")
            return

        # Restore old table
        conn.execute("DROP TABLE IF EXISTS plugin_file_hosts")
        conn.execute("ALTER TABLE plugin_file_hosts_old RENAME TO plugin_file_hosts")
        print("  [OK] Restored plugin_file_hosts from backup")

        # Drop new tables
        conn.execute("DROP TABLE IF EXISTS ports")
        conn.execute("DROP TABLE IF EXISTS hosts")
        print("  [OK] Dropped hosts and ports tables")

        print("  [OK] Migration 004 rollback completed")
