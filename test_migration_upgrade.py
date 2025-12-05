"""Test script to verify migration_003 works correctly with existing databases.

This simulates the real-world scenario where:
1. User has existing database (schema version 2)
2. User upgrades Mundane to version with schema version 3
3. Migration should automatically populate empty lookup tables
"""

import sqlite3
import tempfile
from pathlib import Path

# Import database functions
from mundane_pkg.database import initialize_database, SCHEMA_SQL

def test_migration_upgrade_scenario():
    """Test that migration_003 populates tables even when SCHEMA_SQL creates them first."""

    # Create a temporary database file
    with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as tmp:
        db_path = Path(tmp.name)

    print(f"Test database: {db_path}")
    print("="*60)

    try:
        # Simulate existing database at version 2
        print("\n1. Creating existing database at schema version 2...")
        conn = sqlite3.connect(str(db_path))
        conn.execute("PRAGMA foreign_keys=ON")

        # Create full schema using SCHEMA_SQL (but don't run migrations yet)
        # This simulates a database that was created with schema version 2
        conn.executescript(SCHEMA_SQL)

        # Set schema version to 2 (pretend migrations 1 and 2 have already run)
        conn.execute("DELETE FROM schema_version")  # Clear any auto-inserted versions
        conn.execute("INSERT INTO schema_version (version) VALUES (1)")
        conn.execute("INSERT INTO schema_version (version) VALUES (2)")
        conn.commit()
        conn.close()

        print("   [OK] Created database with full schema at version 2")

        # Verify starting state
        conn = sqlite3.connect(str(db_path))
        cursor = conn.execute("SELECT version FROM schema_version ORDER BY version DESC LIMIT 1")
        current_version = cursor.fetchone()[0]
        print(f"   [OK] Current schema version: {current_version}")
        conn.close()

        # Now simulate user upgrading to new version
        print("\n2. Simulating upgrade to schema version 3...")
        print("   Running initialize_database() (simulates startup)...")

        try:
            success = initialize_database(database_path=db_path)

            if not success:
                print("   [ERROR] initialize_database() failed!")
                return False
        except Exception as e:
            print(f"   [ERROR] initialize_database() raised exception: {e}")
            import traceback
            traceback.print_exc()
            return False

        print("   [OK] initialize_database() completed")

        # Verify migration ran and tables are populated
        print("\n3. Verifying migration results...")
        conn = sqlite3.connect(str(db_path))

        # Check schema version
        cursor = conn.execute("SELECT version FROM schema_version ORDER BY version DESC LIMIT 1")
        new_version = cursor.fetchone()[0]
        print(f"   Schema version: {new_version}")

        if new_version != 3:
            print(f"   [ERROR] Expected version 3, got {new_version}")
            return False

        # Check severity_levels table
        cursor = conn.execute("SELECT COUNT(*) FROM severity_levels")
        severity_count = cursor.fetchone()[0]
        print(f"   severity_levels rows: {severity_count}")

        if severity_count != 5:
            print(f"   [ERROR] Expected 5 severity levels, got {severity_count}")
            return False

        # Verify actual data
        cursor = conn.execute("SELECT severity_int, severity_label FROM severity_levels ORDER BY severity_int DESC")
        severities = cursor.fetchall()
        expected = [(4, 'Critical'), (3, 'High'), (2, 'Medium'), (1, 'Low'), (0, 'Info')]

        for actual, exp in zip(severities, expected):
            if actual != exp:
                print(f"   [ERROR] Expected {exp}, got {actual}")
                return False

        print("   [OK] severity_levels correctly populated:")
        for sev in severities:
            print(f"        {sev[0]}: {sev[1]}")

        # Check artifact_types table
        cursor = conn.execute("SELECT COUNT(*) FROM artifact_types")
        artifact_count = cursor.fetchone()[0]
        print(f"   artifact_types rows: {artifact_count}")

        if artifact_count != 5:
            print(f"   [ERROR] Expected 5 artifact types, got {artifact_count}")
            return False

        # Verify artifact types
        cursor = conn.execute("SELECT type_name FROM artifact_types ORDER BY type_name")
        artifact_types = [row[0] for row in cursor.fetchall()]
        expected_types = ['log', 'netexec_txt', 'nmap_gnmap', 'nmap_txt', 'nmap_xml']

        if artifact_types != expected_types:
            print(f"   [ERROR] Artifact types mismatch")
            print(f"        Expected: {expected_types}")
            print(f"        Got: {artifact_types}")
            return False

        print("   [OK] artifact_types correctly populated:")
        for at in artifact_types:
            print(f"        {at}")

        # Check audit_log table exists and is empty
        cursor = conn.execute("SELECT COUNT(*) FROM audit_log")
        audit_count = cursor.fetchone()[0]
        print(f"   audit_log rows: {audit_count}")

        # Check triggers exist
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='trigger' ORDER BY name")
        triggers = [row[0] for row in cursor.fetchall()]
        print(f"   Triggers created: {triggers}")

        expected_triggers = ['audit_plugin_files_review_update', 'audit_sessions_insert']
        for trigger in expected_triggers:
            if trigger not in triggers:
                print(f"   [ERROR] Missing trigger: {trigger}")
                return False

        conn.close()

        print("\n" + "="*60)
        print("[PASS] TEST PASSED: Migration upgrade scenario works correctly!")
        print("   - Schema version updated from 2 to 3")
        print("   - severity_levels populated with 5 rows")
        print("   - artifact_types populated with 5 rows")
        print("   - audit_log table created with triggers")
        print("="*60)

        return True

    except Exception as e:
        print(f"\n[ERROR] Test failed with exception: {e}")
        import traceback
        traceback.print_exc()
        return False

    finally:
        # Cleanup
        if db_path.exists():
            db_path.unlink()
            print(f"\nCleaned up test database: {db_path}")


if __name__ == "__main__":
    success = test_migration_upgrade_scenario()
    exit(0 if success else 1)
