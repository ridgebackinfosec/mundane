"""Tests for mundane_pkg.session module (database-only architecture)."""

from datetime import datetime
from unittest.mock import patch

import pytest

from mundane_pkg.session import (
    SessionState,
    save_session,
    load_session,
    delete_session,
)
from mundane_pkg.models import Scan


# Ensure database is enabled for tests and use temp_db
@pytest.fixture(autouse=True)
def ensure_db_enabled(monkeypatch, temp_db):
    """Ensure database is enabled and use temp_db for all tests."""
    import mundane_pkg.database

    # Monkeypatch get_connection to return our temp_db
    # Create a wrapper that prevents the connection from being closed
    class UnclosableConnection:
        """Wrapper that delegates to real connection but prevents close()."""
        def __init__(self, conn):
            self._conn = conn

        def __getattr__(self, name):
            if name == 'close':
                # Don't actually close the connection
                return lambda: None
            return getattr(self._conn, name)

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            return False

    def mock_get_connection(database_path=None):
        return UnclosableConnection(temp_db)

    monkeypatch.setattr(mundane_pkg.database, "get_connection", mock_get_connection)


class TestSessionState:
    """Tests for SessionState dataclass."""

    def test_session_state_creation(self):
        """Test creating SessionState with all fields."""
        state = SessionState(
            scan_name="test_scan",
            session_start="2024-01-15T10:30:00",
            reviewed_count=2,
            completed_count=1,
            skipped_count=1,
            tool_executions=5,
            cve_extractions=2,
        )

        assert state.scan_name == "test_scan"
        assert state.reviewed_count == 2
        assert state.completed_count == 1
        assert state.skipped_count == 1
        assert state.tool_executions == 5
        assert state.cve_extractions == 2

    def test_session_state_empty_counts(self):
        """Test SessionState with zero counts."""
        state = SessionState(
            scan_name="empty_scan",
            session_start="2024-01-15T10:00:00",
            reviewed_count=0,
            completed_count=0,
            skipped_count=0,
            tool_executions=0,
            cve_extractions=0,
        )

        assert state.reviewed_count == 0
        assert state.completed_count == 0
        assert state.skipped_count == 0


class TestSaveSession:
    """Tests for save_session function."""

    def test_save_session_creates_scan_and_session(self, temp_db):
        """Test that save_session creates scan and session in database."""
        # Create a scan first
        scan = Scan(scan_name="test_scan", export_root="/tmp/test")
        scan_id = scan.save(temp_db)

        session_start = datetime(2024, 1, 15, 10, 0, 0)

        session_id = save_session(
            scan_id=scan_id,
            session_start=session_start,
            reviewed_count=2,
            completed_count=1,
            skipped_count=0,
            tool_executions=5,
            cve_extractions=2
        )

        assert session_id is not None

        # Verify session in database
        cursor = temp_db.execute(
            """
            SELECT s.files_reviewed, s.files_completed, s.files_skipped,
                   s.tools_executed, s.cves_extracted, s.session_end
            FROM sessions s
            WHERE s.scan_id = ?
            """,
            (scan_id,)
        )
        row = cursor.fetchone()

        assert row is not None
        assert row["files_reviewed"] == 2
        assert row["files_completed"] == 1
        assert row["files_skipped"] == 0
        assert row["tools_executed"] == 5
        assert row["cves_extracted"] == 2
        assert row["session_end"] is None  # Active session

    def test_save_session_updates_existing_session(self, temp_db):
        """Test that save_session updates existing active session."""
        # Create scan
        scan = Scan(scan_name="update_scan", export_root="/tmp/test")
        scan_id = scan.save(temp_db)

        session_start = datetime(2024, 1, 15, 10, 0, 0)

        # First save
        session_id1 = save_session(
            scan_id=scan_id,
            session_start=session_start,
            reviewed_count=1,
            completed_count=0,
            skipped_count=0,
            tool_executions=1,
            cve_extractions=0
        )

        # Second save (should update same session)
        session_id2 = save_session(
            scan_id=scan_id,
            session_start=session_start,
            reviewed_count=3,
            completed_count=2,
            skipped_count=1,
            tool_executions=5,
            cve_extractions=2
        )

        # Should return same session ID
        assert session_id1 == session_id2

        # Verify only one session exists with updated counts
        cursor = temp_db.execute(
            """
            SELECT COUNT(*) as count, files_reviewed, files_completed,
                   tools_executed, cves_extracted
            FROM sessions
            WHERE scan_id = ? AND session_end IS NULL
            """,
            (scan_id,)
        )
        row = cursor.fetchone()

        assert row["count"] == 1
        assert row["files_reviewed"] == 3
        assert row["files_completed"] == 2
        assert row["tools_executed"] == 5
        assert row["cves_extracted"] == 2

    def test_save_session_with_zero_counts(self, temp_db):
        """Test saving session with all zero counts."""
        scan = Scan(scan_name="zero_scan", export_root="/tmp/test")
        scan_id = scan.save(temp_db)

        session_start = datetime(2024, 1, 15, 10, 0, 0)

        session_id = save_session(
            scan_id=scan_id,
            session_start=session_start,
            reviewed_count=0,
            completed_count=0,
            skipped_count=0,
            tool_executions=0,
            cve_extractions=0
        )

        assert session_id is not None

        # Verify counts in database
        cursor = temp_db.execute(
            "SELECT files_reviewed, files_completed FROM sessions WHERE session_id = ?",
            (session_id,)
        )
        row = cursor.fetchone()

        assert row["files_reviewed"] == 0
        assert row["files_completed"] == 0


class TestLoadSession:
    """Tests for load_session function."""

    def test_load_session_success(self, temp_db):
        """Test loading active session from database."""
        # Create scan and session
        scan = Scan(scan_name="load_scan", export_root="/tmp/test")
        scan_id = scan.save(temp_db)

        session_start = datetime(2024, 1, 15, 10, 30, 0)

        save_session(
            scan_id=scan_id,
            session_start=session_start,
            reviewed_count=2,
            completed_count=1,
            skipped_count=1,
            tool_executions=5,
            cve_extractions=2
        )

        # Load session
        state = load_session(scan_id)

        assert state is not None
        assert state.scan_name == "load_scan"
        assert state.reviewed_count == 2
        assert state.completed_count == 1
        assert state.skipped_count == 1
        assert state.tool_executions == 5
        assert state.cve_extractions == 2

    def test_load_session_nonexistent(self, temp_db):
        """Test loading when no session exists."""
        # Create scan but no session
        scan = Scan(scan_name="no_session_scan", export_root="/tmp/test")
        scan_id = scan.save(temp_db)

        state = load_session(scan_id)

        assert state is None

    def test_load_session_ended_session(self, temp_db):
        """Test that load_session only returns active sessions."""
        # Create scan and session
        scan = Scan(scan_name="ended_scan", export_root="/tmp/test")
        scan_id = scan.save(temp_db)

        session_start = datetime(2024, 1, 15, 10, 0, 0)
        session_id = save_session(
            scan_id=scan_id,
            session_start=session_start,
            reviewed_count=1,
            completed_count=0,
            skipped_count=0
        )

        # End the session
        delete_session(scan_id)

        # Load should return None (no active session)
        state = load_session(scan_id)
        assert state is None


class TestDeleteSession:
    """Tests for delete_session function."""

    def test_delete_session_ends_db_session(self, temp_db):
        """Test that delete_session marks database session as ended."""
        # Create scan and session
        scan = Scan(scan_name="delete_scan", export_root="/tmp/test")
        scan_id = scan.save(temp_db)

        session_start = datetime(2024, 1, 15, 10, 0, 0)
        save_session(
            scan_id=scan_id,
            session_start=session_start,
            reviewed_count=1,
            completed_count=0,
            skipped_count=0
        )

        # Verify session is active
        cursor = temp_db.execute(
            "SELECT session_end FROM sessions WHERE scan_id = ?",
            (scan_id,)
        )
        row = cursor.fetchone()
        assert row["session_end"] is None

        # Delete session
        delete_session(scan_id)

        # Verify session is ended
        cursor = temp_db.execute(
            "SELECT session_end, duration_seconds FROM sessions WHERE scan_id = ?",
            (scan_id,)
        )
        row = cursor.fetchone()
        assert row["session_end"] is not None
        assert row["duration_seconds"] is not None
        assert row["duration_seconds"] >= 0

    def test_delete_session_no_active_session(self, temp_db):
        """Test delete_session when no active session exists."""
        # Create scan without session
        scan = Scan(scan_name="no_session", export_root="/tmp/test")
        scan_id = scan.save(temp_db)

        # Should not raise exception
        delete_session(scan_id)


class TestSessionLifecycle:
    """Integration tests for complete session lifecycle."""

    def test_complete_session_lifecycle(self, temp_db):
        """Test complete session lifecycle: save → load → update → delete."""
        # Create scan
        scan = Scan(scan_name="lifecycle_scan", export_root="/tmp/test")
        scan_id = scan.save(temp_db)

        session_start = datetime(2024, 1, 15, 10, 0, 0)

        # 1. Create initial session
        save_session(
            scan_id=scan_id,
            session_start=session_start,
            reviewed_count=1,
            completed_count=0,
            skipped_count=0,
            tool_executions=1,
            cve_extractions=0
        )

        # 2. Load session
        state = load_session(scan_id)
        assert state is not None
        assert state.reviewed_count == 1
        assert state.tool_executions == 1

        # 3. Update session
        save_session(
            scan_id=scan_id,
            session_start=session_start,
            reviewed_count=3,
            completed_count=2,
            skipped_count=1,
            tool_executions=8,
            cve_extractions=3
        )

        # 4. Load updated session
        state = load_session(scan_id)
        assert state is not None
        assert state.reviewed_count == 3
        assert state.completed_count == 2
        assert state.skipped_count == 1
        assert state.tool_executions == 8
        assert state.cve_extractions == 3

        # 5. Verify database has updated counts
        cursor = temp_db.execute(
            """
            SELECT files_reviewed, files_completed, tools_executed, cves_extracted
            FROM sessions WHERE scan_id = ?
            """,
            (scan_id,)
        )
        row = cursor.fetchone()
        assert row["files_reviewed"] == 3
        assert row["files_completed"] == 2
        assert row["tools_executed"] == 8
        assert row["cves_extracted"] == 3

        # 6. Delete session
        delete_session(scan_id)

        # 7. Verify cleanup
        state = load_session(scan_id)
        assert state is None

        # Verify database session is marked ended
        cursor = temp_db.execute(
            "SELECT session_end FROM sessions WHERE scan_id = ?",
            (scan_id,)
        )
        row = cursor.fetchone()
        assert row["session_end"] is not None

    def test_multiple_sessions_for_same_scan(self, temp_db):
        """Test multiple sequential sessions for the same scan."""
        # Create scan
        scan = Scan(scan_name="multi_session_scan", export_root="/tmp/test")
        scan_id = scan.save(temp_db)

        # Session 1
        session1_start = datetime(2024, 1, 15, 10, 0, 0)
        save_session(
            scan_id=scan_id,
            session_start=session1_start,
            reviewed_count=1,
            completed_count=0,
            skipped_count=0
        )
        delete_session(scan_id)

        # Session 2
        session2_start = datetime(2024, 1, 15, 14, 0, 0)
        save_session(
            scan_id=scan_id,
            session_start=session2_start,
            reviewed_count=2,
            completed_count=1,
            skipped_count=0
        )
        delete_session(scan_id)

        # Verify both sessions in database
        cursor = temp_db.execute(
            "SELECT COUNT(*) as count FROM sessions WHERE scan_id = ?",
            (scan_id,)
        )
        row = cursor.fetchone()
        assert row["count"] == 2

        # Verify both sessions have end times
        cursor = temp_db.execute(
            """
            SELECT COUNT(*) as ended_count FROM sessions
            WHERE scan_id = ? AND session_end IS NOT NULL
            """,
            (scan_id,)
        )
        row = cursor.fetchone()
        assert row["ended_count"] == 2
