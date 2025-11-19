"""Tests for mundane_pkg.session module."""

import json
import os
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import pytest

from mundane_pkg.session import (
    SessionState,
    save_session,
    load_session,
    delete_session,
)


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
            scan_dir="/tmp/test_scan",
            session_start="2024-01-15T10:30:00",
            reviewed_files=["file1.txt", "file2.txt"],
            completed_files=["file3.txt"],
            skipped_files=["empty.txt"],
            tool_executions=5,
            cve_extractions=2,
            last_updated="2024-01-15T11:00:00"
        )

        assert state.scan_dir == "/tmp/test_scan"
        assert len(state.reviewed_files) == 2
        assert len(state.completed_files) == 1
        assert len(state.skipped_files) == 1
        assert state.tool_executions == 5
        assert state.cve_extractions == 2

    def test_session_state_empty_lists(self):
        """Test SessionState with empty lists."""
        state = SessionState(
            scan_dir="/tmp/scan",
            session_start="2024-01-15T10:00:00",
            reviewed_files=[],
            completed_files=[],
            skipped_files=[],
            tool_executions=0,
            cve_extractions=0,
            last_updated="2024-01-15T10:00:00"
        )

        assert len(state.reviewed_files) == 0
        assert len(state.completed_files) == 0
        assert len(state.skipped_files) == 0


class TestSaveSession:
    """Tests for save_session function."""

    def test_save_session_basic(self, temp_dir, temp_db):
        """Test basic session save (dual-mode: DB + JSON)."""
        scan_dir = temp_dir / "test_scan"
        scan_dir.mkdir()

        session_start = datetime(2024, 1, 15, 10, 30, 0)
        reviewed = ["file1.txt", "file2.txt"]
        completed = ["file3.txt"]
        skipped = ["empty.txt"]

        save_session(
            scan_dir,
            session_start,
            reviewed,
            completed,
            skipped,
            tool_executions=5,
            cve_extractions=2
        )

        # Verify JSON file was created
        session_file = scan_dir / ".session.json"
        assert session_file.exists()

        # Verify JSON contents
        with open(session_file, "r") as f:
            data = json.load(f)

        assert data["scan_dir"] == str(scan_dir)
        assert data["reviewed_files"] == reviewed
        assert data["completed_files"] == completed
        assert data["skipped_files"] == skipped
        assert data["tool_executions"] == 5
        assert data["cve_extractions"] == 2
        assert "session_start" in data
        assert "last_updated" in data

    def test_save_session_creates_scan_in_db(self, temp_dir, temp_db):
        """Test that save_session creates scan entry in database."""
        scan_dir = temp_dir / "new_scan"
        scan_dir.mkdir()

        session_start = datetime(2024, 1, 15, 10, 0, 0)

        save_session(
            scan_dir,
            session_start,
            reviewed_files=["test.txt"],
            completed_files=[],
            skipped_files=[]
        )

        # Verify scan was created in database
        cursor = temp_db.execute(
            "SELECT scan_name, export_root FROM scans WHERE scan_name = ?",
            (scan_dir.name,)
        )
        row = cursor.fetchone()

        assert row is not None
        assert row["scan_name"] == scan_dir.name
        assert row["export_root"] == str(scan_dir.parent)

    def test_save_session_creates_session_in_db(self, temp_dir, temp_db):
        """Test that save_session creates session entry in database."""
        scan_dir = temp_dir / "test_scan"
        scan_dir.mkdir()

        session_start = datetime(2024, 1, 15, 10, 0, 0)

        save_session(
            scan_dir,
            session_start,
            reviewed_files=["f1.txt", "f2.txt"],
            completed_files=["f3.txt"],
            skipped_files=["f4.txt"],
            tool_executions=3,
            cve_extractions=1
        )

        # Verify session in database
        cursor = temp_db.execute(
            """
            SELECT s.files_reviewed, s.files_completed, s.files_skipped,
                   s.tools_executed, s.cves_extracted, s.session_end
            FROM sessions s
            JOIN scans sc ON s.scan_id = sc.scan_id
            WHERE sc.scan_name = ?
            """,
            (scan_dir.name,)
        )
        row = cursor.fetchone()

        assert row is not None
        assert row["files_reviewed"] == 2
        assert row["files_completed"] == 1
        assert row["files_skipped"] == 1
        assert row["tools_executed"] == 3
        assert row["cves_extracted"] == 1
        assert row["session_end"] is None  # Active session

    def test_save_session_updates_existing_session(self, temp_dir, temp_db):
        """Test that save_session updates existing active session."""
        scan_dir = temp_dir / "test_scan"
        scan_dir.mkdir()

        session_start = datetime(2024, 1, 15, 10, 0, 0)

        # First save
        save_session(
            scan_dir,
            session_start,
            reviewed_files=["f1.txt"],
            completed_files=[],
            skipped_files=[],
            tool_executions=1,
            cve_extractions=0
        )

        # Second save (should update)
        save_session(
            scan_dir,
            session_start,
            reviewed_files=["f1.txt", "f2.txt"],
            completed_files=["f3.txt"],
            skipped_files=["f4.txt"],
            tool_executions=5,
            cve_extractions=2
        )

        # Verify only one session exists with updated counts
        cursor = temp_db.execute(
            """
            SELECT COUNT(*) as count, MAX(files_reviewed) as reviewed,
                   MAX(tools_executed) as tools
            FROM sessions s
            JOIN scans sc ON s.scan_id = sc.scan_id
            WHERE sc.scan_name = ? AND s.session_end IS NULL
            """,
            (scan_dir.name,)
        )
        row = cursor.fetchone()

        assert row["count"] == 1
        assert row["reviewed"] == 2
        assert row["tools"] == 5

    def test_save_session_with_empty_lists(self, temp_dir, temp_db):
        """Test saving session with all empty lists."""
        scan_dir = temp_dir / "empty_scan"
        scan_dir.mkdir()

        session_start = datetime(2024, 1, 15, 10, 0, 0)

        save_session(
            scan_dir,
            session_start,
            reviewed_files=[],
            completed_files=[],
            skipped_files=[],
            tool_executions=0,
            cve_extractions=0
        )

        # Verify JSON
        session_file = scan_dir / ".session.json"
        assert session_file.exists()

        with open(session_file, "r") as f:
            data = json.load(f)

        assert data["reviewed_files"] == []
        assert data["completed_files"] == []
        assert data["skipped_files"] == []

    def test_save_session_handles_missing_directory(self, temp_dir, temp_db):
        """Test that save_session handles missing scan directory gracefully."""
        scan_dir = temp_dir / "nonexistent_scan"
        # Don't create the directory

        session_start = datetime(2024, 1, 15, 10, 0, 0)

        # Should not raise exception (logs error internally)
        save_session(
            scan_dir,
            session_start,
            reviewed_files=["test.txt"],
            completed_files=[],
            skipped_files=[]
        )

        # JSON file should not exist
        session_file = scan_dir / ".session.json"
        assert not session_file.exists()


class TestLoadSession:
    """Tests for load_session function."""

    def test_load_session_success(self, temp_dir):
        """Test loading valid session file."""
        scan_dir = temp_dir / "test_scan"
        scan_dir.mkdir()

        # Create session file
        session_data = {
            "scan_dir": str(scan_dir),
            "session_start": "2024-01-15T10:30:00",
            "reviewed_files": ["file1.txt", "file2.txt"],
            "completed_files": ["file3.txt"],
            "skipped_files": ["empty.txt"],
            "tool_executions": 5,
            "cve_extractions": 2,
            "last_updated": "2024-01-15T11:00:00"
        }

        session_file = scan_dir / ".session.json"
        with open(session_file, "w") as f:
            json.dump(session_data, f)

        # Load session
        state = load_session(scan_dir)

        assert state is not None
        assert state.scan_dir == str(scan_dir)
        assert len(state.reviewed_files) == 2
        assert len(state.completed_files) == 1
        assert state.tool_executions == 5
        assert state.cve_extractions == 2

    def test_load_session_nonexistent_file(self, temp_dir):
        """Test loading when session file doesn't exist."""
        scan_dir = temp_dir / "no_session_scan"
        scan_dir.mkdir()

        state = load_session(scan_dir)

        assert state is None

    def test_load_session_invalid_json(self, temp_dir):
        """Test loading corrupted session file."""
        scan_dir = temp_dir / "corrupt_scan"
        scan_dir.mkdir()

        session_file = scan_dir / ".session.json"
        with open(session_file, "w") as f:
            f.write("{ invalid json }")

        state = load_session(scan_dir)

        assert state is None

    def test_load_session_missing_fields(self, temp_dir):
        """Test loading session file with missing required fields."""
        scan_dir = temp_dir / "incomplete_scan"
        scan_dir.mkdir()

        # Create incomplete session data
        session_data = {
            "scan_dir": str(scan_dir),
            "session_start": "2024-01-15T10:00:00"
            # Missing other required fields
        }

        session_file = scan_dir / ".session.json"
        with open(session_file, "w") as f:
            json.dump(session_data, f)

        state = load_session(scan_dir)

        assert state is None

    def test_load_session_empty_file(self, temp_dir):
        """Test loading empty session file."""
        scan_dir = temp_dir / "empty_file_scan"
        scan_dir.mkdir()

        session_file = scan_dir / ".session.json"
        session_file.touch()  # Create empty file

        state = load_session(scan_dir)

        assert state is None


class TestDeleteSession:
    """Tests for delete_session function."""

    def test_delete_session_removes_json_file(self, temp_dir, temp_db):
        """Test that delete_session removes JSON file."""
        scan_dir = temp_dir / "test_scan"
        scan_dir.mkdir()

        # Create session
        session_start = datetime(2024, 1, 15, 10, 0, 0)
        save_session(
            scan_dir,
            session_start,
            reviewed_files=["f1.txt"],
            completed_files=[],
            skipped_files=[]
        )

        session_file = scan_dir / ".session.json"
        assert session_file.exists()

        # Delete session
        delete_session(scan_dir)

        # Verify JSON file removed
        assert not session_file.exists()

    def test_delete_session_ends_db_session(self, temp_dir, temp_db):
        """Test that delete_session marks database session as ended."""
        scan_dir = temp_dir / "test_scan"
        scan_dir.mkdir()

        # Create session
        session_start = datetime(2024, 1, 15, 10, 0, 0)
        save_session(
            scan_dir,
            session_start,
            reviewed_files=["f1.txt"],
            completed_files=[],
            skipped_files=[]
        )

        # Verify session is active
        cursor = temp_db.execute(
            """
            SELECT session_end FROM sessions s
            JOIN scans sc ON s.scan_id = sc.scan_id
            WHERE sc.scan_name = ?
            """,
            (scan_dir.name,)
        )
        row = cursor.fetchone()
        assert row["session_end"] is None

        # Delete session
        delete_session(scan_dir)

        # Verify session is ended
        cursor = temp_db.execute(
            """
            SELECT session_end, duration_seconds FROM sessions s
            JOIN scans sc ON s.scan_id = sc.scan_id
            WHERE sc.scan_name = ?
            """,
            (scan_dir.name,)
        )
        row = cursor.fetchone()
        assert row["session_end"] is not None
        assert row["duration_seconds"] is not None
        assert row["duration_seconds"] >= 0

    def test_delete_session_no_json_file(self, temp_dir, temp_db):
        """Test delete_session when JSON file doesn't exist."""
        scan_dir = temp_dir / "no_file_scan"
        scan_dir.mkdir()

        # Should not raise exception
        delete_session(scan_dir)

    def test_delete_session_no_db_session(self, temp_dir, temp_db):
        """Test delete_session when no database session exists."""
        scan_dir = temp_dir / "no_db_scan"
        scan_dir.mkdir()

        # Create only JSON file (no DB session)
        session_file = scan_dir / ".session.json"
        session_data = {
            "scan_dir": str(scan_dir),
            "session_start": "2024-01-15T10:00:00",
            "reviewed_files": [],
            "completed_files": [],
            "skipped_files": [],
            "tool_executions": 0,
            "cve_extractions": 0,
            "last_updated": "2024-01-15T10:00:00"
        }
        with open(session_file, "w") as f:
            json.dump(session_data, f)

        # Should not raise exception
        delete_session(scan_dir)

        # JSON file should be removed
        assert not session_file.exists()


class TestSessionLifecycle:
    """Integration tests for complete session lifecycle."""

    def test_complete_session_lifecycle(self, temp_dir, temp_db):
        """Test complete session lifecycle: save → load → update → delete."""
        scan_dir = temp_dir / "lifecycle_scan"
        scan_dir.mkdir()

        session_start = datetime(2024, 1, 15, 10, 0, 0)

        # 1. Create initial session
        save_session(
            scan_dir,
            session_start,
            reviewed_files=["f1.txt"],
            completed_files=[],
            skipped_files=[],
            tool_executions=1,
            cve_extractions=0
        )

        # 2. Load session
        state = load_session(scan_dir)
        assert state is not None
        assert len(state.reviewed_files) == 1
        assert state.tool_executions == 1

        # 3. Update session
        save_session(
            scan_dir,
            session_start,
            reviewed_files=["f1.txt", "f2.txt", "f3.txt"],
            completed_files=["f4.txt", "f5.txt"],
            skipped_files=["empty.txt"],
            tool_executions=8,
            cve_extractions=3
        )

        # 4. Load updated session
        state = load_session(scan_dir)
        assert state is not None
        assert len(state.reviewed_files) == 3
        assert len(state.completed_files) == 2
        assert len(state.skipped_files) == 1
        assert state.tool_executions == 8
        assert state.cve_extractions == 3

        # 5. Verify database has updated counts
        cursor = temp_db.execute(
            """
            SELECT files_reviewed, files_completed, tools_executed, cves_extracted
            FROM sessions s
            JOIN scans sc ON s.scan_id = sc.scan_id
            WHERE sc.scan_name = ?
            """,
            (scan_dir.name,)
        )
        row = cursor.fetchone()
        assert row["files_reviewed"] == 3
        assert row["files_completed"] == 2
        assert row["tools_executed"] == 8
        assert row["cves_extracted"] == 3

        # 6. Delete session
        delete_session(scan_dir)

        # 7. Verify cleanup
        state = load_session(scan_dir)
        assert state is None

        session_file = scan_dir / ".session.json"
        assert not session_file.exists()

        # Verify database session is marked ended
        cursor = temp_db.execute(
            """
            SELECT session_end FROM sessions s
            JOIN scans sc ON s.scan_id = sc.scan_id
            WHERE sc.scan_name = ?
            """,
            (scan_dir.name,)
        )
        row = cursor.fetchone()
        assert row["session_end"] is not None

    def test_multiple_sessions_for_same_scan(self, temp_dir, temp_db):
        """Test multiple sequential sessions for the same scan."""
        scan_dir = temp_dir / "multi_session_scan"
        scan_dir.mkdir()

        # Session 1
        session1_start = datetime(2024, 1, 15, 10, 0, 0)
        save_session(
            scan_dir,
            session1_start,
            reviewed_files=["f1.txt"],
            completed_files=[],
            skipped_files=[]
        )
        delete_session(scan_dir)

        # Session 2
        session2_start = datetime(2024, 1, 15, 14, 0, 0)
        save_session(
            scan_dir,
            session2_start,
            reviewed_files=["f2.txt", "f3.txt"],
            completed_files=["f1.txt"],
            skipped_files=[]
        )
        delete_session(scan_dir)

        # Verify both sessions in database
        cursor = temp_db.execute(
            """
            SELECT COUNT(*) as count FROM sessions s
            JOIN scans sc ON s.scan_id = sc.scan_id
            WHERE sc.scan_name = ?
            """,
            (scan_dir.name,)
        )
        row = cursor.fetchone()
        assert row["count"] == 2

        # Verify both sessions have end times
        cursor = temp_db.execute(
            """
            SELECT COUNT(*) as ended_count FROM sessions s
            JOIN scans sc ON s.scan_id = sc.scan_id
            WHERE sc.scan_name = ? AND s.session_end IS NOT NULL
            """,
            (scan_dir.name,)
        )
        row = cursor.fetchone()
        assert row["ended_count"] == 2
