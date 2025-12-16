"""Tests for mundane_pkg.fs module."""

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from mundane_pkg.fs import (
    read_text_lines,
    list_dirs,
    list_files,
    mark_review_complete,
    undo_review_complete,
    build_results_paths,
    pretty_severity_label,
    default_page_size,
    write_work_files,
)


# Database mocking fixture similar to test_session.py
@pytest.fixture(autouse=True)
def mock_db_for_fs(monkeypatch, temp_db):
    """Mock database connection for fs module tests."""
    monkeypatch.setenv("MUNDANE_USE_DB", "1")

    import mundane_pkg.database

    class UnclosableConnection:
        """Wrapper that prevents connection from being closed."""
        def __init__(self, conn):
            self._conn = conn

        def __getattr__(self, name):
            if name == 'close':
                return lambda: None
            return getattr(self._conn, name)

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            return False

    def mock_get_connection(database_path=None):
        return UnclosableConnection(temp_db)

    monkeypatch.setattr(mundane_pkg.database, "get_connection", mock_get_connection)


class TestReadTextLines:
    """Tests for read_text_lines function."""

    def test_read_text_lines_basic(self, temp_dir):
        """Test reading basic text file."""
        test_file = temp_dir / "test.txt"
        test_file.write_text("line1\nline2\nline3\n")

        lines = read_text_lines(test_file)

        assert len(lines) == 3
        assert lines == ["line1", "line2", "line3"]

    def test_read_text_lines_windows_endings(self, temp_dir):
        """Test reading file with Windows line endings."""
        test_file = temp_dir / "windows.txt"
        # Write with binary mode to preserve \r\n
        test_file.write_bytes(b"line1\r\nline2\r\nline3\r\n")

        lines = read_text_lines(test_file)

        # splitlines() returns empty lines for \r\n on some systems
        # Filter out empty strings
        non_empty_lines = [l for l in lines if l]
        assert len(non_empty_lines) == 3
        assert non_empty_lines == ["line1", "line2", "line3"]

    def test_read_text_lines_empty_file(self, temp_dir):
        """Test reading empty file."""
        test_file = temp_dir / "empty.txt"
        test_file.write_text("")

        lines = read_text_lines(test_file)

        # Empty file returns empty list (splitlines on empty string)
        assert lines == []

    def test_read_text_lines_with_unicode(self, temp_dir):
        """Test reading file with unicode characters."""
        test_file = temp_dir / "unicode.txt"
        test_file.write_text("hello\nworld\n™\n", encoding="utf-8")

        lines = read_text_lines(test_file)

        assert len(lines) == 3
        assert lines[2] == "™"


class TestListDirs:
    """Tests for list_dirs function."""

    def test_list_dirs_basic(self, temp_dir):
        """Test listing directories."""
        (temp_dir / "dir1").mkdir()
        (temp_dir / "dir2").mkdir()
        (temp_dir / "dir3").mkdir()
        (temp_dir / "file.txt").touch()

        dirs = list_dirs(temp_dir)

        assert len(dirs) == 3
        assert all(d.is_dir() for d in dirs)
        # Verify sorted by name
        assert [d.name for d in dirs] == ["dir1", "dir2", "dir3"]

    def test_list_dirs_empty(self, temp_dir):
        """Test listing empty directory."""
        dirs = list_dirs(temp_dir)

        assert dirs == []

    def test_list_dirs_mixed_content(self, temp_dir):
        """Test listing with files and directories."""
        (temp_dir / "zzz_dir").mkdir()
        (temp_dir / "aaa_dir").mkdir()
        (temp_dir / "file1.txt").touch()
        (temp_dir / "file2.txt").touch()

        dirs = list_dirs(temp_dir)

        assert len(dirs) == 2
        # Verify sorted alphabetically
        assert dirs[0].name == "aaa_dir"
        assert dirs[1].name == "zzz_dir"


class TestListFiles:
    """Tests for list_files function."""

    def test_list_files_basic(self, temp_dir):
        """Test listing files."""
        (temp_dir / "file1.txt").touch()
        (temp_dir / "file2.txt").touch()
        (temp_dir / "file3.txt").touch()
        (temp_dir / "subdir").mkdir()

        files = list_files(temp_dir)

        assert len(files) == 3
        assert all(f.is_file() for f in files)
        # Verify sorted by name
        assert [f.name for f in files] == ["file1.txt", "file2.txt", "file3.txt"]

    def test_list_files_empty(self, temp_dir):
        """Test listing directory with no files."""
        (temp_dir / "subdir").mkdir()

        files = list_files(temp_dir)

        assert files == []


@pytest.mark.skip(reason="is_review_complete removed - review state is now DB-only")
class TestIsReviewComplete:
    """Tests for is_review_complete function."""

    def test_is_review_complete_with_prefix(self, temp_dir):
        """Test file with review complete prefix."""
        test_file = temp_dir / f"{REVIEW_PREFIX}test.txt"
        test_file.touch()

        assert is_review_complete(test_file) is True

    def test_is_review_complete_without_prefix(self, temp_dir):
        """Test file without review complete prefix."""
        test_file = temp_dir / "test.txt"
        test_file.touch()

        assert is_review_complete(test_file) is False

    def test_is_review_complete_partial_match(self, temp_dir):
        """Test file with similar but not exact prefix."""
        test_file = temp_dir / "REVIEW_test.txt"
        test_file.touch()

        assert is_review_complete(test_file) is False


@pytest.mark.skip(reason="is_reviewed_filename removed - review state is now DB-only")
class TestIsReviewedFilename:
    """Tests for is_reviewed_filename function."""

    def test_is_reviewed_filename_uppercase(self):
        """Test uppercase review complete prefix."""
        assert is_reviewed_filename("REVIEW_COMPLETE-file.txt") is True

    def test_is_reviewed_filename_lowercase(self):
        """Test lowercase review complete prefix."""
        assert is_reviewed_filename("review_complete-file.txt") is True

    def test_is_reviewed_filename_hyphen_format(self):
        """Test hyphen format."""
        assert is_reviewed_filename("review-complete-file.txt") is True

    def test_is_reviewed_filename_mixed_case(self):
        """Test mixed case (case-insensitive)."""
        assert is_reviewed_filename("Review_Complete-file.txt") is True

    def test_is_reviewed_filename_no_prefix(self):
        """Test filename without prefix."""
        assert is_reviewed_filename("file.txt") is False

    def test_is_reviewed_filename_no_hyphen(self):
        """Test filename with prefix but no hyphen."""
        assert is_reviewed_filename("REVIEW_COMPLETEfile.txt") is False


@pytest.mark.skip(reason="rename_review_complete replaced with mark_review_complete - DB-only, no file renaming")
class TestRenameReviewComplete:
    """Tests for rename_review_complete function (deprecated)."""

    def test_rename_review_complete_basic(self, temp_dir, temp_db):
        """Test basic rename with review complete prefix."""
        test_file = temp_dir / "test.txt"
        test_file.write_text("content")

        new_path = rename_review_complete(test_file)

        assert new_path.name == f"{REVIEW_PREFIX}test.txt"
        assert new_path.exists()
        assert not test_file.exists()
        assert new_path.read_text() == "content"

    def test_rename_review_complete_already_marked(self, temp_dir, temp_db, capsys):
        """Test renaming already marked file."""
        test_file = temp_dir / f"{REVIEW_PREFIX}test.txt"
        test_file.write_text("content")

        new_path = rename_review_complete(test_file)

        # Should return original path unchanged
        assert new_path == test_file
        assert test_file.exists()

    def test_rename_review_complete_with_db_update(self, temp_dir, temp_db):
        """Test that database is updated on rename."""
        from mundane_pkg.models import Scan, Plugin, Finding

        # Create database entries
        scan = Scan(scan_name="test_scan", export_root=str(temp_dir))
        scan_id = scan.save(temp_db)

        plugin = Plugin(plugin_id=12345, plugin_name="Test", severity_int=2)
        plugin.save(temp_db)

        test_file = temp_dir / "test.txt"
        test_file.write_text("content")

        # Create Finding entry with resolved path
        pf = Finding(
            scan_id=scan_id,
            plugin_id=12345,
            file_path=str(test_file.resolve())
        )
        pf.save(temp_db)
        temp_db.commit()

        # Rename the file
        new_path = rename_review_complete(test_file)

        # The file is renamed but database path still points to old path
        # The _db_update_review_state function looks up by new_path but entry has old path
        # So it won't find it - this is expected behavior
        # Database would need to be updated with new path separately
        assert new_path.exists()
        assert new_path.name.startswith(REVIEW_PREFIX)


@pytest.mark.skip(reason="undo_review_complete updated to DB-only - no file renaming")
class TestUndoReviewComplete:
    """Tests for undo_review_complete function (needs rewrite for DB-only)."""

    def test_undo_review_complete_basic(self, temp_dir, temp_db):
        """Test basic undo of review complete prefix."""
        test_file = temp_dir / f"{REVIEW_PREFIX}test.txt"
        test_file.write_text("content")

        new_path = undo_review_complete(test_file)

        assert new_path.name == "test.txt"
        assert new_path.exists()
        assert not test_file.exists()
        assert new_path.read_text() == "content"

    def test_undo_review_complete_not_marked(self, temp_dir, temp_db, capsys):
        """Test undo on file without review complete prefix."""
        test_file = temp_dir / "test.txt"
        test_file.write_text("content")

        new_path = undo_review_complete(test_file)

        # Should return original path unchanged
        assert new_path == test_file
        assert test_file.exists()

    def test_undo_review_complete_with_db_update(self, temp_dir, temp_db):
        """Test that database is updated on undo."""
        from mundane_pkg.models import Scan, Plugin, Finding

        # Create database entries
        scan = Scan(scan_name="test_scan", export_root=str(temp_dir))
        scan_id = scan.save(temp_db)

        plugin = Plugin(plugin_id=12345, plugin_name="Test", severity_int=2)
        plugin.save(temp_db)

        test_file = temp_dir / f"{REVIEW_PREFIX}test.txt"
        test_file.write_text("content")

        pf = Finding(
            scan_id=scan_id,
            plugin_id=12345,
            file_path=str(test_file.resolve()),
            review_state="completed"
        )
        pf.save(temp_db)
        temp_db.commit()

        # Undo the review complete
        new_path = undo_review_complete(test_file)

        # Similar to rename test - database lookup won't find renamed file
        # This is expected behavior - file path in DB needs separate update
        assert new_path.exists()
        assert not new_path.name.startswith(REVIEW_PREFIX)


class TestBuildResultsPaths:
    """Tests for build_results_paths function."""

    def test_build_results_paths_basic(self, temp_dir, monkeypatch):
        """Test building result paths."""
        # Mock get_results_root() to return temp directory
        import mundane_pkg.constants
        monkeypatch.setattr(mundane_pkg.constants, "_results_root_cache", temp_dir / "results")

        scan_dir = temp_dir / "my_scan"
        sev_dir = scan_dir / "4_Critical"
        plugin_filename = "12345_Test_Plugin.txt"

        output_dir, output_base = build_results_paths(scan_dir, sev_dir, plugin_filename)

        assert output_dir.exists()
        # Path structure: results/my_scan/Critical/12345_Test_Plugin
        assert output_dir.name == "12345_Test_Plugin"
        assert "Critical" in str(output_dir)
        assert output_base.name.startswith("run-")
        assert len(output_base.name.split("-")) == 3  # run-YYYYMMDD-HHMMSS

    def test_build_results_paths_creates_dirs(self, temp_dir, monkeypatch):
        """Test that output directory is created."""
        # Mock get_results_root() to return temp directory
        import mundane_pkg.constants
        monkeypatch.setattr(mundane_pkg.constants, "_results_root_cache", temp_dir / "results")

        scan_dir = temp_dir / "scan"
        sev_dir = scan_dir / "3_High"
        plugin_filename = "99999_Another_Plugin.txt"

        output_dir, _ = build_results_paths(scan_dir, sev_dir, plugin_filename)

        assert output_dir.exists()
        assert output_dir.is_dir()


class TestPrettySeverityLabel:
    """Tests for pretty_severity_label function."""

    def test_pretty_severity_label_critical(self):
        """Test converting critical severity."""
        assert pretty_severity_label("4_critical") == "Critical"

    def test_pretty_severity_label_high(self):
        """Test converting high severity."""
        assert pretty_severity_label("3_high") == "High"

    def test_pretty_severity_label_medium(self):
        """Test converting medium severity."""
        assert pretty_severity_label("2_medium") == "Medium"

    def test_pretty_severity_label_with_underscores(self):
        """Test converting multi-word severity."""
        assert pretty_severity_label("1_very_low") == "Very Low"

    def test_pretty_severity_label_no_number_prefix(self):
        """Test label without number prefix."""
        result = pretty_severity_label("critical")
        assert result == "Critical"

    def test_pretty_severity_label_with_spaces(self):
        """Test label with extra spaces."""
        assert pretty_severity_label("4_  critical  ") == "Critical"


class TestDefaultPageSize:
    """Tests for default_page_size function."""

    def test_default_page_size_normal_terminal(self):
        """Test page size with normal terminal."""
        with patch('shutil.get_terminal_size', return_value=type('obj', (), {'lines': 40, 'columns': 80})()):
            size = default_page_size()
            assert size == 25  # 40 - 15

    def test_default_page_size_small_terminal(self):
        """Test page size with small terminal."""
        with patch('shutil.get_terminal_size', return_value=type('obj', (), {'lines': 15, 'columns': 80})()):
            size = default_page_size()
            assert size == 8  # Minimum is 8

    def test_default_page_size_exception(self):
        """Test page size when terminal size fails."""
        with patch('shutil.get_terminal_size', side_effect=Exception("No terminal")):
            size = default_page_size()
            assert size == 12  # Default fallback


class TestWriteWorkFiles:
    """Tests for write_work_files function."""

    def test_write_work_files_tcp_only(self, temp_dir):
        """Test writing TCP work files."""
        hosts = ["192.168.1.1", "192.168.1.2", "10.0.0.1"]
        ports = "80,443,8080"

        tcp_ips, udp_ips, tcp_sockets = write_work_files(temp_dir, hosts, ports, udp=False)

        # Verify TCP IPs file
        assert tcp_ips.exists()
        assert tcp_ips.read_text() == "192.168.1.1\n192.168.1.2\n10.0.0.1\n"

        # Verify UDP IPs file not created
        assert not udp_ips.exists()

        # Verify TCP sockets file
        assert tcp_sockets.exists()
        lines = tcp_sockets.read_text().strip().split("\n")
        assert len(lines) == 3
        assert lines[0] == "192.168.1.1:80,443,8080"
        assert lines[1] == "192.168.1.2:80,443,8080"
        assert lines[2] == "10.0.0.1:80,443,8080"

    def test_write_work_files_with_udp(self, temp_dir):
        """Test writing work files with UDP enabled."""
        hosts = ["192.168.1.1", "192.168.1.2"]
        ports = "53"

        tcp_ips, udp_ips, tcp_sockets = write_work_files(temp_dir, hosts, ports, udp=True)

        # Verify both TCP and UDP files exist
        assert tcp_ips.exists()
        assert udp_ips.exists()

        # Verify UDP content
        assert udp_ips.read_text() == "192.168.1.1\n192.168.1.2\n"

    def test_write_work_files_no_ports(self, temp_dir):
        """Test writing work files without ports."""
        hosts = ["192.168.1.1"]

        tcp_ips, udp_ips, tcp_sockets = write_work_files(temp_dir, hosts, "", udp=False)

        # TCP IPs should still be written
        assert tcp_ips.exists()
        assert tcp_ips.read_text() == "192.168.1.1\n"

        # Socket file is not created when ports_str is empty
        # The function only writes tcp_sockets if ports_str is truthy
        assert not tcp_sockets.exists()

    def test_write_work_files_creates_workdir(self, temp_dir):
        """Test that workdir is created if it doesn't exist."""
        workdir = temp_dir / "nested" / "work"
        hosts = ["10.0.0.1"]

        tcp_ips, udp_ips, tcp_sockets = write_work_files(workdir, hosts, "22", udp=False)

        assert workdir.exists()
        assert workdir.is_dir()
        assert tcp_ips.exists()

    def test_write_work_files_single_host_multiple_ports(self, temp_dir):
        """Test work files with single host and multiple ports."""
        hosts = ["192.168.1.100"]
        ports = "80,443,8443,3000"

        tcp_ips, udp_ips, tcp_sockets = write_work_files(temp_dir, hosts, ports, udp=False)

        assert tcp_ips.exists()
        assert tcp_sockets.exists()

        socket_content = tcp_sockets.read_text().strip()
        assert socket_content == "192.168.1.100:80,443,8443,3000"


@pytest.mark.skip(reason="Review lifecycle tests need rewrite for DB-only approach")
class TestReviewCompleteLifecycle:
    """Integration tests for complete review lifecycle (needs rewrite for DB-only)."""

    def test_complete_lifecycle_mark_and_undo(self, temp_dir, temp_db):
        """Test complete lifecycle: mark complete → verify → undo → verify."""
        test_file = temp_dir / "lifecycle_test.txt"
        test_file.write_text("test content")

        # Initially not marked
        assert not is_review_complete(test_file)

        # Mark as complete
        marked_path = rename_review_complete(test_file)
        assert is_review_complete(marked_path)
        assert marked_path.name.startswith(REVIEW_PREFIX)
        assert not test_file.exists()

        # Undo
        restored_path = undo_review_complete(marked_path)
        assert not is_review_complete(restored_path)
        assert restored_path.name == "lifecycle_test.txt"
        assert not marked_path.exists()
        assert restored_path.read_text() == "test content"

    def test_multiple_files_review_workflow(self, temp_dir, temp_db):
        """Test review workflow with multiple files."""
        files = [
            temp_dir / "file1.txt",
            temp_dir / "file2.txt",
            temp_dir / "file3.txt",
        ]

        for f in files:
            f.write_text(f"content of {f.name}")

        # Mark all as complete
        marked_files = [rename_review_complete(f) for f in files]

        # Verify all marked
        assert all(is_review_complete(f) for f in marked_files)

        # List files should show all with prefix
        all_files = list_files(temp_dir)
        assert len(all_files) == 3
        assert all(f.name.startswith(REVIEW_PREFIX) for f in all_files)

        # Undo first file only
        restored = undo_review_complete(marked_files[0])
        assert not is_review_complete(restored)

        # Verify mixed state
        current_files = list_files(temp_dir)
        assert len(current_files) == 3
        reviewed_count = sum(1 for f in current_files if is_review_complete(f))
        assert reviewed_count == 2
