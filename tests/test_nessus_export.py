"""Tests for mundane_pkg.nessus_export module."""

from pathlib import Path

import pytest

from mundane_pkg.nessus_export import (
    export_nessus_plugins,
    ExportResult,
)


@pytest.fixture
def minimal_nessus_fixture() -> Path:
    """Get path to minimal.nessus test fixture.

    Returns:
        Path: Path to minimal.nessus fixture file
    """
    fixture_path = Path(__file__).parent / "fixtures" / "minimal.nessus"
    if not fixture_path.exists():
        pytest.skip("minimal.nessus fixture not found")
    return fixture_path


class TestNessusExport:
    """Tests for Nessus export functionality."""

    @pytest.mark.integration
    def test_export_creates_directory_structure(self, minimal_nessus_fixture, temp_dir):
        """Test that export creates proper directory structure."""
        result = export_nessus_plugins(
            minimal_nessus_fixture,
            temp_dir,
            use_database=False
        )

        # Check scan directory exists
        scan_dir = temp_dir / "Minimal_Test_Scan"
        assert scan_dir.exists()
        assert scan_dir.is_dir()

        # Check severity directories
        assert (scan_dir / "1_High").exists()
        assert (scan_dir / "2_Medium").exists()
        assert (scan_dir / "4_Info").exists()

    @pytest.mark.integration
    def test_export_creates_plugin_files(self, minimal_nessus_fixture, temp_dir):
        """Test that plugin files are created."""
        result = export_nessus_plugins(
            minimal_nessus_fixture,
            temp_dir,
            use_database=False
        )

        scan_dir = temp_dir / "Minimal_Test_Scan"

        # Should have files for each unique plugin
        medium_dir = scan_dir / "2_Medium"
        assert (medium_dir / "12345_Test_Medium_Plugin.txt").exists()

        high_dir = scan_dir / "1_High"
        assert (high_dir / "54321_SSH_Server_Version.txt").exists()

        info_dir = scan_dir / "4_Info"
        assert (info_dir / "10107_HTTP_Server_Type_and_Version.txt").exists()

    @pytest.mark.integration
    def test_export_file_content_format(self, minimal_nessus_fixture, temp_dir):
        """Test that plugin file content is correctly formatted."""
        result = export_nessus_plugins(
            minimal_nessus_fixture,
            temp_dir,
            include_ports=True,
            use_database=False
        )

        scan_dir = temp_dir / "Minimal_Test_Scan"
        plugin_file = scan_dir / "2_Medium" / "12345_Test_Medium_Plugin.txt"

        content = plugin_file.read_text()

        # Should have both hosts (IPs before hostnames)
        assert "192.168.1.1:80" in content
        assert "192.168.1.2:80" in content

        # IPs should come before hostnames
        lines = [line.strip() for line in content.split('\n') if line.strip()]
        ip_indices = [i for i, line in enumerate(lines) if line.startswith("192.168")]
        hostname_indices = [i for i, line in enumerate(lines) if "test.local" in line]

        if ip_indices and hostname_indices:
            assert max(ip_indices) < min(hostname_indices), "IPs should come before hostnames"

    @pytest.mark.integration
    def test_export_without_ports(self, minimal_nessus_fixture, temp_dir):
        """Test export with ports disabled."""
        result = export_nessus_plugins(
            minimal_nessus_fixture,
            temp_dir,
            include_ports=False,
            use_database=False
        )

        scan_dir = temp_dir / "Minimal_Test_Scan"
        plugin_file = scan_dir / "2_Medium" / "12345_Test_Medium_Plugin.txt"

        content = plugin_file.read_text()

        # Should have hosts without ports
        assert "192.168.1.1\n" in content or "192.168.1.1" in content.split('\n')
        assert "192.168.1.1:80" not in content

    @pytest.mark.integration
    def test_export_result_structure(self, minimal_nessus_fixture, temp_dir):
        """Test that ExportResult contains correct data."""
        result = export_nessus_plugins(
            minimal_nessus_fixture,
            temp_dir,
            use_database=False
        )

        assert isinstance(result, ExportResult)
        assert result.scan_name == "Minimal_Test_Scan"
        assert result.total_plugins == 3  # 3 unique plugins
        assert result.base_scan_dir.exists()

        # Check severity counts
        assert result.by_severity["High"] == 1
        assert result.by_severity["Medium"] == 1
        assert result.by_severity["Info"] == 1

    @pytest.mark.integration
    def test_export_host_deduplication(self, minimal_nessus_fixture, temp_dir):
        """Test that duplicate host:port entries are deduplicated."""
        result = export_nessus_plugins(
            minimal_nessus_fixture,
            temp_dir,
            use_database=False
        )

        scan_dir = temp_dir / "Minimal_Test_Scan"
        plugin_file = scan_dir / "2_Medium" / "12345_Test_Medium_Plugin.txt"

        content = plugin_file.read_text()
        lines = [line.strip() for line in content.split('\n') if line.strip()]

        # Should not have duplicates
        assert len(lines) == len(set(lines))

    @pytest.mark.integration
    def test_export_handles_special_characters_in_name(self, sample_nessus_xml, temp_dir):
        """Test that special characters in plugin names are sanitized."""
        # This test uses the fixture from conftest.py
        result = export_nessus_plugins(
            sample_nessus_xml,
            temp_dir,
            use_database=False
        )

        # Check that files were created with sanitized names
        scan_dir = temp_dir / "Test_Scan"
        assert scan_dir.exists()

        # Find created files
        files = list(scan_dir.rglob("*.txt"))
        assert len(files) > 0

        # Filenames should not contain invalid characters
        for f in files:
            assert "/" not in f.name
            assert "\\" not in f.name
            assert ":" not in f.stem  # Stem excludes extension

    @pytest.mark.slow
    @pytest.mark.integration
    def test_export_large_scan(self, goad_nessus_fixture, temp_dir):
        """Test exporting large real-world scan (GOAD)."""
        result = export_nessus_plugins(
            goad_nessus_fixture,
            temp_dir,
            use_database=False
        )

        assert result.total_plugins > 0
        assert result.base_scan_dir.exists()

        # Verify files were created
        txt_files = list(result.base_scan_dir.rglob("*.txt"))
        assert len(txt_files) == result.total_plugins


class TestNessusExportDatabaseIntegration:
    """Tests for Nessus export with database integration."""

    @pytest.mark.integration
    def test_export_populates_database(self, minimal_nessus_fixture, temp_dir, temp_db):
        """Test that export writes to database."""
        from mundane_pkg.database import get_connection
        from mundane_pkg import database

        # Temporarily override database path for testing
        original_path = database.DATABASE_PATH
        test_db_path = temp_dir / "test.db"
        database.DATABASE_PATH = test_db_path

        try:
            result = export_nessus_plugins(
                minimal_nessus_fixture,
                temp_dir,
                use_database=True
            )

            # Check database was created
            assert test_db_path.exists()

            # Verify data
            conn = get_connection(test_db_path)

            # Check scan
            cursor = conn.execute("SELECT scan_name FROM scans")
            scan = cursor.fetchone()
            assert scan["scan_name"] == "Minimal_Test_Scan"

            # Check plugins
            cursor = conn.execute("SELECT COUNT(*) as count FROM plugins")
            plugin_count = cursor.fetchone()["count"]
            assert plugin_count == 3

            # Check plugin files
            cursor = conn.execute("SELECT COUNT(*) as count FROM plugin_files")
            file_count = cursor.fetchone()["count"]
            assert file_count == 3

            # Check hosts
            cursor = conn.execute("SELECT COUNT(*) as count FROM plugin_file_hosts")
            host_count = cursor.fetchone()["count"]
            assert host_count > 0  # Should have multiple host entries

            conn.close()

        finally:
            # Restore original path
            database.DATABASE_PATH = original_path

    @pytest.mark.integration
    def test_export_plugin_metadata(self, minimal_nessus_fixture, temp_dir):
        """Test that plugin metadata is correctly stored."""
        from mundane_pkg.database import get_connection
        from mundane_pkg import database

        original_path = database.DATABASE_PATH
        test_db_path = temp_dir / "test.db"
        database.DATABASE_PATH = test_db_path

        try:
            result = export_nessus_plugins(
                minimal_nessus_fixture,
                temp_dir,
                use_database=True
            )

            conn = get_connection(test_db_path)

            # Check specific plugin
            cursor = conn.execute(
                """SELECT plugin_name, severity_int, cvss3_score
                   FROM plugins WHERE plugin_id = ?""",
                (12345,)
            )
            plugin = cursor.fetchone()

            assert plugin["plugin_name"] == "Test Medium Plugin"
            assert plugin["severity_int"] == 2  # Medium
            assert plugin["cvss3_score"] == 5.3

            conn.close()

        finally:
            database.DATABASE_PATH = original_path

    @pytest.mark.integration
    def test_export_host_ip_type_detection(self, minimal_nessus_fixture, temp_dir):
        """Test that IP types (IPv4/IPv6/hostname) are detected."""
        from mundane_pkg.database import get_connection
        from mundane_pkg import database

        original_path = database.DATABASE_PATH
        test_db_path = temp_dir / "test.db"
        database.DATABASE_PATH = test_db_path

        try:
            result = export_nessus_plugins(
                minimal_nessus_fixture,
                temp_dir,
                use_database=True
            )

            conn = get_connection(test_db_path)

            # Check IPv4 host
            cursor = conn.execute(
                """SELECT host, is_ipv4, is_ipv6
                   FROM plugin_file_hosts WHERE host = ?""",
                ("192.168.1.1",)
            )
            host = cursor.fetchone()
            if host:
                assert host["is_ipv4"] == 1
                assert host["is_ipv6"] == 0

            # Check hostname
            cursor = conn.execute(
                """SELECT host, is_ipv4, is_ipv6
                   FROM plugin_file_hosts WHERE host = ?""",
                ("test.local",)
            )
            host = cursor.fetchone()
            if host:
                assert host["is_ipv4"] == 0
                assert host["is_ipv6"] == 0

            conn.close()

        finally:
            database.DATABASE_PATH = original_path


class TestNessusExportEdgeCases:
    """Tests for edge cases in Nessus export."""

    def test_export_nonexistent_file(self, temp_dir):
        """Test exporting nonexistent file raises error."""
        nonexistent = temp_dir / "nonexistent.nessus"

        with pytest.raises(FileNotFoundError):
            export_nessus_plugins(nonexistent, temp_dir, use_database=False)

    def test_export_to_nonexistent_output_dir(self, minimal_nessus_fixture, temp_dir):
        """Test export creates output directory if missing."""
        output_dir = temp_dir / "new_dir" / "nested"

        result = export_nessus_plugins(
            minimal_nessus_fixture,
            output_dir,
            use_database=False
        )

        assert output_dir.exists()
        assert result.base_scan_dir.exists()

    @pytest.mark.integration
    def test_export_idempotent(self, minimal_nessus_fixture, temp_dir):
        """Test that running export twice handles existing files."""
        # First export
        result1 = export_nessus_plugins(
            minimal_nessus_fixture,
            temp_dir,
            use_database=False
        )

        # Second export (should handle existing directory)
        result2 = export_nessus_plugins(
            minimal_nessus_fixture,
            temp_dir,
            use_database=False
        )

        # Both should succeed
        assert result1.scan_name == result2.scan_name
        assert result1.total_plugins == result2.total_plugins
