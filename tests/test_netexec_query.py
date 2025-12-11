"""Tests for NetExec query module."""

import os
import pytest
from pathlib import Path
from unittest.mock import patch

from mundane_pkg.netexec_query import (
    get_netexec_workspace_path,
    check_netexec_available,
    query_finding_correlation,
    query_credential_details,
)


class TestWorkspacePath:
    """Test workspace path resolution with priority: config → env var → default."""

    def test_workspace_path_from_config(self, tmp_path, monkeypatch):
        """Test workspace path from config.yaml (highest priority)."""
        # Create a test workspace
        workspace = tmp_path / "netexec_workspace"
        workspace.mkdir()
        (workspace / "smb.db").touch()

        # Mock config to return our test workspace
        from mundane_pkg.config import MundaneConfig

        with patch("mundane_pkg.netexec_query.load_config") as mock_load:
            mock_load.return_value = MundaneConfig(
                netexec_workspace_path=str(workspace)
            )

            result = get_netexec_workspace_path()
            assert result == workspace

    def test_workspace_path_from_env_var(self, tmp_path, monkeypatch):
        """Test workspace path from NETEXEC_WORKSPACE env var (second priority)."""
        # Create a test workspace
        workspace = tmp_path / "netexec_workspace"
        workspace.mkdir()

        # Set env var
        monkeypatch.setenv("NETEXEC_WORKSPACE", str(workspace))

        # Mock config to return None (no config set)
        from mundane_pkg.config import MundaneConfig

        with patch("mundane_pkg.netexec_query.load_config") as mock_load:
            mock_load.return_value = MundaneConfig(netexec_workspace_path=None)

            result = get_netexec_workspace_path()
            assert result == workspace

    def test_workspace_path_default(self, tmp_path, monkeypatch):
        """Test default workspace path (lowest priority)."""
        # Mock home directory
        fake_home = tmp_path / "home"
        fake_home.mkdir()
        default_workspace = fake_home / ".nxc" / "workspaces" / "default"
        default_workspace.mkdir(parents=True)

        monkeypatch.setattr(Path, "home", lambda: fake_home)

        # Mock config to return None
        from mundane_pkg.config import MundaneConfig

        with patch("mundane_pkg.netexec_query.load_config") as mock_load:
            mock_load.return_value = MundaneConfig(netexec_workspace_path=None)

            # Unset env var
            monkeypatch.delenv("NETEXEC_WORKSPACE", raising=False)

            result = get_netexec_workspace_path()
            assert result == default_workspace

    def test_workspace_path_not_found(self, monkeypatch):
        """Test when no workspace exists."""
        # Mock config to return None
        from mundane_pkg.config import MundaneConfig

        with patch("mundane_pkg.netexec_query.load_config") as mock_load:
            mock_load.return_value = MundaneConfig(netexec_workspace_path=None)

            # Unset env var
            monkeypatch.delenv("NETEXEC_WORKSPACE", raising=False)

            # Mock home to return a non-existent path
            monkeypatch.setattr(
                Path, "home", lambda: Path("/nonexistent/home")
            )

            result = get_netexec_workspace_path()
            assert result is None


class TestNetExecAvailability:
    """Test NetExec availability checks."""

    def test_check_available_with_smb_db(self, tmp_path):
        """Test availability when SMB database exists."""
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        smb_db = workspace / "smb.db"
        smb_db.write_text("fake db content")

        with patch(
            "mundane_pkg.netexec_query.get_netexec_workspace_path"
        ) as mock_path:
            mock_path.return_value = workspace
            assert check_netexec_available() is True

    def test_check_not_available_no_workspace(self):
        """Test unavailability when workspace doesn't exist."""
        with patch(
            "mundane_pkg.netexec_query.get_netexec_workspace_path"
        ) as mock_path:
            mock_path.return_value = None
            assert check_netexec_available() is False

    def test_check_not_available_empty_workspace(self, tmp_path):
        """Test unavailability when workspace has no databases."""
        workspace = tmp_path / "workspace"
        workspace.mkdir()

        with patch(
            "mundane_pkg.netexec_query.get_netexec_workspace_path"
        ) as mock_path:
            mock_path.return_value = workspace
            assert check_netexec_available() is False

    def test_check_available_with_any_protocol(self, tmp_path):
        """Test availability with SSH database (not just SMB)."""
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        ssh_db = workspace / "ssh.db"
        ssh_db.write_text("fake db content")

        with patch(
            "mundane_pkg.netexec_query.get_netexec_workspace_path"
        ) as mock_path:
            mock_path.return_value = workspace
            assert check_netexec_available() is True


class TestQueryFindingCorrelation:
    """Test finding correlation queries."""

    def test_query_with_no_hosts(self):
        """Test query with empty host list."""
        result = query_finding_correlation([])

        assert result["hosts_with_data"] == 0
        assert result["total_hosts"] == 0
        assert result["protocols_tested"] == []
        assert result["credentials_count"] == 0
        assert result["admin_access_count"] == 0
        assert result["vulnerabilities"] == {}

    def test_query_with_no_workspace(self):
        """Test query when workspace doesn't exist."""
        with patch(
            "mundane_pkg.netexec_query.get_netexec_workspace_path"
        ) as mock_path:
            mock_path.return_value = None

            result = query_finding_correlation(["192.168.1.1"])

            assert result["hosts_with_data"] == 0
            assert result["total_hosts"] == 1
            assert result["protocols_tested"] == []

    def test_query_with_real_fixtures(self):
        """Test query with actual fixture databases."""
        # Use the test fixtures
        fixtures_path = Path(__file__).parent / "fixtures" / "netexec"

        if not fixtures_path.exists():
            pytest.skip("NetExec fixtures not found")

        with patch(
            "mundane_pkg.netexec_query.get_netexec_workspace_path"
        ) as mock_path:
            mock_path.return_value = fixtures_path

            # Query with test hosts (will return empty since DBs are empty)
            result = query_finding_correlation(["192.168.1.1", "192.168.1.2"])

            assert isinstance(result, dict)
            assert "hosts_with_data" in result
            assert "total_hosts" in result
            assert result["total_hosts"] == 2

    def test_query_handles_db_error_gracefully(self, tmp_path):
        """Test graceful handling of database errors."""
        workspace = tmp_path / "workspace"
        workspace.mkdir()

        # Create a corrupt database (empty file)
        smb_db = workspace / "smb.db"
        smb_db.write_bytes(b"")

        with patch(
            "mundane_pkg.netexec_query.get_netexec_workspace_path"
        ) as mock_path:
            mock_path.return_value = workspace

            # Should not raise exception, should return empty data
            result = query_finding_correlation(["192.168.1.1"])

            assert isinstance(result, dict)
            assert result["hosts_with_data"] == 0


class TestQueryCredentialDetails:
    """Test credential detail queries."""

    def test_query_with_no_hosts(self):
        """Test credential query with no hosts."""
        result = query_credential_details([], "smb")
        assert result == []

    def test_query_with_no_protocol(self):
        """Test credential query with no protocol."""
        result = query_credential_details(["192.168.1.1"], "")
        assert result == []

    def test_query_with_nonexistent_protocol(self, tmp_path):
        """Test credential query with non-existent protocol database."""
        workspace = tmp_path / "workspace"
        workspace.mkdir()

        with patch(
            "mundane_pkg.netexec_query.get_netexec_workspace_path"
        ) as mock_path:
            mock_path.return_value = workspace

            result = query_credential_details(["192.168.1.1"], "nonexistent")
            assert result == []

    def test_query_with_real_fixtures(self):
        """Test credential query with actual fixture databases."""
        fixtures_path = Path(__file__).parent / "fixtures" / "netexec"

        if not fixtures_path.exists():
            pytest.skip("NetExec fixtures not found")

        with patch(
            "mundane_pkg.netexec_query.get_netexec_workspace_path"
        ) as mock_path:
            mock_path.return_value = fixtures_path

            # Query with test hosts (will return empty since DBs are empty)
            result = query_credential_details(["192.168.1.1"], "smb")

            assert isinstance(result, list)


class TestEdgeCases:
    """Test edge cases and error conditions."""

    @pytest.mark.parametrize(
        "hosts,expected_total",
        [
            ([], 0),
            (["192.168.1.1"], 1),
            (["192.168.1.1", "192.168.1.1"], 2),  # Duplicates counted
            (["192.168.1.1", "192.168.1.2", "192.168.1.3"], 3),
        ],
    )
    def test_correlation_with_various_host_counts(self, hosts, expected_total):
        """Test correlation handles various host list sizes."""
        with patch(
            "mundane_pkg.netexec_query.get_netexec_workspace_path"
        ) as mock_path:
            mock_path.return_value = None  # No workspace

            result = query_finding_correlation(hosts)
            assert result["total_hosts"] == expected_total

    def test_query_with_special_characters_in_hosts(self, tmp_path):
        """Test query with special characters in host addresses."""
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        (workspace / "smb.db").touch()

        with patch(
            "mundane_pkg.netexec_query.get_netexec_workspace_path"
        ) as mock_path:
            mock_path.return_value = workspace

            # IPv6 address with brackets
            result = query_finding_correlation(["::1", "fe80::1"])
            assert isinstance(result, dict)

    def test_query_with_permission_error(self, tmp_path):
        """Test graceful handling of permission errors."""
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        smb_db = workspace / "smb.db"
        smb_db.write_text("test")

        with patch(
            "mundane_pkg.netexec_query.get_netexec_workspace_path"
        ) as mock_path:
            mock_path.return_value = workspace

            # Mock sqlite3.connect to raise PermissionError
            with patch("mundane_pkg.netexec_query.sqlite3.connect") as mock_connect:
                mock_connect.side_effect = PermissionError("Access denied")

                # Should not raise, should return empty data
                result = query_finding_correlation(["192.168.1.1"])
                assert result["hosts_with_data"] == 0
