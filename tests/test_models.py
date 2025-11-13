"""Tests for mundane_pkg.models module."""

import json
from datetime import datetime

import pytest

from mundane_pkg.models import (
    Scan,
    Plugin,
    PluginFile,
    ToolExecution,
    Artifact,
    now_iso,
)


class TestScanModel:
    """Tests for Scan model."""

    def test_scan_save_creates_record(self, temp_db):
        """Test saving a new scan."""
        scan = Scan(
            scan_name="test_scan",
            nessus_file_path="/tmp/test.nessus",
            export_root="/tmp/exports"
        )

        scan_id = scan.save(temp_db)

        assert scan_id is not None
        assert scan_id > 0

    def test_scan_get_by_name(self, temp_db):
        """Test retrieving scan by name."""
        # Create scan
        scan = Scan(
            scan_name="test_scan",
            nessus_file_path="/tmp/test.nessus",
            export_root="/tmp/exports"
        )
        scan.save(temp_db)

        # Retrieve it
        retrieved = Scan.get_by_name("test_scan", temp_db)

        assert retrieved is not None
        assert retrieved.scan_name == "test_scan"
        assert retrieved.nessus_file_path == "/tmp/test.nessus"

    def test_scan_get_by_name_nonexistent(self, temp_db):
        """Test retrieving nonexistent scan returns None."""
        result = Scan.get_by_name("nonexistent", temp_db)
        assert result is None

    def test_scan_get_by_id(self, temp_db):
        """Test retrieving scan by ID."""
        scan = Scan(scan_name="test_scan", export_root="/tmp")
        scan_id = scan.save(temp_db)

        retrieved = Scan.get_by_id(scan_id, temp_db)

        assert retrieved is not None
        assert retrieved.scan_id == scan_id
        assert retrieved.scan_name == "test_scan"

    def test_scan_update_existing(self, temp_db):
        """Test updating existing scan."""
        scan = Scan(scan_name="test_scan", export_root="/tmp")
        scan_id = scan.save(temp_db)

        # Update
        scan.scan_id = scan_id
        scan.nessus_file_hash = "abc123"
        scan.save(temp_db)

        # Retrieve and verify
        retrieved = Scan.get_by_id(scan_id, temp_db)
        assert retrieved.nessus_file_hash == "abc123"

    def test_scan_unique_constraint(self, temp_db):
        """Test that scan names must be unique."""
        scan1 = Scan(scan_name="test_scan", export_root="/tmp")
        scan1.save(temp_db)

        scan2 = Scan(scan_name="test_scan", export_root="/tmp2")

        with pytest.raises(Exception):  # Should raise IntegrityError
            scan2.save(temp_db)


class TestPluginModel:
    """Tests for Plugin model."""

    def test_plugin_save_creates_record(self, temp_db):
        """Test saving a new plugin."""
        plugin = Plugin(
            plugin_id=12345,
            plugin_name="Test Plugin",
            severity_int=2,
            cvss3_score=5.3
        )

        plugin.save(temp_db)

        # Verify saved
        cursor = temp_db.execute(
            "SELECT plugin_name FROM plugins WHERE plugin_id = ?",
            (12345,)
        )
        result = cursor.fetchone()
        assert result["plugin_name"] == "Test Plugin"

    def test_plugin_get_by_id(self, temp_db):
        """Test retrieving plugin by ID."""
        plugin = Plugin(
            plugin_id=12345,
            plugin_name="Test Plugin",
            severity_int=2
        )
        plugin.save(temp_db)

        retrieved = Plugin.get_by_id(12345, temp_db)

        assert retrieved is not None
        assert retrieved.plugin_id == 12345
        assert retrieved.plugin_name == "Test Plugin"

    def test_plugin_cve_list_serialization(self, temp_db):
        """Test CVE list is serialized to JSON."""
        plugin = Plugin(
            plugin_id=12345,
            plugin_name="Test Plugin",
            severity_int=2,
            cves=["CVE-2024-0001", "CVE-2024-0002"]
        )
        plugin.save(temp_db)

        # Check stored as JSON
        cursor = temp_db.execute(
            "SELECT cves FROM plugins WHERE plugin_id = ?",
            (12345,)
        )
        result = cursor.fetchone()
        cves = json.loads(result["cves"])
        assert cves == ["CVE-2024-0001", "CVE-2024-0002"]

    def test_plugin_update_with_cves(self, temp_db):
        """Test updating plugin with CVE list."""
        plugin = Plugin(
            plugin_id=12345,
            plugin_name="Test Plugin",
            severity_int=2
        )
        plugin.save(temp_db)

        # Update with CVEs
        plugin.cves = ["CVE-2024-0001"]
        plugin.save(temp_db)

        retrieved = Plugin.get_by_id(12345, temp_db)
        assert retrieved.cves == ["CVE-2024-0001"]


class TestPluginFileModel:
    """Tests for PluginFile model."""

    def test_plugin_file_save_creates_record(self, temp_db):
        """Test saving a new plugin file."""
        # Create dependencies
        scan = Scan(scan_name="test_scan", export_root="/tmp")
        scan_id = scan.save(temp_db)

        plugin = Plugin(plugin_id=12345, plugin_name="Test", severity_int=2)
        plugin.save(temp_db)

        # Create plugin file
        pf = PluginFile(
            scan_id=scan_id,
            plugin_id=12345,
            file_path="/tmp/test/plugin.txt",
            host_count=5
        )

        file_id = pf.save(temp_db)

        assert file_id is not None
        assert file_id > 0

    def test_plugin_file_get_by_path(self, temp_db):
        """Test retrieving plugin file by path."""
        # Setup
        scan = Scan(scan_name="test_scan", export_root="/tmp")
        scan_id = scan.save(temp_db)
        plugin = Plugin(plugin_id=12345, plugin_name="Test", severity_int=2)
        plugin.save(temp_db)

        pf = PluginFile(
            scan_id=scan_id,
            plugin_id=12345,
            file_path="/tmp/test/plugin.txt"
        )
        pf.save(temp_db)

        # Retrieve
        retrieved = PluginFile.get_by_path("/tmp/test/plugin.txt", temp_db)

        assert retrieved is not None
        assert retrieved.file_path == "/tmp/test/plugin.txt"

    def test_plugin_file_update_review_state(self, temp_db):
        """Test updating plugin file review state."""
        # Setup
        scan = Scan(scan_name="test_scan", export_root="/tmp")
        scan_id = scan.save(temp_db)
        plugin = Plugin(plugin_id=12345, plugin_name="Test", severity_int=2)
        plugin.save(temp_db)

        pf = PluginFile(
            scan_id=scan_id,
            plugin_id=12345,
            file_path="/tmp/test/plugin.txt",
            review_state="pending"
        )
        file_id = pf.save(temp_db)

        # Update review state
        pf.file_id = file_id
        pf.update_review_state("completed", notes="All fixed", conn=temp_db)

        # Verify
        retrieved = PluginFile.get_by_id(file_id, temp_db)
        assert retrieved.review_state == "completed"
        assert retrieved.reviewed_at is not None

    def test_plugin_file_default_review_state(self, temp_db):
        """Test default review state is 'pending'."""
        scan = Scan(scan_name="test_scan", export_root="/tmp")
        scan_id = scan.save(temp_db)
        plugin = Plugin(plugin_id=12345, plugin_name="Test", severity_int=2)
        plugin.save(temp_db)

        pf = PluginFile(
            scan_id=scan_id,
            plugin_id=12345,
            file_path="/tmp/test/plugin.txt"
        )
        file_id = pf.save(temp_db)

        retrieved = PluginFile.get_by_id(file_id, temp_db)
        assert retrieved.review_state == "pending"


class TestToolExecutionModel:
    """Tests for ToolExecution model."""

    def test_tool_execution_save(self, temp_db):
        """Test saving tool execution."""
        execution = ToolExecution(
            tool_name="nmap",
            command_text="nmap -sV 192.168.1.1",
            exit_code=0,
            duration_seconds=12.5
        )

        exec_id = execution.save(temp_db)

        assert exec_id is not None
        assert exec_id > 0

    def test_tool_execution_with_session_link(self, temp_db):
        """Test tool execution linked to session."""
        # Create session
        scan = Scan(scan_name="test_scan", export_root="/tmp")
        scan_id = scan.save(temp_db)

        cursor = temp_db.execute(
            "INSERT INTO sessions (scan_id, session_start) VALUES (?, datetime('now'))",
            (scan_id,)
        )
        session_id = cursor.lastrowid
        temp_db.commit()

        # Create execution
        execution = ToolExecution(
            session_id=session_id,
            tool_name="nmap",
            command_text="nmap -sV 192.168.1.1",
            exit_code=0,
            duration_seconds=12.5
        )
        exec_id = execution.save(temp_db)

        # Verify link
        cursor = temp_db.execute(
            "SELECT session_id FROM tool_executions WHERE execution_id = ?",
            (exec_id,)
        )
        result = cursor.fetchone()
        assert result["session_id"] == session_id

    def test_tool_execution_metadata_fields(self, temp_db):
        """Test tool execution captures all metadata."""
        execution = ToolExecution(
            tool_name="nmap",
            tool_protocol=None,
            command_text="sudo nmap -sS 192.168.1.0/24",
            exit_code=0,
            duration_seconds=45.2,
            host_count=256,
            sampled=False,
            ports="1-1000",
            used_sudo=True
        )

        exec_id = execution.save(temp_db)

        # Retrieve and verify
        cursor = temp_db.execute(
            """SELECT * FROM tool_executions WHERE execution_id = ?""",
            (exec_id,)
        )
        result = cursor.fetchone()

        assert result["tool_name"] == "nmap"
        assert result["host_count"] == 256
        assert result["ports"] == "1-1000"
        assert result["used_sudo"] == 1
        assert result["duration_seconds"] == 45.2


class TestArtifactModel:
    """Tests for Artifact model."""

    def test_artifact_save(self, temp_db):
        """Test saving artifact."""
        # Create execution first
        execution = ToolExecution(
            tool_name="nmap",
            command_text="nmap -oA scan 192.168.1.1",
            exit_code=0,
            duration_seconds=10.0
        )
        exec_id = execution.save(temp_db)

        # Create artifact
        artifact = Artifact(
            execution_id=exec_id,
            artifact_path="/tmp/scan.xml",
            artifact_type="nmap_xml",
            file_size_bytes=1024,
            file_hash="abc123"
        )

        artifact_id = artifact.save(temp_db)

        assert artifact_id is not None
        assert artifact_id > 0

    def test_artifact_linked_to_execution(self, temp_db):
        """Test artifact is linked to tool execution."""
        execution = ToolExecution(
            tool_name="nmap",
            command_text="nmap -oA scan 192.168.1.1",
            exit_code=0,
            duration_seconds=10.0
        )
        exec_id = execution.save(temp_db)

        artifact = Artifact(
            execution_id=exec_id,
            artifact_path="/tmp/scan.xml",
            artifact_type="nmap_xml"
        )
        artifact_id = artifact.save(temp_db)

        # Verify link via join
        cursor = temp_db.execute(
            """
            SELECT te.tool_name, a.artifact_type
            FROM artifacts a
            JOIN tool_executions te ON a.execution_id = te.execution_id
            WHERE a.artifact_id = ?
            """,
            (artifact_id,)
        )
        result = cursor.fetchone()
        assert result["tool_name"] == "nmap"
        assert result["artifact_type"] == "nmap_xml"

    def test_artifact_metadata_json(self, temp_db):
        """Test artifact metadata is stored as JSON."""
        execution = ToolExecution(
            tool_name="nmap",
            command_text="nmap 192.168.1.1",
            exit_code=0,
            duration_seconds=10.0
        )
        exec_id = execution.save(temp_db)

        artifact = Artifact(
            execution_id=exec_id,
            artifact_path="/tmp/scan.xml",
            artifact_type="nmap_xml",
            metadata={"scan_type": "SYN", "hosts_up": 5}
        )
        artifact_id = artifact.save(temp_db)

        # Retrieve and verify
        cursor = temp_db.execute(
            "SELECT metadata FROM artifacts WHERE artifact_id = ?",
            (artifact_id,)
        )
        result = cursor.fetchone()
        metadata = json.loads(result["metadata"]) if result["metadata"] else None
        assert metadata == {"scan_type": "SYN", "hosts_up": 5}


class TestTimestampFunctions:
    """Tests for timestamp helper functions."""

    def test_now_iso_format(self):
        """Test now_iso returns ISO format timestamp."""
        timestamp = now_iso()

        # Should parse as datetime
        dt = datetime.fromisoformat(timestamp)
        assert isinstance(dt, datetime)

    def test_now_iso_is_recent(self):
        """Test now_iso returns current time."""
        timestamp = now_iso()
        dt = datetime.fromisoformat(timestamp)

        # Should be within last minute
        now = datetime.now()
        diff = (now - dt).total_seconds()
        assert abs(diff) < 60


class TestModelRelationships:
    """Tests for model relationships and cascading."""

    @pytest.mark.integration
    def test_delete_scan_cascades_to_files(self, temp_db):
        """Test deleting scan removes plugin files."""
        # Create chain: scan -> plugin -> plugin_file
        scan = Scan(scan_name="test_scan", export_root="/tmp")
        scan_id = scan.save(temp_db)

        plugin = Plugin(plugin_id=12345, plugin_name="Test", severity_int=2)
        plugin.save(temp_db)

        pf = PluginFile(
            scan_id=scan_id,
            plugin_id=12345,
            file_path="/tmp/test/plugin.txt"
        )
        pf.save(temp_db)

        # Delete scan
        temp_db.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
        temp_db.commit()

        # Plugin file should be gone
        cursor = temp_db.execute("SELECT COUNT(*) as count FROM plugin_files")
        assert cursor.fetchone()["count"] == 0

    @pytest.mark.integration
    def test_delete_execution_cascades_to_artifacts(self, temp_db):
        """Test deleting tool execution removes artifacts."""
        execution = ToolExecution(
            tool_name="nmap",
            command_text="nmap 192.168.1.1",
            exit_code=0,
            duration_seconds=10.0
        )
        exec_id = execution.save(temp_db)

        artifact = Artifact(
            execution_id=exec_id,
            artifact_path="/tmp/scan.xml",
            artifact_type="nmap_xml"
        )
        artifact.save(temp_db)

        # Delete execution
        temp_db.execute("DELETE FROM tool_executions WHERE execution_id = ?", (exec_id,))
        temp_db.commit()

        # Artifact should still exist but execution_id should be NULL (ON DELETE SET NULL)
        cursor = temp_db.execute("SELECT COUNT(*) as count FROM artifacts WHERE artifact_path = ?", ("/tmp/scan.xml",))
        assert cursor.fetchone()["count"] == 1

        cursor = temp_db.execute("SELECT execution_id FROM artifacts WHERE artifact_path = ?", ("/tmp/scan.xml",))
        assert cursor.fetchone()["execution_id"] is None
