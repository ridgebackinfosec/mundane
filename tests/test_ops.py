"""Tests for mundane_pkg.ops module."""

import tempfile
from pathlib import Path

import pytest

from mundane_pkg.ops import (
    ExecutionMetadata,
    log_tool_execution,
    log_artifact,
    log_artifacts_for_nmap,
)


class TestExecutionMetadata:
    """Tests for ExecutionMetadata dataclass."""

    def test_execution_metadata_creation(self):
        """Test creating ExecutionMetadata."""
        metadata = ExecutionMetadata(
            exit_code=0,
            duration_seconds=12.5,
            used_sudo=True
        )

        assert metadata.exit_code == 0
        assert metadata.duration_seconds == 12.5
        assert metadata.used_sudo is True

    def test_execution_metadata_with_failure(self):
        """Test metadata for failed execution."""
        metadata = ExecutionMetadata(
            exit_code=1,
            duration_seconds=5.2,
            used_sudo=False
        )

        assert metadata.exit_code == 1
        assert metadata.duration_seconds == 5.2
        assert metadata.used_sudo is False


class TestLogToolExecution:
    """Tests for log_tool_execution function."""

    def test_log_execution_basic(self, temp_db):
        """Test logging basic tool execution."""
        metadata = ExecutionMetadata(
            exit_code=0,
            duration_seconds=10.5,
            used_sudo=False
        )

        execution_id = log_tool_execution(
            tool_name="nmap",
            command_text="nmap -sV 192.168.1.1",
            execution_metadata=metadata,
            conn=temp_db
        )

        assert execution_id is not None
        assert execution_id > 0

        # Verify in database
        cursor = temp_db.execute(
            "SELECT * FROM tool_executions WHERE execution_id = ?",
            (execution_id,)
        )
        row = cursor.fetchone()

        assert row["tool_name"] == "nmap"
        assert row["command_text"] == "nmap -sV 192.168.1.1"
        assert row["exit_code"] == 0
        assert row["duration_seconds"] == 10.5
        assert row["used_sudo"] == 0

    def test_log_execution_with_metadata(self, temp_db):
        """Test logging execution with full metadata."""
        metadata = ExecutionMetadata(
            exit_code=0,
            duration_seconds=45.2,
            used_sudo=True
        )

        execution_id = log_tool_execution(
            tool_name="nmap",
            command_text="sudo nmap -sS -p- 192.168.1.0/24",
            execution_metadata=metadata,
            host_count=256,
            sampled=False,
            ports="1-65535",
            conn=temp_db
        )

        assert execution_id is not None

        # Verify metadata
        cursor = temp_db.execute(
            "SELECT * FROM tool_executions WHERE execution_id = ?",
            (execution_id,)
        )
        row = cursor.fetchone()

        assert row["host_count"] == 256
        assert row["sampled"] == 0
        assert row["ports"] == "1-65535"
        assert row["used_sudo"] == 1

    def test_log_execution_with_protocol(self, temp_db):
        """Test logging netexec execution with protocol."""
        metadata = ExecutionMetadata(
            exit_code=0,
            duration_seconds=15.3,
            used_sudo=False
        )

        execution_id = log_tool_execution(
            tool_name="netexec",
            command_text="netexec smb targets.txt -u admin -p password",
            execution_metadata=metadata,
            tool_protocol="smb",
            host_count=10,
            conn=temp_db
        )

        assert execution_id is not None

        cursor = temp_db.execute(
            "SELECT tool_protocol FROM tool_executions WHERE execution_id = ?",
            (execution_id,)
        )
        row = cursor.fetchone()
        assert row["tool_protocol"] == "smb"

    @pytest.mark.integration
    def test_log_execution_with_session_link(self, temp_db):
        """Test logging execution linked to a session."""
        from mundane_pkg.models import Scan

        # Create scan and session
        scan = Scan(scan_name="test_scan", export_root="/tmp/test")
        scan_id = scan.save(temp_db)

        cursor = temp_db.execute(
            "INSERT INTO sessions (scan_id, session_start) VALUES (?, datetime('now'))",
            (scan_id,)
        )
        temp_db.commit()
        session_id = cursor.lastrowid

        # Create scan directory for linking
        with tempfile.TemporaryDirectory() as tmpdir:
            scan_dir = Path(tmpdir) / "test_scan"
            scan_dir.mkdir()

            metadata = ExecutionMetadata(
                exit_code=0,
                duration_seconds=5.0,
                used_sudo=False
            )

            # Note: This won't actually link since scan_dir.name != scan_name in DB
            # but tests the code path
            execution_id = log_tool_execution(
                tool_name="nmap",
                command_text="nmap 192.168.1.1",
                execution_metadata=metadata,
                scan_dir=scan_dir,
                conn=temp_db
            )

            assert execution_id is not None

    @pytest.mark.integration
    def test_log_execution_with_file_link(self, temp_db, temp_dir):
        """Test logging execution linked to a plugin file."""
        from mundane_pkg.models import Scan, Plugin, PluginFile

        # Create dependencies
        scan = Scan(scan_name="test_scan", export_root="/tmp/test")
        scan_id = scan.save(temp_db)

        plugin = Plugin(plugin_id=12345, plugin_name="Test", severity_int=2)
        plugin.save(temp_db)

        file_path = temp_dir / "test_plugin.txt"
        file_path.write_text("192.168.1.1:80\n")

        pf = PluginFile(
            scan_id=scan_id,
            plugin_id=12345,
            file_path=str(file_path.resolve())
        )
        pf.save(temp_db)

        # Log execution
        metadata = ExecutionMetadata(
            exit_code=0,
            duration_seconds=8.5,
            used_sudo=False
        )

        execution_id = log_tool_execution(
            tool_name="nmap",
            command_text="nmap -sV 192.168.1.1",
            execution_metadata=metadata,
            file_path=file_path,
            conn=temp_db
        )

        assert execution_id is not None

        # Verify link
        cursor = temp_db.execute(
            "SELECT file_id FROM tool_executions WHERE execution_id = ?",
            (execution_id,)
        )
        row = cursor.fetchone()
        assert row["file_id"] is not None


class TestLogArtifact:
    """Tests for log_artifact function."""

    def test_log_artifact_basic(self, temp_db, temp_dir):
        """Test logging a basic artifact."""
        from mundane_pkg.models import ToolExecution, now_iso

        # Create tool execution first
        execution = ToolExecution(
            tool_name="nmap",
            command_text="nmap -oA scan 192.168.1.1",
            executed_at=now_iso(),
            exit_code=0,
            duration_seconds=10.0
        )
        exec_id = execution.save(temp_db)

        # Create artifact file
        artifact_file = temp_dir / "scan.xml"
        artifact_file.write_text("<nmaprun>test</nmaprun>")

        # Log artifact
        artifact_id = log_artifact(
            execution_id=exec_id,
            artifact_path=artifact_file,
            artifact_type="nmap_xml",
            conn=temp_db
        )

        assert artifact_id is not None
        assert artifact_id > 0

        # Verify in database
        cursor = temp_db.execute(
            "SELECT * FROM artifacts WHERE artifact_id = ?",
            (artifact_id,)
        )
        row = cursor.fetchone()

        assert row["execution_id"] == exec_id
        assert row["artifact_type"] == "nmap_xml"
        assert row["file_size_bytes"] == len("<nmaprun>test</nmaprun>")
        assert row["file_hash"] is not None
        assert len(row["file_hash"]) == 64  # SHA256

    def test_log_artifact_with_metadata(self, temp_db, temp_dir):
        """Test logging artifact with metadata."""
        from mundane_pkg.models import ToolExecution, now_iso
        import json

        execution = ToolExecution(
            tool_name="nmap",
            command_text="nmap 192.168.1.1",
            executed_at=now_iso(),
            exit_code=0,
            duration_seconds=10.0
        )
        exec_id = execution.save(temp_db)

        artifact_file = temp_dir / "scan.xml"
        artifact_file.write_text("test")

        metadata_dict = {"scan_type": "SYN", "hosts_up": 5}

        artifact_id = log_artifact(
            execution_id=exec_id,
            artifact_path=artifact_file,
            artifact_type="nmap_xml",
            metadata=metadata_dict,
            conn=temp_db
        )

        assert artifact_id is not None

        # Verify metadata
        cursor = temp_db.execute(
            "SELECT metadata FROM artifacts WHERE artifact_id = ?",
            (artifact_id,)
        )
        row = cursor.fetchone()
        stored_metadata = json.loads(row["metadata"]) if row["metadata"] else None
        assert stored_metadata == metadata_dict

    def test_log_artifact_nonexistent_file(self, temp_db, temp_dir):
        """Test logging artifact for nonexistent file."""
        from mundane_pkg.models import ToolExecution, now_iso

        execution = ToolExecution(
            tool_name="nmap",
            command_text="nmap 192.168.1.1",
            executed_at=now_iso(),
            exit_code=0,
            duration_seconds=10.0
        )
        exec_id = execution.save(temp_db)

        nonexistent = temp_dir / "nonexistent.xml"

        # Should still log but with None for size/hash
        artifact_id = log_artifact(
            execution_id=exec_id,
            artifact_path=nonexistent,
            artifact_type="nmap_xml",
            conn=temp_db
        )

        assert artifact_id is not None

        cursor = temp_db.execute(
            "SELECT file_size_bytes, file_hash FROM artifacts WHERE artifact_id = ?",
            (artifact_id,)
        )
        row = cursor.fetchone()
        assert row["file_size_bytes"] is None
        assert row["file_hash"] is None


class TestLogArtifactsForNmap:
    """Tests for log_artifacts_for_nmap function."""

    def test_log_nmap_artifacts_all_formats(self, temp_db, temp_dir):
        """Test logging all nmap output formats."""
        from mundane_pkg.models import ToolExecution, now_iso

        execution = ToolExecution(
            tool_name="nmap",
            command_text="nmap -oA scan 192.168.1.1",
            executed_at=now_iso(),
            exit_code=0,
            duration_seconds=10.0
        )
        exec_id = execution.save(temp_db)

        # Create all three nmap output files
        oabase = temp_dir / "scan"
        (temp_dir / "scan.xml").write_text("<nmaprun/>")
        (temp_dir / "scan.nmap").write_text("Nmap scan")
        (temp_dir / "scan.gnmap").write_text("# Nmap scan")

        artifact_ids = log_artifacts_for_nmap(exec_id, oabase, conn=temp_db)

        assert len(artifact_ids) == 3

        # Verify all artifacts in database
        cursor = temp_db.execute(
            "SELECT artifact_type FROM artifacts WHERE execution_id = ? ORDER BY artifact_type",
            (exec_id,)
        )
        types = [row["artifact_type"] for row in cursor.fetchall()]
        assert types == ["nmap_gnmap", "nmap_nmap", "nmap_xml"]

    def test_log_nmap_artifacts_partial(self, temp_db, temp_dir):
        """Test logging when only some nmap files exist."""
        from mundane_pkg.models import ToolExecution, now_iso

        execution = ToolExecution(
            tool_name="nmap",
            command_text="nmap -oX scan.xml 192.168.1.1",
            executed_at=now_iso(),
            exit_code=0,
            duration_seconds=10.0
        )
        exec_id = execution.save(temp_db)

        # Create only XML file
        oabase = temp_dir / "scan"
        (temp_dir / "scan.xml").write_text("<nmaprun/>")

        artifact_ids = log_artifacts_for_nmap(exec_id, oabase, conn=temp_db)

        assert len(artifact_ids) == 1

        cursor = temp_db.execute(
            "SELECT artifact_type FROM artifacts WHERE execution_id = ?",
            (exec_id,)
        )
        row = cursor.fetchone()
        assert row["artifact_type"] == "nmap_xml"

    def test_log_nmap_artifacts_none_exist(self, temp_db, temp_dir):
        """Test logging when no nmap files exist."""
        from mundane_pkg.models import ToolExecution, now_iso

        execution = ToolExecution(
            tool_name="nmap",
            command_text="nmap 192.168.1.1",
            executed_at=now_iso(),
            exit_code=0,
            duration_seconds=10.0
        )
        exec_id = execution.save(temp_db)

        oabase = temp_dir / "scan"

        artifact_ids = log_artifacts_for_nmap(exec_id, oabase, conn=temp_db)

        assert len(artifact_ids) == 0

    def test_log_nmap_artifacts_with_metadata(self, temp_db, temp_dir):
        """Test logging nmap artifacts with metadata."""
        from mundane_pkg.models import ToolExecution, now_iso

        execution = ToolExecution(
            tool_name="nmap",
            command_text="nmap -oA scan 192.168.1.1",
            executed_at=now_iso(),
            exit_code=0,
            duration_seconds=10.0
        )
        exec_id = execution.save(temp_db)

        oabase = temp_dir / "scan"
        (temp_dir / "scan.xml").write_text("<nmaprun/>")

        metadata_dict = {"scan_type": "version_detection"}

        artifact_ids = log_artifacts_for_nmap(exec_id, oabase, metadata=metadata_dict, conn=temp_db)

        assert len(artifact_ids) == 1

        # Verify metadata was stored
        import json
        cursor = temp_db.execute(
            "SELECT metadata FROM artifacts WHERE artifact_id = ?",
            (artifact_ids[0],)
        )
        row = cursor.fetchone()
        stored_metadata = json.loads(row["metadata"]) if row["metadata"] else None
        assert stored_metadata == metadata_dict
