"""ORM models and CRUD operations for mundane database.

This module provides dataclass-based models and database operations for
tracking findings, review state, tool executions, and artifacts.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from .database import db_transaction, get_connection, query_all, query_one
from .logging_setup import log_error, log_info


# ========== Helper Functions ==========

def now_iso() -> str:
    """Get current timestamp in ISO 8601 format.

    Returns:
        ISO formatted timestamp string
    """
    return datetime.now().isoformat()


# ========== Model: Scan ==========

@dataclass
class Scan:
    """Represents a Nessus scan and its exported findings."""

    scan_id: Optional[int] = None
    scan_name: str = ""
    nessus_file_path: Optional[str] = None
    nessus_file_hash: Optional[str] = None
    export_root: str = ""
    created_at: Optional[str] = None
    last_reviewed_at: Optional[str] = None

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> Scan:
        """Create Scan from database row.

        Args:
            row: SQLite row

        Returns:
            Scan instance
        """
        return cls(
            scan_id=row["scan_id"],
            scan_name=row["scan_name"],
            nessus_file_path=row["nessus_file_path"],
            nessus_file_hash=row["nessus_file_hash"],
            export_root=row["export_root"],
            created_at=row["created_at"],
            last_reviewed_at=row["last_reviewed_at"]
        )

    def save(self, conn: Optional[sqlite3.Connection] = None) -> int:
        """Insert or update scan in database.

        Args:
            conn: Database connection (creates new if None)

        Returns:
            scan_id of saved record
        """
        with db_transaction(conn) as c:
            if self.scan_id is None:
                # Insert new scan
                cursor = c.execute(
                    """
                    INSERT INTO scans (scan_name, nessus_file_path, nessus_file_hash, export_root)
                    VALUES (?, ?, ?, ?)
                    """,
                    (self.scan_name, self.nessus_file_path, self.nessus_file_hash, self.export_root)
                )
                self.scan_id = cursor.lastrowid
                log_info(f"Created scan: {self.scan_name} (ID: {self.scan_id})")
            else:
                # Update existing scan
                c.execute(
                    """
                    UPDATE scans
                    SET scan_name=?, nessus_file_path=?, nessus_file_hash=?,
                        export_root=?, last_reviewed_at=?
                    WHERE scan_id=?
                    """,
                    (self.scan_name, self.nessus_file_path, self.nessus_file_hash,
                     self.export_root, self.last_reviewed_at, self.scan_id)
                )

        return self.scan_id

    @classmethod
    def get_by_name(cls, scan_name: str, conn: Optional[sqlite3.Connection] = None) -> Optional[Scan]:
        """Retrieve scan by name.

        Args:
            scan_name: Name of scan
            conn: Database connection

        Returns:
            Scan instance or None if not found
        """
        with db_transaction(conn) as c:
            row = query_one(c, "SELECT * FROM scans WHERE scan_name = ?", (scan_name,))
            return cls.from_row(row) if row else None

    @classmethod
    def get_by_id(cls, scan_id: int, conn: Optional[sqlite3.Connection] = None) -> Optional[Scan]:
        """Retrieve scan by ID.

        Args:
            scan_id: Scan ID
            conn: Database connection

        Returns:
            Scan instance or None if not found
        """
        with db_transaction(conn) as c:
            row = query_one(c, "SELECT * FROM scans WHERE scan_id = ?", (scan_id,))
            return cls.from_row(row) if row else None

    @classmethod
    def get_all(cls, conn: Optional[sqlite3.Connection] = None) -> list[Scan]:
        """Retrieve all scans ordered by last reviewed (most recent first).

        Scans with NULL last_reviewed_at appear last, ordered by created_at DESC.

        Args:
            conn: Database connection

        Returns:
            List of Scan instances (may be empty)
        """
        with db_transaction(conn) as c:
            rows = query_all(
                c,
                """
                SELECT * FROM scans
                ORDER BY last_reviewed_at DESC NULLS LAST, created_at DESC
                """
            )
            return [cls.from_row(row) for row in rows]


# ========== Model: Plugin ==========

@dataclass
class Plugin:
    """Represents a Nessus plugin (finding type).

    NOTE: "plugin" is internal terminology. User-facing commands use "findings".
    """

    plugin_id: int
    plugin_name: str = ""
    severity_int: int = 0
    severity_label: str = ""
    has_metasploit: bool = False
    cvss3_score: Optional[float] = None
    cvss2_score: Optional[float] = None
    cves: Optional[list[str]] = None  # JSON array
    plugin_url: Optional[str] = None
    metadata_fetched_at: Optional[str] = None

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> Plugin:
        """Create Plugin from database row.

        Args:
            row: SQLite row

        Returns:
            Plugin instance
        """
        cves_json = row["cves"]
        cves = json.loads(cves_json) if cves_json else None

        return cls(
            plugin_id=row["plugin_id"],
            plugin_name=row["plugin_name"],
            severity_int=row["severity_int"],
            severity_label=row["severity_label"],
            has_metasploit=bool(row["has_metasploit"]),
            cvss3_score=row["cvss3_score"],
            cvss2_score=row["cvss2_score"],
            cves=cves,
            plugin_url=row["plugin_url"],
            metadata_fetched_at=row["metadata_fetched_at"]
        )

    def save(self, conn: Optional[sqlite3.Connection] = None) -> int:
        """Insert or update plugin in database (upsert).

        Args:
            conn: Database connection

        Returns:
            plugin_id
        """
        cves_json = json.dumps(self.cves) if self.cves else None

        with db_transaction(conn) as c:
            c.execute(
                """
                INSERT OR REPLACE INTO plugins (
                    plugin_id, plugin_name, severity_int, severity_label,
                    has_metasploit, cvss3_score, cvss2_score, cves,
                    plugin_url, metadata_fetched_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (self.plugin_id, self.plugin_name, self.severity_int, self.severity_label,
                 self.has_metasploit, self.cvss3_score, self.cvss2_score, cves_json,
                 self.plugin_url, self.metadata_fetched_at)
            )

        return self.plugin_id

    @classmethod
    def get_by_id(cls, plugin_id: int, conn: Optional[sqlite3.Connection] = None) -> Optional[Plugin]:
        """Retrieve plugin by ID.

        Args:
            plugin_id: Plugin ID
            conn: Database connection

        Returns:
            Plugin instance or None if not found
        """
        with db_transaction(conn) as c:
            row = query_one(c, "SELECT * FROM plugins WHERE plugin_id = ?", (plugin_id,))
            return cls.from_row(row) if row else None


# ========== Model: PluginFile ==========

@dataclass
class PluginFile:
    """Represents an exported plugin .txt file for a specific scan."""

    file_id: Optional[int] = None
    scan_id: int = 0
    plugin_id: int = 0
    file_path: str = ""
    severity_dir: str = ""
    review_state: str = "pending"  # 'pending', 'reviewed', 'completed', 'skipped'
    reviewed_at: Optional[str] = None
    reviewed_by: Optional[str] = None
    review_notes: Optional[str] = None
    host_count: int = 0
    port_count: int = 0
    file_created_at: Optional[str] = None
    file_modified_at: Optional[str] = None
    last_parsed_at: Optional[str] = None

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> PluginFile:
        """Create PluginFile from database row.

        Args:
            row: SQLite row

        Returns:
            PluginFile instance
        """
        return cls(
            file_id=row["file_id"],
            scan_id=row["scan_id"],
            plugin_id=row["plugin_id"],
            file_path=row["file_path"],
            severity_dir=row["severity_dir"],
            review_state=row["review_state"],
            reviewed_at=row["reviewed_at"],
            reviewed_by=row["reviewed_by"],
            review_notes=row["review_notes"],
            host_count=row["host_count"],
            port_count=row["port_count"],
            file_created_at=row["file_created_at"],
            file_modified_at=row["file_modified_at"],
            last_parsed_at=row["last_parsed_at"]
        )

    def save(self, conn: Optional[sqlite3.Connection] = None) -> int:
        """Insert or update plugin file in database.

        Args:
            conn: Database connection

        Returns:
            file_id of saved record
        """
        with db_transaction(conn) as c:
            if self.file_id is None:
                # Insert new file
                cursor = c.execute(
                    """
                    INSERT INTO plugin_files (
                        scan_id, plugin_id, file_path, severity_dir, review_state,
                        reviewed_at, reviewed_by, review_notes, host_count, port_count,
                        file_created_at, file_modified_at, last_parsed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (self.scan_id, self.plugin_id, self.file_path, self.severity_dir,
                     self.review_state, self.reviewed_at, self.reviewed_by, self.review_notes,
                     self.host_count, self.port_count, self.file_created_at,
                     self.file_modified_at, self.last_parsed_at)
                )
                self.file_id = cursor.lastrowid
            else:
                # Update existing file
                c.execute(
                    """
                    UPDATE plugin_files
                    SET review_state=?, reviewed_at=?, reviewed_by=?, review_notes=?,
                        host_count=?, port_count=?, file_modified_at=?, last_parsed_at=?
                    WHERE file_id=?
                    """,
                    (self.review_state, self.reviewed_at, self.reviewed_by, self.review_notes,
                     self.host_count, self.port_count, self.file_modified_at,
                     self.last_parsed_at, self.file_id)
                )

        return self.file_id

    @classmethod
    def get_by_id(cls, file_id: int, conn: Optional[sqlite3.Connection] = None) -> Optional[PluginFile]:
        """Retrieve plugin file by ID.

        Args:
            file_id: Plugin file ID
            conn: Database connection

        Returns:
            PluginFile instance or None if not found
        """
        with db_transaction(conn) as c:
            row = query_one(c, "SELECT * FROM plugin_files WHERE file_id = ?", (file_id,))
            return cls.from_row(row) if row else None

    @classmethod
    def get_by_path(cls, file_path: str, conn: Optional[sqlite3.Connection] = None) -> Optional[PluginFile]:
        """Retrieve plugin file by path.

        Args:
            file_path: Path to file
            conn: Database connection

        Returns:
            PluginFile instance or None if not found
        """
        with db_transaction(conn) as c:
            row = query_one(c, "SELECT * FROM plugin_files WHERE file_path = ?", (file_path,))
            return cls.from_row(row) if row else None

    def update_review_state(
        self,
        new_state: str,
        notes: Optional[str] = None,
        conn: Optional[sqlite3.Connection] = None
    ) -> None:
        """Update review state and timestamp.

        Args:
            new_state: New review state ('pending', 'reviewed', 'completed', 'skipped')
            notes: Optional review notes
            conn: Database connection
        """
        self.review_state = new_state
        self.reviewed_at = now_iso()
        if notes:
            self.review_notes = notes

        self.save(conn)


# ========== Model: ToolExecution ==========

@dataclass
class ToolExecution:
    """Represents a single tool execution (nmap, netexec, etc.)."""

    execution_id: Optional[int] = None
    session_id: Optional[int] = None
    file_id: Optional[int] = None
    tool_name: str = ""
    tool_protocol: Optional[str] = None
    command_text: str = ""
    command_args: Optional[list[str]] = None  # JSON array
    executed_at: Optional[str] = None
    exit_code: Optional[int] = None
    duration_seconds: Optional[float] = None
    host_count: Optional[int] = None
    sampled: bool = False
    ports: Optional[str] = None
    used_sudo: bool = False

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> ToolExecution:
        """Create ToolExecution from database row.

        Args:
            row: SQLite row

        Returns:
            ToolExecution instance
        """
        cmd_args_json = row["command_args"]
        cmd_args = json.loads(cmd_args_json) if cmd_args_json else None

        return cls(
            execution_id=row["execution_id"],
            session_id=row["session_id"],
            file_id=row["file_id"],
            tool_name=row["tool_name"],
            tool_protocol=row["tool_protocol"],
            command_text=row["command_text"],
            command_args=cmd_args,
            executed_at=row["executed_at"],
            exit_code=row["exit_code"],
            duration_seconds=row["duration_seconds"],
            host_count=row["host_count"],
            sampled=bool(row["sampled"]),
            ports=row["ports"],
            used_sudo=bool(row["used_sudo"])
        )

    def save(self, conn: Optional[sqlite3.Connection] = None) -> int:
        """Insert or update tool execution in database.

        Args:
            conn: Database connection

        Returns:
            execution_id of saved record
        """
        cmd_args_json = json.dumps(self.command_args) if self.command_args else None

        with db_transaction(conn) as c:
            if self.execution_id is None:
                # Insert new execution
                cursor = c.execute(
                    """
                    INSERT INTO tool_executions (
                        session_id, file_id, tool_name, tool_protocol, command_text,
                        command_args, executed_at, exit_code, duration_seconds,
                        host_count, sampled, ports, used_sudo
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (self.session_id, self.file_id, self.tool_name, self.tool_protocol,
                     self.command_text, cmd_args_json, self.executed_at or now_iso(),
                     self.exit_code, self.duration_seconds, self.host_count,
                     self.sampled, self.ports, self.used_sudo)
                )
                self.execution_id = cursor.lastrowid
            else:
                # Update existing execution
                c.execute(
                    """
                    UPDATE tool_executions
                    SET exit_code=?, duration_seconds=?
                    WHERE execution_id=?
                    """,
                    (self.exit_code, self.duration_seconds, self.execution_id)
                )

        return self.execution_id


# ========== Model: Artifact ==========

@dataclass
class Artifact:
    """Represents a generated artifact file (nmap output, logs, etc.)."""

    artifact_id: Optional[int] = None
    execution_id: Optional[int] = None
    artifact_path: str = ""
    artifact_type: str = ""
    file_size_bytes: Optional[int] = None
    file_hash: Optional[str] = None
    created_at: Optional[str] = None
    last_accessed_at: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None  # JSON object

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> Artifact:
        """Create Artifact from database row.

        Args:
            row: SQLite row

        Returns:
            Artifact instance
        """
        metadata_json = row["metadata"]
        metadata = json.loads(metadata_json) if metadata_json else None

        return cls(
            artifact_id=row["artifact_id"],
            execution_id=row["execution_id"],
            artifact_path=row["artifact_path"],
            artifact_type=row["artifact_type"],
            file_size_bytes=row["file_size_bytes"],
            file_hash=row["file_hash"],
            created_at=row["created_at"],
            last_accessed_at=row["last_accessed_at"],
            metadata=metadata
        )

    def save(self, conn: Optional[sqlite3.Connection] = None) -> int:
        """Insert artifact in database.

        Args:
            conn: Database connection

        Returns:
            artifact_id of saved record
        """
        metadata_json = json.dumps(self.metadata) if self.metadata else None

        with db_transaction(conn) as c:
            cursor = c.execute(
                """
                INSERT OR REPLACE INTO artifacts (
                    artifact_id, execution_id, artifact_path, artifact_type,
                    file_size_bytes, file_hash, created_at, last_accessed_at, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (self.artifact_id, self.execution_id, self.artifact_path, self.artifact_type,
                 self.file_size_bytes, self.file_hash, self.created_at or now_iso(),
                 self.last_accessed_at, metadata_json)
            )
            if self.artifact_id is None:
                self.artifact_id = cursor.lastrowid

        return self.artifact_id

    @classmethod
    def get_by_execution(cls, execution_id: int, conn: Optional[sqlite3.Connection] = None) -> list[Artifact]:
        """Retrieve all artifacts for a tool execution.

        Args:
            execution_id: Tool execution ID
            conn: Database connection

        Returns:
            List of Artifact instances
        """
        with db_transaction(conn) as c:
            rows = query_all(c, "SELECT * FROM artifacts WHERE execution_id = ?", (execution_id,))
            return [cls.from_row(row) for row in rows]
