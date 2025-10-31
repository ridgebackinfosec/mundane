"""Session persistence for mundane review sessions."""

import json
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional


@dataclass
class SessionState:
    """
    Represents the state of a mundane review session.

    Attributes:
        scan_dir: Path to scan directory
        session_start: ISO format timestamp of session start
        reviewed_files: List of reviewed (not marked complete) filenames
        completed_files: List of marked complete filenames
        skipped_files: List of skipped (empty) filenames
        tool_executions: Count of tool executions
        cve_extractions: Count of CVE extractions performed
        last_updated: ISO format timestamp of last update
    """

    scan_dir: str
    session_start: str
    reviewed_files: list[str]
    completed_files: list[str]
    skipped_files: list[str]
    tool_executions: int
    cve_extractions: int
    last_updated: str


def get_session_file_path(scan_dir: Path) -> Path:
    """
    Get the path to the session file for a scan directory.

    Args:
        scan_dir: Scan directory path

    Returns:
        Path to .mundane_session.json file
    """
    return scan_dir / ".mundane_session.json"


def save_session(
    scan_dir: Path,
    session_start: datetime,
    reviewed_files: list[str],
    completed_files: list[str],
    skipped_files: list[str],
    tool_executions: int = 0,
    cve_extractions: int = 0,
) -> None:
    """
    Save session state to JSON file.

    Args:
        scan_dir: Scan directory path
        session_start: Session start datetime
        reviewed_files: List of reviewed filenames
        completed_files: List of completed filenames
        skipped_files: List of skipped filenames
        tool_executions: Count of tool executions
        cve_extractions: Count of CVE extractions
    """
    session_file = get_session_file_path(scan_dir)

    state = SessionState(
        scan_dir=str(scan_dir),
        session_start=session_start.isoformat(),
        reviewed_files=reviewed_files,
        completed_files=completed_files,
        skipped_files=skipped_files,
        tool_executions=tool_executions,
        cve_extractions=cve_extractions,
        last_updated=datetime.now().isoformat(),
    )

    try:
        with open(session_file, "w", encoding="utf-8") as f:
            json.dump(asdict(state), f, indent=2)
    except Exception as e:
        # Silent fail - session persistence is not critical
        pass


def load_session(scan_dir: Path) -> Optional[SessionState]:
    """
    Load session state from JSON file.

    Args:
        scan_dir: Scan directory path

    Returns:
        SessionState object if file exists and is valid, None otherwise
    """
    session_file = get_session_file_path(scan_dir)

    if not session_file.exists():
        return None

    try:
        with open(session_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        return SessionState(**data)
    except Exception:
        # Invalid or corrupted session file
        return None


def delete_session(scan_dir: Path) -> None:
    """
    Delete session file.

    Args:
        scan_dir: Scan directory path
    """
    session_file = get_session_file_path(scan_dir)
    try:
        if session_file.exists():
            session_file.unlink()
    except Exception:
        pass
