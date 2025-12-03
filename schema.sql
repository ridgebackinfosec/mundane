-- ============================================================================
-- MUNDANE DATABASE SCHEMA
-- ============================================================================
-- SQLite schema for tracking Nessus findings, review state, tool executions,
-- and generated artifacts. This file serves as reference documentation.
--
-- Database location: ~/.mundane/mundane.db (global, cross-scan queries)
-- ============================================================================

-- ============================================================================
-- SCANS: Top-level scan tracking
-- ============================================================================
CREATE TABLE IF NOT EXISTS scans (
    scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_name TEXT NOT NULL UNIQUE,
    nessus_file_path TEXT,              -- Original .nessus file path
    nessus_file_hash TEXT,              -- SHA256 of .nessus file for change detection
    export_root TEXT NOT NULL,          -- Where plugin .txt files are stored
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_reviewed_at TIMESTAMP,

    CONSTRAINT unique_scan_name UNIQUE (scan_name)
);

CREATE INDEX IF NOT EXISTS idx_scans_name ON scans(scan_name);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at);

-- ============================================================================
-- PLUGINS: Plugin metadata (Nessus plugin ID - internal reference only)
-- ============================================================================
-- NOTE: "plugin" is internal terminology. User-facing commands use "findings"
-- ============================================================================
CREATE TABLE IF NOT EXISTS plugins (
    plugin_id INTEGER PRIMARY KEY,      -- Nessus plugin ID (e.g., 57608)
    plugin_name TEXT NOT NULL,
    severity_int INTEGER NOT NULL,      -- 0=Info, 1=Low, 2=Medium, 3=High, 4=Critical
    severity_label TEXT NOT NULL,       -- "Info", "Low", "Medium", "High", "Critical"
    has_metasploit BOOLEAN DEFAULT 0,
    cvss3_score REAL,                   -- CVSS v3 base score
    cvss2_score REAL,                   -- CVSS v2 base score (fallback)

    -- Metasploit module names (JSON array, extracted from .nessus XML)
    metasploit_names TEXT,              -- JSON: ["Chargen Probe Utility", "Another Module"]

    -- CVE associations (JSON array, extracted from .nessus XML)
    cves TEXT,                          -- JSON: ["CVE-2023-1234", "CVE-2023-5678"]

    -- Tenable plugin URL
    plugin_url TEXT,                    -- https://www.tenable.com/plugins/nessus/{plugin_id}

    -- Metadata fetch timestamp (deprecated - CVEs now extracted from XML)
    metadata_fetched_at TIMESTAMP,

    CONSTRAINT severity_range CHECK (severity_int BETWEEN 0 AND 4)
);

CREATE INDEX IF NOT EXISTS idx_plugins_severity ON plugins(severity_int);
CREATE INDEX IF NOT EXISTS idx_plugins_metasploit ON plugins(has_metasploit);
CREATE INDEX IF NOT EXISTS idx_plugins_name ON plugins(plugin_name);

-- ============================================================================
-- PLUGIN_FILES: Findings per scan (one per plugin per scan)
-- ============================================================================
-- Streamlined in v1.9.0: Removed duplicate/unnecessary columns
--   - severity_dir: duplicates plugins.severity_int (use JOIN)
--   - file_path: not needed in DB-only (can construct if needed)
--   - file_created_at, file_modified_at, last_parsed_at: unused
-- ============================================================================
CREATE TABLE IF NOT EXISTS plugin_files (
    file_id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    plugin_id INTEGER NOT NULL,

    -- Review state (replaces REVIEW_COMPLETE- file prefix)
    review_state TEXT DEFAULT 'pending', -- 'pending', 'reviewed', 'completed', 'skipped'
    reviewed_at TIMESTAMP,
    reviewed_by TEXT,                    -- Future: user tracking
    review_notes TEXT,                   -- Future: user notes

    -- Host/port summary (denormalized for performance)
    host_count INTEGER DEFAULT 0,
    port_count INTEGER DEFAULT 0,

    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE,
    FOREIGN KEY (plugin_id) REFERENCES plugins(plugin_id),

    CONSTRAINT valid_review_state CHECK (review_state IN ('pending', 'reviewed', 'completed', 'skipped')),
    CONSTRAINT unique_scan_plugin UNIQUE (scan_id, plugin_id)
);

CREATE INDEX IF NOT EXISTS idx_plugin_files_scan ON plugin_files(scan_id);
CREATE INDEX IF NOT EXISTS idx_plugin_files_plugin ON plugin_files(plugin_id);
CREATE INDEX IF NOT EXISTS idx_plugin_files_review_state ON plugin_files(review_state);

-- ============================================================================
-- PLUGIN_FILE_HOSTS: Host:port combinations per plugin file
-- ============================================================================
CREATE TABLE IF NOT EXISTS plugin_file_hosts (
    host_id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id INTEGER NOT NULL,

    host TEXT NOT NULL,                 -- IP address or hostname
    port INTEGER,                       -- NULL if no port specified

    -- Host metadata
    is_ipv4 BOOLEAN DEFAULT 0,
    is_ipv6 BOOLEAN DEFAULT 0,

    -- Plugin output (extracted from .nessus <plugin_output> element)
    plugin_output TEXT,                 -- Host-specific Nessus scanner output

    FOREIGN KEY (file_id) REFERENCES plugin_files(file_id) ON DELETE CASCADE,

    CONSTRAINT unique_file_host_port UNIQUE (file_id, host, port)
);

CREATE INDEX IF NOT EXISTS idx_plugin_file_hosts_file ON plugin_file_hosts(file_id);
CREATE INDEX IF NOT EXISTS idx_plugin_file_hosts_host ON plugin_file_hosts(host);

-- ============================================================================
-- SESSIONS: Review session tracking (INTERNAL - no user-facing commands)
-- ============================================================================
CREATE TABLE IF NOT EXISTS sessions (
    session_id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,

    session_start TIMESTAMP NOT NULL,
    session_end TIMESTAMP,
    duration_seconds INTEGER,           -- Computed on session_end

    -- Session statistics
    files_reviewed INTEGER DEFAULT 0,
    files_completed INTEGER DEFAULT 0,
    files_skipped INTEGER DEFAULT 0,
    tools_executed INTEGER DEFAULT 0,
    cves_extracted INTEGER DEFAULT 0,

    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_sessions_scan ON sessions(scan_id);
CREATE INDEX IF NOT EXISTS idx_sessions_start ON sessions(session_start);

-- ============================================================================
-- TOOL_EXECUTIONS: Track every tool run
-- ============================================================================
CREATE TABLE IF NOT EXISTS tool_executions (
    execution_id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER,                 -- NULL if run outside session
    file_id INTEGER,                    -- Which plugin file triggered this

    -- Tool identification
    tool_name TEXT NOT NULL,            -- 'nmap', 'netexec', 'metasploit', 'custom'
    tool_protocol TEXT,                 -- For netexec: 'smb', 'ssh', 'rdp', etc.

    -- Command details
    command_text TEXT NOT NULL,         -- Full command as string
    command_args TEXT,                  -- JSON array of arguments

    -- Execution metadata
    executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    exit_code INTEGER,
    duration_seconds REAL,

    -- Host/port context
    host_count INTEGER,
    sampled BOOLEAN DEFAULT 0,          -- Was host list sampled (>5 hosts)?
    ports TEXT,                         -- Comma-separated port list

    -- Sudo usage
    used_sudo BOOLEAN DEFAULT 0,

    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE SET NULL,
    FOREIGN KEY (file_id) REFERENCES plugin_files(file_id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_tool_executions_session ON tool_executions(session_id);
CREATE INDEX IF NOT EXISTS idx_tool_executions_file ON tool_executions(file_id);
CREATE INDEX IF NOT EXISTS idx_tool_executions_tool ON tool_executions(tool_name);
CREATE INDEX IF NOT EXISTS idx_tool_executions_executed ON tool_executions(executed_at);

-- ============================================================================
-- ARTIFACTS: Track all generated output files
-- ============================================================================
CREATE TABLE IF NOT EXISTS artifacts (
    artifact_id INTEGER PRIMARY KEY AUTOINCREMENT,
    execution_id INTEGER,               -- NULL if manually created

    -- Artifact identification
    artifact_path TEXT NOT NULL UNIQUE, -- Absolute path
    artifact_type TEXT NOT NULL,        -- 'nmap_xml', 'nmap_gnmap', 'nmap_nmap',
                                        -- 'netexec_log', 'metasploit_rc', 'custom'

    -- File metadata
    file_size_bytes INTEGER,
    file_hash TEXT,                     -- SHA256

    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_accessed_at TIMESTAMP,

    -- Artifact-specific metadata (JSON)
    metadata TEXT,                      -- JSON: {"nse_scripts": [...], "udp": true, ...}

    FOREIGN KEY (execution_id) REFERENCES tool_executions(execution_id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_artifacts_execution ON artifacts(execution_id);
CREATE INDEX IF NOT EXISTS idx_artifacts_type ON artifacts(artifact_type);
CREATE INDEX IF NOT EXISTS idx_artifacts_path ON artifacts(artifact_path);

-- ============================================================================
-- WORKFLOWS: Custom workflow tracking
-- ============================================================================
CREATE TABLE IF NOT EXISTS workflow_executions (
    workflow_execution_id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id INTEGER,
    workflow_name TEXT NOT NULL,

    -- Workflow tracking
    executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed BOOLEAN DEFAULT 0,

    -- Workflow results (JSON)
    results TEXT,                       -- JSON: {"step1": "ok", "step2": "failed", ...}

    FOREIGN KEY (file_id) REFERENCES plugin_files(file_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_workflow_executions_file ON workflow_executions(file_id);
CREATE INDEX IF NOT EXISTS idx_workflow_executions_workflow ON workflow_executions(workflow_name);

-- ============================================================================
-- VIEWS: Common queries for reporting
-- ============================================================================

-- Review progress per scan and severity
CREATE VIEW IF NOT EXISTS v_review_progress AS
SELECT
    s.scan_name,
    pf.severity_dir,
    COUNT(*) as total_files,
    SUM(CASE WHEN pf.review_state = 'completed' THEN 1 ELSE 0 END) as completed,
    SUM(CASE WHEN pf.review_state = 'reviewed' THEN 1 ELSE 0 END) as reviewed,
    SUM(CASE WHEN pf.review_state = 'skipped' THEN 1 ELSE 0 END) as skipped,
    SUM(CASE WHEN pf.review_state = 'pending' THEN 1 ELSE 0 END) as pending,
    ROUND(100.0 * SUM(CASE WHEN pf.review_state = 'completed' THEN 1 ELSE 0 END) / COUNT(*), 1) as completion_pct
FROM scans s
JOIN plugin_files pf ON pf.scan_id = s.scan_id
GROUP BY s.scan_name, pf.severity_dir
ORDER BY s.scan_name, pf.severity_dir DESC;

-- Session statistics
CREATE VIEW IF NOT EXISTS v_session_stats AS
SELECT
    sess.session_id,
    sess.session_start,
    sess.session_end,
    sess.duration_seconds,
    s.scan_name,
    sess.tools_executed,
    sess.cves_extracted,
    sess.files_completed,
    sess.files_reviewed,
    sess.files_skipped
FROM sessions sess
JOIN scans s ON s.scan_id = sess.scan_id
ORDER BY sess.session_start DESC;

-- Tool execution summary
CREATE VIEW IF NOT EXISTS v_tool_summary AS
SELECT
    te.tool_name,
    te.tool_protocol,
    COUNT(*) as execution_count,
    AVG(te.duration_seconds) as avg_duration,
    SUM(CASE WHEN te.exit_code = 0 THEN 1 ELSE 0 END) as success_count,
    SUM(CASE WHEN te.exit_code != 0 THEN 1 ELSE 0 END) as failure_count,
    COUNT(DISTINCT a.artifact_id) as artifacts_created
FROM tool_executions te
LEFT JOIN artifacts a ON a.execution_id = te.execution_id
GROUP BY te.tool_name, te.tool_protocol
ORDER BY execution_count DESC;

-- Artifact storage summary
CREATE VIEW IF NOT EXISTS v_artifact_storage AS
SELECT
    a.artifact_type,
    COUNT(*) as file_count,
    SUM(a.file_size_bytes) as total_bytes,
    ROUND(SUM(a.file_size_bytes) / 1024.0 / 1024.0, 2) as total_mb,
    AVG(a.file_size_bytes) as avg_file_size
FROM artifacts a
GROUP BY a.artifact_type
ORDER BY total_bytes DESC;

-- ============================================================================
-- PRAGMA SETTINGS (applied at connection time by database.py)
-- ============================================================================
-- PRAGMA journal_mode=WAL;        -- Write-Ahead Logging for concurrency
-- PRAGMA foreign_keys=ON;         -- Enable referential integrity
-- PRAGMA synchronous=NORMAL;      -- Balance between safety and performance
-- PRAGMA temp_store=MEMORY;       -- Keep temp tables in memory
-- PRAGMA cache_size=-64000;       -- 64MB cache
