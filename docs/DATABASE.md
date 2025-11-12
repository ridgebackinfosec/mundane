# Mundane Database Documentation

Mundane includes an **integrated SQLite database** for tracking scan metadata, review state, tool executions, and generated artifacts. This provides an audit trail, enables historical analysis, and supports advanced queries across multiple scans.

---

## Table of Contents

- [Overview](#overview)
- [Database Location](#database-location)
- [Dual-Mode Operation](#dual-mode-operation)
- [Schema Overview](#schema-overview)
- [Table Descriptions](#table-descriptions)
- [Views and Reports](#views-and-reports)
- [Query Examples](#query-examples)
- [Environment Variables](#environment-variables)
- [Schema Reference](#schema-reference)

---

## Overview

The Mundane database tracks:

- **Scans**: Nessus export metadata (scan name, export root, .nessus file hash)
- **Plugins**: Vulnerability findings (plugin ID, name, severity, CVSS scores, CVEs)
- **Plugin Files**: Individual .txt files per scan (file paths, review state, host counts)
- **Sessions**: Review session state (start time, duration, statistics)
- **Tool Executions**: Commands run during reviews (tool name, exit codes, duration)
- **Artifacts**: Generated files from tool runs (file paths, SHA256 hashes, sizes)
- **Workflows**: Custom workflow execution tracking

All operations work **transparently** - no manual database management required.

---

## Database Location

**Default Path**: `~/.mundane/mundane.db`

The database is global across all scans, enabling cross-scan queries and historical analysis.

**Directory**: `~/.mundane/` is created automatically on first use.

---

## Dual-Mode Operation

Mundane operates in **dual-mode** by default - data is written to both:

1. **SQLite database** (`~/.mundane/mundane.db`)
2. **JSON session files** (`.mundane_session.json` in scan directory)

This ensures:
- **Compatibility**: Existing workflows using JSON files continue working
- **Migration path**: Users can adopt database features gradually
- **Audit trail**: Database tracks historical data across sessions

### Operating Modes

| Mode | `MUNDANE_USE_DB` | `MUNDANE_DB_ONLY` | Behavior |
|---|---|---|---|
| **Dual-mode** (default) | `1` | `0` | Database + JSON files |
| **Database-only** | `1` | `1` | Database only, no JSON files |
| **Legacy** | `0` | - | JSON files only, no database |

---

## Schema Overview

The database consists of **11 tables** and **4 views**:

### Core Tables

1. **scans** - Top-level scan tracking
2. **plugins** - Plugin metadata (Nessus plugin ID, severity, CVEs)
3. **plugin_files** - Exported .txt files per scan
4. **plugin_file_hosts** - Host:port combinations per file

### Review Tracking

5. **sessions** - Review session tracking
6. **tool_executions** - Commands run during reviews
7. **artifacts** - Generated output files
8. **workflow_executions** - Custom workflow tracking

### Views (Pre-Built Queries)

- **v_review_progress** - Review progress by scan and severity
- **v_session_stats** - Session statistics with scan details
- **v_tool_summary** - Tool execution summary with success/failure rates
- **v_artifact_storage** - Artifact storage summary by type

---

## Table Descriptions

### scans

Top-level scan tracking - one row per Nessus export.

| Column | Type | Description |
|---|---|---|
| `scan_id` | INTEGER | Primary key (auto-increment) |
| `scan_name` | TEXT | Unique scan name (from import command or export directory) |
| `nessus_file_path` | TEXT | Original .nessus file path |
| `nessus_file_hash` | TEXT | SHA256 of .nessus file for change detection |
| `export_root` | TEXT | Where plugin .txt files are stored |
| `created_at` | TIMESTAMP | Scan creation time |
| `last_reviewed_at` | TIMESTAMP | Last review session timestamp |

**Relationships**: One scan has many plugin_files, sessions

---

### plugins

Plugin metadata - one row per Nessus plugin ID.

| Column | Type | Description |
|---|---|---|
| `plugin_id` | INTEGER | Nessus plugin ID (e.g., 57608) |
| `plugin_name` | TEXT | Plugin name |
| `severity_int` | INTEGER | 0=Info, 1=Low, 2=Medium, 3=High, 4=Critical |
| `severity_label` | TEXT | "Info", "Low", "Medium", "High", "Critical" |
| `has_metasploit` | BOOLEAN | Metasploit module availability |
| `cvss3_score` | REAL | CVSS v3 base score |
| `cvss2_score` | REAL | CVSS v2 base score (fallback) |
| `cves` | TEXT | JSON array of CVE IDs (NULL until fetched) |
| `plugin_url` | TEXT | Tenable plugin URL |
| `metadata_fetched_at` | TIMESTAMP | When CVEs were fetched by user |

**Note**: "plugin" is internal terminology. User-facing commands use "findings".

**Relationships**: One plugin has many plugin_files (across different scans)

---

### plugin_files

Exported .txt files - one row per plugin per scan.

| Column | Type | Description |
|---|---|---|
| `file_id` | INTEGER | Primary key |
| `scan_id` | INTEGER | Foreign key to scans |
| `plugin_id` | INTEGER | Foreign key to plugins |
| `file_path` | TEXT | Absolute path to .txt file (unique) |
| `severity_dir` | TEXT | e.g., "3_High", "4_Critical" |
| `review_state` | TEXT | 'pending', 'reviewed', 'completed', 'skipped' |
| `reviewed_at` | TIMESTAMP | When file was reviewed |
| `reviewed_by` | TEXT | User tracking (future feature) |
| `review_notes` | TEXT | User notes (future feature) |
| `host_count` | INTEGER | Number of unique hosts |
| `port_count` | INTEGER | Number of unique ports |
| `file_created_at` | TIMESTAMP | File creation time |
| `file_modified_at` | TIMESTAMP | File modification time |
| `last_parsed_at` | TIMESTAMP | Last time file was parsed |

**Review State Values**:
- `pending` - Not yet reviewed
- `reviewed` - File opened/viewed
- `completed` - Marked as REVIEW_COMPLETE
- `skipped` - Intentionally skipped

**Relationships**: Belongs to one scan and one plugin. Has many plugin_file_hosts and tool_executions.

---

### plugin_file_hosts

Host:port combinations - parsed from plugin .txt files.

| Column | Type | Description |
|---|---|---|
| `host_id` | INTEGER | Primary key |
| `file_id` | INTEGER | Foreign key to plugin_files |
| `host` | TEXT | IP address or hostname |
| `port` | INTEGER | Port number (NULL if no port) |
| `is_ipv4` | BOOLEAN | IPv4 address flag |
| `is_ipv6` | BOOLEAN | IPv6 address flag |

**Relationships**: Belongs to one plugin_file

---

### sessions

Review session tracking - one row per review session.

| Column | Type | Description |
|---|---|---|
| `session_id` | INTEGER | Primary key |
| `scan_id` | INTEGER | Foreign key to scans |
| `session_start` | TIMESTAMP | Session start time |
| `session_end` | TIMESTAMP | Session end time |
| `duration_seconds` | INTEGER | Session duration (computed on end) |
| `files_reviewed` | INTEGER | Count of reviewed files |
| `files_completed` | INTEGER | Count of completed files |
| `files_skipped` | INTEGER | Count of skipped files |
| `tools_executed` | INTEGER | Count of tool runs |
| `cves_extracted` | INTEGER | Count of CVE extractions |

**Relationships**: Belongs to one scan. Has many tool_executions.

---

### tool_executions

Command execution tracking - one row per tool run.

| Column | Type | Description |
|---|---|---|
| `execution_id` | INTEGER | Primary key |
| `session_id` | INTEGER | Foreign key to sessions (NULL if outside session) |
| `file_id` | INTEGER | Which plugin file triggered this |
| `tool_name` | TEXT | 'nmap', 'netexec', 'metasploit', 'custom' |
| `tool_protocol` | TEXT | For netexec: 'smb', 'ssh', 'rdp', etc. |
| `command_text` | TEXT | Full command as string |
| `command_args` | TEXT | JSON array of arguments |
| `executed_at` | TIMESTAMP | Execution timestamp |
| `exit_code` | INTEGER | Command exit code |
| `duration_seconds` | REAL | Execution duration |
| `host_count` | INTEGER | Number of hosts targeted |
| `sampled` | BOOLEAN | Was host list sampled (>5 hosts)? |
| `ports` | TEXT | Comma-separated port list |
| `used_sudo` | BOOLEAN | Was sudo used? |

**Relationships**: Belongs to one session and one plugin_file. Has many artifacts.

---

### artifacts

Generated output files - one row per artifact file.

| Column | Type | Description |
|---|---|---|
| `artifact_id` | INTEGER | Primary key |
| `execution_id` | INTEGER | Foreign key to tool_executions |
| `artifact_path` | TEXT | Absolute path (unique) |
| `artifact_type` | TEXT | 'nmap_xml', 'nmap_gnmap', 'netexec_log', etc. |
| `file_size_bytes` | INTEGER | File size in bytes |
| `file_hash` | TEXT | SHA256 hash |
| `created_at` | TIMESTAMP | Creation timestamp |
| `last_accessed_at` | TIMESTAMP | Last access time |
| `metadata` | TEXT | JSON metadata (NSE scripts, UDP flag, etc.) |

**Artifact Types**:
- `nmap_xml` - Nmap XML output
- `nmap_gnmap` - Nmap grepable output
- `nmap_nmap` - Nmap normal output
- `netexec_log` - NetExec/nxc output
- `metasploit_rc` - Metasploit resource script
- `custom` - Custom tool output

**Relationships**: Belongs to one tool_execution

---

### workflow_executions

Custom workflow tracking - one row per workflow execution.

| Column | Type | Description |
|---|---|---|
| `workflow_execution_id` | INTEGER | Primary key |
| `file_id` | INTEGER | Foreign key to plugin_files |
| `workflow_name` | TEXT | Workflow identifier |
| `executed_at` | TIMESTAMP | Execution timestamp |
| `completed` | BOOLEAN | Completion status |
| `results` | TEXT | JSON results (step outcomes) |

**Relationships**: Belongs to one plugin_file

---

## Views and Reports

Pre-built views for common queries:

### v_review_progress

Review progress by scan and severity.

**Columns**: `scan_name`, `severity_dir`, `total_files`, `completed`, `reviewed`, `skipped`, `pending`, `completion_pct`

**Example**:
```sql
SELECT * FROM v_review_progress WHERE scan_name = 'GOAD';
```

---

### v_session_stats

Session statistics with scan details.

**Columns**: `session_id`, `session_start`, `session_end`, `duration_seconds`, `scan_name`, `tools_executed`, `cves_extracted`, `files_completed`, `files_reviewed`, `files_skipped`

**Example**:
```sql
SELECT * FROM v_session_stats ORDER BY session_start DESC LIMIT 10;
```

---

### v_tool_summary

Tool execution summary with success/failure rates.

**Columns**: `tool_name`, `tool_protocol`, `execution_count`, `avg_duration`, `success_count`, `failure_count`, `artifacts_created`

**Example**:
```sql
SELECT * FROM v_tool_summary WHERE tool_name = 'nmap';
```

---

### v_artifact_storage

Artifact storage summary by type.

**Columns**: `artifact_type`, `file_count`, `total_bytes`, `total_mb`, `avg_file_size`

**Example**:
```sql
SELECT * FROM v_artifact_storage ORDER BY total_mb DESC;
```

---

## Query Examples

### Find All Nmap Scans for a Specific Host

```sql
SELECT
    te.executed_at,
    te.command_text,
    a.artifact_path,
    a.file_size_bytes
FROM tool_executions te
JOIN artifacts a ON a.execution_id = te.execution_id
WHERE te.tool_name = 'nmap'
  AND te.command_text LIKE '%192.168.1.1%'
ORDER BY te.executed_at DESC;
```

---

### Review Progress Across All Scans

```sql
SELECT
    s.scan_name,
    COUNT(*) as total_files,
    SUM(CASE WHEN pf.review_state = 'completed' THEN 1 ELSE 0 END) as completed,
    ROUND(100.0 * SUM(CASE WHEN pf.review_state = 'completed' THEN 1 ELSE 0 END) / COUNT(*), 1) as completion_pct
FROM scans s
JOIN plugin_files pf ON pf.scan_id = s.scan_id
GROUP BY s.scan_name
ORDER BY completion_pct DESC;
```

---

### Find Critical Plugins with Metasploit Modules

```sql
SELECT
    p.plugin_id,
    p.plugin_name,
    p.cvss3_score,
    COUNT(DISTINCT pf.scan_id) as scan_count,
    GROUP_CONCAT(DISTINCT s.scan_name) as affected_scans
FROM plugins p
JOIN plugin_files pf ON pf.plugin_id = p.plugin_id
JOIN scans s ON s.scan_id = pf.scan_id
WHERE p.severity_int = 4  -- Critical
  AND p.has_metasploit = 1
GROUP BY p.plugin_id
ORDER BY p.cvss3_score DESC;
```

---

### Tool Execution History for a Scan

```sql
SELECT
    te.executed_at,
    te.tool_name,
    te.tool_protocol,
    te.command_text,
    te.exit_code,
    te.duration_seconds,
    te.used_sudo,
    COUNT(a.artifact_id) as artifact_count
FROM tool_executions te
JOIN sessions sess ON sess.session_id = te.session_id
JOIN scans s ON s.scan_id = sess.scan_id
LEFT JOIN artifacts a ON a.execution_id = te.execution_id
WHERE s.scan_name = 'GOAD'
GROUP BY te.execution_id
ORDER BY te.executed_at;
```

---

### Find Duplicate Hosts Across Multiple Plugins

```sql
SELECT
    pfh.host,
    COUNT(DISTINCT pf.plugin_id) as plugin_count,
    GROUP_CONCAT(DISTINCT p.plugin_name) as plugins,
    GROUP_CONCAT(DISTINCT pf.severity_dir) as severities
FROM plugin_file_hosts pfh
JOIN plugin_files pf ON pf.file_id = pfh.file_id
JOIN plugins p ON p.plugin_id = pf.plugin_id
WHERE pf.scan_id = (SELECT scan_id FROM scans WHERE scan_name = 'GOAD')
GROUP BY pfh.host
HAVING COUNT(DISTINCT pf.plugin_id) > 1
ORDER BY plugin_count DESC;
```

---

### Session Duration Statistics

```sql
SELECT
    s.scan_name,
    COUNT(sess.session_id) as session_count,
    AVG(sess.duration_seconds) / 60.0 as avg_duration_minutes,
    MAX(sess.duration_seconds) / 60.0 as max_duration_minutes,
    SUM(sess.tools_executed) as total_tools_executed,
    SUM(sess.files_completed) as total_files_completed
FROM sessions sess
JOIN scans s ON s.scan_id = sess.scan_id
WHERE sess.session_end IS NOT NULL
GROUP BY s.scan_name;
```

---

### Artifact Storage by Scan

```sql
SELECT
    s.scan_name,
    a.artifact_type,
    COUNT(*) as file_count,
    SUM(a.file_size_bytes) / 1024.0 / 1024.0 as total_mb,
    AVG(a.file_size_bytes) / 1024.0 as avg_kb
FROM artifacts a
JOIN tool_executions te ON te.execution_id = a.execution_id
JOIN sessions sess ON sess.session_id = te.session_id
JOIN scans s ON s.scan_id = sess.scan_id
GROUP BY s.scan_name, a.artifact_type
ORDER BY s.scan_name, total_mb DESC;
```

---

### Compare Findings Across Two Scans

```sql
SELECT
    p.plugin_id,
    p.plugin_name,
    p.severity_label,
    s1.host_count as scan1_hosts,
    s2.host_count as scan2_hosts,
    ABS(s1.host_count - s2.host_count) as difference
FROM plugins p
LEFT JOIN (
    SELECT pf.plugin_id, SUM(pf.host_count) as host_count
    FROM plugin_files pf
    JOIN scans s ON s.scan_id = pf.scan_id
    WHERE s.scan_name = 'Scan1'
    GROUP BY pf.plugin_id
) s1 ON s1.plugin_id = p.plugin_id
LEFT JOIN (
    SELECT pf.plugin_id, SUM(pf.host_count) as host_count
    FROM plugin_files pf
    JOIN scans s ON s.scan_id = pf.scan_id
    WHERE s.scan_name = 'Scan2'
    GROUP BY pf.plugin_id
) s2 ON s2.plugin_id = p.plugin_id
WHERE s1.host_count IS NOT NULL OR s2.host_count IS NOT NULL
ORDER BY difference DESC;
```

---

## Environment Variables

Control database behavior with these environment variables:

| Variable | Description | Values | Default |
|---|---|---|---|
| `MUNDANE_USE_DB` | Enable database integration | `0`, `1`, `true`, `on` | `1` |
| `MUNDANE_DB_ONLY` | Skip JSON session files | `0`, `1`, `true`, `on` | `0` |

**Examples**:

```bash
# Disable database entirely (legacy mode)
export MUNDANE_USE_DB=0
mundane review --export-root ~/.mundane/scans/<scan_name>

# Use database-only mode (no JSON session files)
export MUNDANE_DB_ONLY=1
mundane review --export-root ~/.mundane/scans/<scan_name>
```

---

## Schema Reference

Full schema available in [`schema.sql`](../schema.sql).

### Database Initialization

The database is initialized automatically on first use. Schema creation is handled by `mundane_pkg/database.py:initialize_database()`.

### PRAGMA Settings

Applied at connection time for optimal performance:

```sql
PRAGMA journal_mode=WAL;        -- Write-Ahead Logging for concurrency
PRAGMA foreign_keys=ON;         -- Enable referential integrity
PRAGMA synchronous=NORMAL;      -- Balance safety and performance
PRAGMA temp_store=MEMORY;       -- Keep temp tables in memory
PRAGMA cache_size=-64000;       -- 64MB cache
```

### Foreign Key Relationships

```
scans
  ├── plugin_files (scan_id) - CASCADE DELETE
  └── sessions (scan_id) - CASCADE DELETE

plugins
  └── plugin_files (plugin_id) - RESTRICT DELETE

plugin_files
  ├── plugin_file_hosts (file_id) - CASCADE DELETE
  ├── tool_executions (file_id) - SET NULL DELETE
  └── workflow_executions (file_id) - CASCADE DELETE

sessions
  └── tool_executions (session_id) - SET NULL DELETE

tool_executions
  └── artifacts (execution_id) - SET NULL DELETE
```

**Cascade Rules**:
- Deleting a scan removes all plugin_files, sessions, and dependent records
- Deleting a plugin_file removes all hosts and workflow_executions
- Deleting a session or tool_execution sets foreign keys to NULL (preserves artifacts)

---

## Advanced Usage

### Direct Database Access

Connect to the database directly with SQLite tools:

```bash
# Open database in sqlite3 CLI
sqlite3 ~/.mundane/mundane.db

# Run a query
sqlite3 ~/.mundane/mundane.db "SELECT * FROM v_review_progress;"

# Export to CSV
sqlite3 -csv ~/.mundane/mundane.db "SELECT * FROM v_session_stats;" > sessions.csv
```

### Database Maintenance

```bash
# Check database integrity
sqlite3 ~/.mundane/mundane.db "PRAGMA integrity_check;"

# Optimize database (reclaim space)
sqlite3 ~/.mundane/mundane.db "VACUUM;"

# Database statistics
sqlite3 ~/.mundane/mundane.db "PRAGMA page_count; PRAGMA page_size;"
```

### Backup Database

```bash
# Create backup
cp ~/.mundane/mundane.db ~/.mundane/mundane.db.backup

# Or use SQLite backup command
sqlite3 ~/.mundane/mundane.db ".backup ~/.mundane/mundane.db.backup"
```

---

## Future Enhancements

Planned database features (see [TODO.md](../TODO.md)):

- **Migration command**: Import existing JSON sessions into database
- **Enhanced summary command**: Cross-scan analysis, trend analysis
- **Database query utilities**: Custom SQL queries, exports, statistics
- **Web UI**: Database-backed web interface for team collaboration
- **Cloud database support**: Optional PostgreSQL/MySQL for teams

---

**Last Updated**: 2024-01-12
**Maintained By**: Ridgeback InfoSec, LLC
