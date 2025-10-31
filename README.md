# mundane.py

A modernized **TUI helper** to review Nessus plugin host files quickly and kick off focused checks with **nmap**, **NetExec**, or custom commands. Includes a one-step **wizard** to seed an export structure directly from a `.nessus` file.

---

## Requirements

- **Python 3.11+** (3.8+ may still work but is not the target)
- Install Python deps:
  ```bash
  pip install -r requirements.txt
  ```
  Uses: `rich`, `typer`, `pyperclip`, `colorama`, `loguru`, `requests`, `beautifulsoup4`, `pyyaml`
- Optional external tools (only when you run them):
  - `git` – used by the wizard to clone **NessusPluginHosts**
  - `nmap`
  - `nxc` / `netexec`
  - `msfconsole` – for Metasploit module searches
- Linux recommended. For clipboard copy you may need `xclip`, `xsel`, or `wl-copy`.

---

## Environment configuration (no config files required)

All runtime defaults are controlled via environment variables:

| Variable | Description | Default |
|---|---|---|
| `MUNDANE_LOG` | Log file path | `~/mundane.log` |
| `MUNDANE_DEBUG` | DEBUG logging when truthy (`1`, `true`, `on`) | off |
| `MUNDANE_PROMPT` | Enable confirmation prompts | on |
| `MUNDANE_SUDO_PREFLIGHT` | Run sudo preflight checks | on |

Example:
```bash
export MUNDANE_LOG="$PWD/mundane.log"
export MUNDANE_DEBUG=1
python mundane.py review
tail -f mundane.log
```

---

## Logging & diagnostics

- Prefers **loguru** with rotation/retention; automatically falls back to stdlib `logging` if unavailable or file sink creation fails.
- Parent directory is created for the log file.
- `_log_info/_log_debug/_log_error` shims keep the rest of the code backend‑agnostic.
- Global `sys.excepthook` logs unhandled exceptions (Rich still shows pretty tracebacks).
- `@log_timing` decorates key functions to log execution time at DEBUG level.

---

## Quick start

### 1) Seed exports from a `.nessus` (wizard)
Clone **NessusPluginHosts** and export plugin hostlists into `./nessus_plugin_hosts`:

```bash
python mundane.py wizard path/to/scan.nessus
# immediately start reviewing after export:
python mundane.py wizard path/to/scan.nessus --review
# customize clone/output locations:
python mundane.py wizard scan.nessus --repo-dir ./vendor/NessusPluginHosts --out-dir ./nessus_plugin_hosts
```

### 2) Review exports interactively
```bash
python mundane.py review --export-root ./nessus_plugin_hosts
```

---

## Features

- **Browse scans & severities** in Rich tables.
- **Preview plugin files** before acting (with a link to Tenable plugin details).
- **Paged views** with `[N]ext`, `[P]rev`, `[B]ack` navigation.
- **Grouped view** (`host:port,port`) or raw file view.
- **Clipboard copy** for any file or command.
- **CVE extraction** - View CVE identifiers for plugins:
  - Individual file view: Press `[E]` to fetch CVEs for the current plugin
  - Bulk extraction: Press `[E]` in file list to extract CVEs for all filtered files
  - Choose between separated-by-file or combined list display
- **Metasploit module search** - Search for relevant Metasploit modules by CVE or description:
  - Automatically extracts CVEs and exploit descriptions from plugin pages
  - Generates `msfconsole` search commands (simplified - single command per term)
  - Execute searches directly with progress spinner and confirmation prompts
  - Return to command list after execution to run multiple searches
- **Workflow mappings** - Plugin-specific verification workflows:
  - YAML-based configuration mapping plugin IDs to verification steps
  - Display-only workflows with commands, notes, and references
  - Press `[W]` when viewing a file to see its verification workflow (if available)
  - Ships with example workflows for common vulnerabilities (SMB signing, anonymous FTP, weak SSL, etc.)
  - Support for multi-plugin workflows (comma-separated plugin IDs map to single workflow)
  - Supplement defaults with `--custom-workflows` (custom overrides on conflict)
  - Replace defaults entirely with `--custom-workflows-only`
- **Session persistence** - Resume interrupted review sessions:
  - Auto-saves session state to `.mundane_session.json` in scan directory
  - Resume prompt on startup with session details (reviewed/completed/skipped counts)
  - Tracks session start time for accurate duration statistics
  - Auto-cleanup after successful completion
- **Reversible review-complete** - Undo accidentally marked files:
  - Press `[U]` in reviewed files menu to undo review-complete prefix
  - Multi-select support: individual files (1,3,5) or `[A]ll`
- **Session end statistics** - Rich statistics display:
  - Session duration with hours/minutes/seconds
  - Per-severity breakdown for completed files
  - Detailed file lists (reviewed, completed, skipped)
- **Wizard post-export suggestions** - Suggested commands after wizard completes:
  - eyewitness (web screenshot tool)
  - gowitness (web screenshot tool)
  - msfconsole db_import
- **Run tools** against hosts:
  - `nmap` (profiles and UDP handling supported)
  - `netexec` / `nxc`
  - **Custom templates** with placeholder substitution
- **Compare** plugin hostlists across severities.
- **Coverage/superset** analysis across files.
- **Bulk mark** reviewed files as `REVIEW_COMPLETE-...`.
- **Scan overview** summaries (totals, top ports, identical groups).
- **Progress indicators** for cloning, parsing, exporting, or running tools.
- **Registry-driven tool system** (nmap/netexec/metasploit today; others can be added later).

---

## Commands (common)

```bash
# Wizard: seed exported plugin files from a .nessus scan (then optionally review)
python mundane.py wizard <scan.nessus> [--repo-dir DIR] [--out-dir DIR] [--review]

# Interactive review (main workflow)
python mundane.py review --export-root ./nessus_plugin_hosts [--no-tools] [--custom-workflows PATH] [--custom-workflows-only PATH]

# Summarize a scan directory
python mundane.py summary ./nessus_plugin_hosts/<ScanName> [--top-ports 10]

# Compare/group identical host:port combos across files
python mundane.py compare 4_Critical/*.txt

# Quick file preview
python mundane.py view nessus_plugin_hosts/<Scan>/<Severity>/<Plugin>.txt [--grouped]
```

---

## Custom workflow options

The `review` command supports custom workflow YAML files to extend or replace the bundled workflows:

### Supplement mode (merge with defaults)
```bash
python mundane.py review --export-root ./nessus_plugin_hosts --custom-workflows my_workflows.yaml
# Short form:
python mundane.py review --export-root ./nessus_plugin_hosts -w my_workflows.yaml
```
- Loads bundled workflows from `workflow_mappings.yaml`
- Merges in custom workflows from specified file
- **Custom workflows override defaults** if plugin IDs conflict
- Useful for adding organization-specific workflows while keeping bundled ones

### Replace mode (ignore defaults)
```bash
python mundane.py review --export-root ./nessus_plugin_hosts --custom-workflows-only my_workflows.yaml
```
- Loads **only** custom workflows from specified file
- Ignores bundled `workflow_mappings.yaml` entirely
- Useful for completely custom workflow sets

**Note**: Cannot use both `--custom-workflows` and `--custom-workflows-only` together.

### Custom workflow YAML format
```yaml
version: "1.0"
workflows:
  - plugin_id: "57608,12345"  # Single ID or comma-separated IDs
    workflow_name: "SMB Signing Not Required"
    description: "Remote SMB server does not enforce message signing"
    steps:
      - title: "Verify SMB signing is disabled"
        commands:
          - "netexec smb <target> -u <username> -p <password>"
        notes: "Check output for 'Message signing: disabled'"
    references:
      - "https://www.tenable.com/plugins/nessus/57608"
```

---

## Custom command placeholders

When defining or executing custom commands, placeholders are substituted at runtime:

| Placeholder | Meaning |
|---|---|
| `{TCP_IPS}` | File with one IP per line |
| `{UDP_IPS}` | File with UDP targets |
| `{TCP_HOST_PORTS}` | `host:port1,port2,...` |
| `{PORTS}` | Comma‑separated ports |
| `{WORKDIR}` | Temporary workspace |
| `{RESULTS_DIR}` | Persistent results directory |
| `{OABASE}` | Base path for output artifacts |

**Examples**
```bash
httpx -l {TCP_IPS} -silent -o {OABASE}.urls.txt
nuclei -l {OABASE}.urls.txt -o {OABASE}.nuclei.txt
cat {TCP_IPS} | xargs -I{} sh -c 'echo {}; nmap -Pn -p {PORTS} {}'
```

---

## Architecture notes (Phases 1–6)

- **Canonical parsing**: one parser creates a `ParsedHostsPorts` model (stable host order, unique sorted ports, explicit `host:port` detection) with a small in‑process cache.
- **Data vs render separation**: `build_compare_data()` and `build_coverage_data()` compute pure data; rendering wrappers keep Rich output unchanged.
- **Tool registry**: `ToolSpec` (`builder: Callable[[dict], tuple[Any, dict]]`) with entries for `nmap` and `netexec`; legacy builders remain for backward compatibility.
- **Constants & helpers**: centralized constants; unified severity/label helpers (`_severity_color_name`, `_ansi_from_style`, `label()` + `cyan_label()`).
- **Sudo preflight & prompts**: both enabled by default via env‑driven settings.

---

## Tips

- Disable colors with `NO_COLOR=1` or in a dumb terminal (`TERM=dumb`).
- Not running as root without `sudo` may restrict UDP/NSE; you’ll be warned.
- On headless Linux without clipboard utilities, the script prints copy targets.
- Log rotation (~1 MB) keeps logs manageable.

---

## Directory layout (after wizard)

```
nessus_plugin_hosts/
  <ScanName>/
    4_Critical/
      193421_Apache_2.4.x___2.4.54_Authentication_Bypass.txt
      ...
    3_High/
    2_Medium/
    1_Low/
    0_Info/
scan_artifacts/
  <ScanName>/<Severity>/<PluginBase>/run-YYYYmmdd-HHMMSS.*
```

---

## License

This tool orchestrates local utilities and uses data produced by
[DefensiveOrigins/NessusPluginHosts](https://github.com/DefensiveOrigins/NessusPluginHosts).
Respect all dependencies’ licenses and your organization’s policies.
