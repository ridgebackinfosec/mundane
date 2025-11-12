# mundane.py

A modernized **TUI helper** to review Nessus findings quickly and kick off focused checks with **nmap**, **NetExec**, or custom commands. Includes a one-step **wizard** to seed an export structure directly from a `.nessus` file.

---

## Table of Contents

- [Installation](#installation)
- [Requirements](#requirements)
- [Environment configuration](#environment-configuration-no-config-files-required)
- [Logging & diagnostics](#logging--diagnostics)
- [Quick start](#quick-start)
- [Features](#features)
- [Commands (common)](#commands-common)
- [Custom workflow options](#custom-workflow-options)
- [Custom command placeholders](#custom-command-placeholders)
- [Architecture notes](#architecture-notes-phases-16)
- [Tips](#tips)
- [Directory layout](#directory-layout-after-wizard)
- [License](#license)

---

## Installation

### Option 1: Install with pipx (recommended)

Install directly from GitHub to get the `mundane` command globally:

```bash
pipx install git+https://github.com/ridgebackinfosec/mundane.git
```

Verify installation:
```bash
mundane --help
```

**Benefits:**
- Isolated environment (no dependency conflicts)
- Global `mundane` command available system-wide
- Easy to upgrade: `pipx upgrade mundane`
- Easy to uninstall: `pipx uninstall mundane`

### Option 2: Install with pip

```bash
pip install git+https://github.com/ridgebackinfosec/mundane.git
```

### Option 3: Git clone (for development)

Clone and run directly without installation:

```bash
git clone https://github.com/ridgebackinfosec/mundane.git
cd mundane
pip install -r requirements.txt
python mundane.py --help
```

For development with editable install:
```bash
git clone https://github.com/ridgebackinfosec/mundane.git
cd mundane
pipx install -e .  # or: pip install -e .
mundane --help
```

---

## Requirements

- **Python 3.11+** (3.8+ may still work but is not the target)
- Dependencies (automatically installed with pip/pipx):
  - `rich`, `typer`, `pyperclip`, `colorama`, `loguru`, `requests`, `beautifulsoup4`, `pyyaml`
- Optional external tools (only when you run them):
  - `nmap`
  - `nxc` / `netexec`
  - `msfconsole` – for Metasploit module searches
- Linux recommended. For clipboard copy you may need `xclip`, `xsel`, or `wl-copy`.

---

## Configuration

Mundane supports both **environment variables** and an optional **config file** for user preferences.

### Config file (optional)

Create `~/.mundane/config.yaml` to set persistent preferences:

```bash
# Create an example config file with all options documented
mundane config init
```

**Available settings:**
```yaml
# Paths
results_root: "~/mundane_scans"       # Custom path for scan artifacts

# Display preferences
default_page_size: 20                  # Items per page in lists
top_ports_count: 10                    # Top ports to show in summaries

# Behavior
default_workflow_path: "~/my_workflows.yaml"  # Path to custom workflows
auto_save_session: true                # Auto-save progress (default: true)
confirm_bulk_operations: true          # Confirm bulk actions (default: true)

# Network
http_timeout: 15                       # HTTP request timeout (seconds)

# Tool defaults
default_tool: "nmap"                   # Pre-select tool: nmap, netexec, custom
default_netexec_protocol: "smb"       # Default netexec protocol
nmap_default_profile: "SMB"           # Default NSE profile name
```

All settings are optional - the application works with defaults if no config file exists.

### Environment variables

Environment variables override config file settings:

| Variable | Description | Default |
|---|---|---|
| `MUNDANE_RESULTS_ROOT` | Root directory for mundane artifacts | `mundane_artifacts` |
| `NPH_RESULTS_ROOT` | (Deprecated) Legacy name for `MUNDANE_RESULTS_ROOT` | - |
| `MUNDANE_LOG` | Log file path | `~/mundane.log` |
| `MUNDANE_DEBUG` | DEBUG logging when truthy (`1`, `true`, `on`) | off |
| `MUNDANE_PROMPT` | Enable confirmation prompts | on |
| `MUNDANE_SUDO_PREFLIGHT` | Run sudo preflight checks | on |

**Example:**
```bash
export NPH_RESULTS_ROOT="$HOME/security/scans"
export MUNDANE_LOG="$PWD/mundane.log"
export MUNDANE_DEBUG=1
mundane review --export-root ./nessus_plugin_hosts
tail -f mundane.log
```

**Priority order:** Environment variables > Config file > Application defaults

### Config Management Commands

Mundane provides CLI commands to manage your configuration without manually editing YAML:

#### Create example config file
```bash
# Generate ~/.mundane/config.yaml with all options documented
mundane config-init
```
Creates a commented example config file with all available settings. Useful for first-time setup.

#### View current configuration
```bash
# Display merged configuration from all sources (file + defaults)
mundane config-show
```
Shows a Rich table with all settings, their current values, and sources (file/default/env).

#### Get specific config value
```bash
# Retrieve a single config value
mundane config-get default_page_size
mundane config-get results_root
```
Useful for scripting or checking individual settings.

#### Set config value
```bash
# Set a config value (creates config file if needed)
mundane config-set default_page_size 30
mundane config-set results_root "~/my_scans"
mundane config-set auto_save_session false
```
Updates `~/.mundane/config.yaml` with the new value. Creates the file if it doesn't exist.

**Common workflows:**

```bash
# First-time setup
mundane config-init
# Edit ~/.mundane/config.yaml to customize

# Quick customization without editing YAML
mundane config-set default_page_size 50
mundane config-set default_tool "netexec"

# Check what you've configured
mundane config-show

# Verify specific setting
mundane config-get default_tool
```

**Note:** All config commands are optional - mundane works perfectly with defaults if no config file exists.

---

## Logging & diagnostics

- Prefers **loguru** with rotation/retention; automatically falls back to stdlib `logging` if unavailable or file sink creation fails.
- Parent directory is created for the log file.
- `_log_info/_log_debug/_log_error` shims keep the rest of the code backend‑agnostic.
- Global `sys.excepthook` logs unhandled exceptions (Rich still shows pretty tracebacks).
- `@log_timing` decorates key functions to log execution time at DEBUG level.

---

## Quick start

**Got 5 minutes and a `.nessus` scan file?** Try this:

```bash
# 1. Export plugins from your scan
python mundane.py wizard myscan.nessus --review

# That's it! The wizard will:
#   - Parse your .nessus file
#   - Export all plugins to ./nessus_plugin_hosts/
#   - Launch the interactive review TUI
```

**Already have exported plugin files?** Jump straight to review:

```bash
python mundane.py review --export-root ./nessus_plugin_hosts
```

### 1) Export plugins from a `.nessus` (wizard)
Export plugin hostlists from `.nessus` file into `./nessus_plugin_hosts`:

```bash
python mundane.py wizard path/to/scan.nessus
# immediately start reviewing after export:
python mundane.py wizard path/to/scan.nessus --review
# customize output location:
python mundane.py wizard scan.nessus --out-dir ./nessus_plugin_hosts
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
# Wizard: export plugin files from a .nessus scan (then optionally review)
python mundane.py wizard <scan.nessus> [--out-dir DIR] [--review]

# Interactive review (main workflow)
python mundane.py review --export-root ./nessus_plugin_hosts [--no-tools] [--custom-workflows PATH] [--custom-workflows-only PATH]

# Summarize a scan directory
python mundane.py summary ./nessus_plugin_hosts/<ScanName> [--top-ports 10]

# Compare/group identical host:port combos across files
python mundane.py compare 4_Critical/*.txt

# Quick file preview
python mundane.py view nessus_plugin_hosts/<Scan>/<Severity>/<Plugin>.txt [--grouped]

# Config management
mundane config-init                    # Create example config file
mundane config-show                    # Display current configuration
mundane config-get <key>               # Get specific config value
mundane config-set <key> <value>       # Set config value
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
mundane_artifacts/
  <ScanName>/<Severity>/<PluginBase>/run-YYYYmmdd-HHMMSS.*
```

---

## License

This tool orchestrates local utilities and includes Nessus XML parsing functionality adapted from
[DefensiveOrigins/NessusPluginHosts](https://github.com/DefensiveOrigins/NessusPluginHosts).
Respect all dependencies' licenses and your organization's policies.
