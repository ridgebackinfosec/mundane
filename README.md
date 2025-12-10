# Mundane

A **TUI tool** for reviewing Nessus scan findings and orchestrating security tools (**nmap**, **NetExec**, custom commands). Import `.nessus` files into a SQLite database for organized, persistent vulnerability verification and exploitation.

**Key capabilities:**
- 🔍 Interactive TUI for browsing/reviewing vulnerability findings
- 💾 SQLite-backed persistence (cross-scan tracking, session resume)
- ⚡ One-command tool launches (nmap NSE scripts, NetExec, custom workflows)
- 📊 CVE extraction, Metasploit module search, host comparison

---

## Quick Start

```bash
# Install with pipx (recommended)
pipx install git+https://github.com/ridgebackinfosec/mundane.git

# Import a Nessus scan
mundane import nessus scan.nessus

# Review findings interactively
mundane review
```

**That's it!** See [Common Commands](#commands) for more.

---

## Installation

**Recommended (pipx):**
```bash
pipx install git+https://github.com/ridgebackinfosec/mundane.git
mundane --help
```

**Alternative (pip):**
```bash
pip install git+https://github.com/ridgebackinfosec/mundane.git
```

**Development:**
```bash
git clone https://github.com/ridgebackinfosec/mundane.git
cd mundane
pip install -e .
```

**Shell completion:**
```bash
mundane --install-completion  # Enable tab completion for your shell
```

**Upgrading from v1.x:** v2.0 introduced breaking schema changes. Delete old database and re-import scans. See [docs/DATABASE.md](docs/DATABASE.md).

---

## Requirements

- **Python 3.11+**
- **Optional tools:** `nmap`, `nxc`/`netexec`, `msfconsole` (only if you use them)
- **Linux recommended** (clipboard tools: `xclip`, `xsel`, or `wl-copy`)

---

## Configuration

**Optional config file** (`~/.mundane/config.yaml`):
```bash
mundane config init        # Generate example config
mundane config show        # View current settings
mundane config set <key> <value>  # Set a value
```

**Key environment variables:**
- `MUNDANE_RESULTS_ROOT` - Tool artifact directory (default: `~/.mundane/artifacts`)
- `MUNDANE_LOG` - Log file path (default: `~/.mundane/mundane.log`)
- `MUNDANE_DEBUG` - Enable debug logging (`1`, `true`, `on`)

**Priority:** Environment variables > Config file > Defaults

---

## Features

**TUI Navigation:**
- Rich tables with paged views (`[N]ext`, `[P]rev`, `[B]ack`)
- Browse by severity, preview plugin details, clipboard copy
- Grouped view (`host:port,port`) or raw file view

**Intelligence & Research:**
- **CVE extraction** - CVEs imported from .nessus file (press `[E]`)
- **Metasploit search** - Find relevant modules by CVE/description
- **Workflow mappings** - Plugin-specific verification/exploitation steps (press `[W]`)
- **Host comparison** - Compare findings across hosts to find superset and identical overlaps

**Tool Orchestration:**
- Launch **nmap** (NSE profiles, UDP), **NetExec**, or custom commands
- Placeholder substitution for flexible templating
- Execution logging & artifact tracking

**Session Management:**
- Auto-save/resume interrupted reviews
- Reversible review-complete (undo with `[U]`)
- Session statistics (duration, per-severity breakdown)

**Database:** SQLite-backed persistence at `~/.mundane/mundane.db` tracks scans, findings, sessions, tool executions, and artifacts. See [docs/DATABASE.md](docs/DATABASE.md) for schema details.

---

## Commands

```bash
# Import and review
mundane import nessus <scan.nessus>
mundane review [--custom-workflows PATH]

# Manage scans
mundane scan list
mundane scan delete <scan_name>

# Configuration
mundane config init | show | get <key> | set <key> <value>
```

---

## Custom Workflows

Add plugin-specific verification workflows with `--custom-workflows` (merges & supplements with defaults) or `--custom-workflows-only` (replaces defaults):

```bash
mundane review --custom-workflows my_workflows.yaml
```

**Example workflow YAML:**
```yaml
version: "1.0"
workflows:
  - plugin_id: "57608"
    workflow_name: "SMB Signing Not Required"
    steps:
      - title: "Verify SMB signing"
        commands: ["netexec smb <target> -u <user> -p <pass>"]
```

**Custom command placeholders:** `{TCP_IPS}`, `{UDP_IPS}`, `{TCP_HOST_PORTS}`, `{PORTS}`, `{WORKDIR}`, `{RESULTS_DIR}`, `{OABASE}`

---

## Documentation

- [Database schema & queries](docs/DATABASE.md)
- [Adding custom tools](docs/ADDING_TOOLS_QUICKSTART.md)
- [Tool system guide](docs/TOOL_SYSTEM_GUIDE.md)
- [Error handling](docs/ERROR_HANDLING.md)

---

## License

This tool orchestrates local utilities and includes Nessus XML parsing functionality adapted from
[DefensiveOrigins/NessusPluginHosts](https://github.com/DefensiveOrigins/NessusPluginHosts).
Respect all dependencies' licenses and your organization's policies.
