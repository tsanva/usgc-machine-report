# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

TR-100 Machine Report is a collection of bash scripts that display system information when users log into a server (similar to Neofetch). Originally designed for Debian systems with ZFS, now supports multiple platforms.

### Platform-Specific Scripts

| Script | Platform | Data Sources |
|--------|----------|--------------|
| `machine_report.sh` | Debian + ZFS | `lscpu`, `/proc/*`, `zfs` |
| `machine_report_debian.sh` | Debian/Ubuntu | `lscpu`, `/proc/*`, `df` |
| `machine_report_macos.sh` | macOS (Apple Silicon) | `sysctl`, `sw_vers`, `vm_stat` |
| `machine_report_openwrt.sh` | OpenWrt/BusyBox | `/proc/*` parsing only |

## Philosophy

**Direct source editing is the intended customization method.** No config files, no DSL, no modules. Users modify the script directly. This is intentional - avoid adding abstraction layers.

Key principles:
- Single file for easy deployment
- 1:1 visual mapping between code and output (printf statements reflect final layout)
- Variables at top for minimal configuration, but keep it minimal

## Running and Testing

```bash
# Make executable (first time only)
chmod +x machine_report.sh

# Run directly
./machine_report.sh

# Typical installation: add to ~/.bashrc for SSH login display
```

## Script Architecture

The script follows a linear flow: **collect data → calculate layout → render output**.

### Data Collection (lines 234-333)
System info gathered into variables:
- `os_*` - OS name, kernel from `/etc/os-release`
- `net_*` - hostname, IPs, DNS, user
- `cpu_*` - processor info from `lscpu` and `/proc/cpuinfo`
- `mem_*` - memory from `/proc/meminfo`
- `zfs_*` / `root_*` - disk usage (ZFS or standard filesystem)
- `last_login_*`, `sys_uptime` - session info

### Layout Calculation
- `set_current_len()` - calculates column width based on longest data string
- `CURRENT_LEN` - global width used by all print functions
- `MIN_NAME_LEN`, `MAX_NAME_LEN`, `MAX_DATA_LEN` - column constraints

### Print Functions (rendering layer)
- `PRINT_HEADER()` / `PRINT_FOOTER()` - box top/bottom borders
- `PRINT_DIVIDER(side)` - section separators ("top", "bottom", or middle)
- `PRINT_DATA(name, data)` - single row with label and value
- `PRINT_CENTERED_DATA(text)` - centered title text
- `bar_graph(used, total)` - visual usage bar with █ and ░ characters

### Machine Report Output (lines 336-383)
Sequence of PRINT_* calls that render the final table. What you see in code maps directly to output order.

## System Requirements

**Debian scripts:** `lscpu`, `lastlog`, `/proc/meminfo`, `/proc/cpuinfo`
**macOS script:** Built-in only (`sysctl`, `sw_vers`, `vm_stat`, `df`)
**OpenWrt script:** BusyBox-compatible, no external dependencies

## Customization Points

- `report_title` (line 15) - organization name in header
- Add/remove PRINT_DATA calls in the Machine Report section to change displayed fields
