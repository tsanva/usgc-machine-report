#!/bin/bash
# TR-100 Machine Report - OpenWrt Edition
# Copyright © 2024, U.S. Graphics, LLC. BSD-3-Clause License.
# Designed for OpenWrt on GL-MT300N-V2 and similar embedded devices
# BusyBox-compatible (no lscpu, nproc, lastlog, uptime -p)

# Global variables
MIN_NAME_LEN=5
MAX_NAME_LEN=13

MIN_DATA_LEN=20
MAX_DATA_LEN=32

BORDERS_AND_PADDING=7

# Basic configuration, change as needed
report_title="UNITED STATES GRAPHICS COMPANY"
last_login_ip_present=0

# Utilities
max_length() {
    local max_len=0
    local len

    for str in "$@"; do
        len=${#str}
        if (( len > max_len )); then
            max_len=$len
        fi
    done

    if [ $max_len -lt $MAX_DATA_LEN ]; then
        printf '%s' "$max_len"
    else
        printf '%s' "$MAX_DATA_LEN"
    fi
}

# All data strings must go here
set_current_len() {
    CURRENT_LEN=$(max_length                                     \
        "$report_title"                                          \
        "$os_name"                                               \
        "$os_kernel"                                             \
        "$net_hostname"                                          \
        "$net_machine_ip"                                        \
        "$net_client_ip"                                         \
        "$net_current_user"                                      \
        "$cpu_model"                                             \
        "$cpu_cores core(s)"                                     \
        "$cpu_hypervisor"                                        \
        "$cpu_freq GHz"                                          \
        "$cpu_1min_bar_graph"                                    \
        "$cpu_5min_bar_graph"                                    \
        "$cpu_15min_bar_graph"                                   \
        "$root_used_gb/$root_total_gb GB [$disk_percent%]"       \
        "$disk_bar_graph"                                        \
        "${mem_used_gb}/${mem_total_gb} MiB [${mem_percent}%]"   \
        "${mem_bar_graph}"                                       \
        "$last_login_time"                                       \
        "$sys_uptime"                                            \
    )
}

PRINT_HEADER() {
    local length=$((CURRENT_LEN+MAX_NAME_LEN+BORDERS_AND_PADDING))

    local top="┌"
    local bottom="├"
    for (( i = 0; i < length - 2; i++ )); do
        top+="┬"
        bottom+="┴"
    done
    top+="┐"
    bottom+="┤"

    printf '%s\n' "$top"
    printf '%s\n' "$bottom"
}

PRINT_CENTERED_DATA() {
    local max_len=$((CURRENT_LEN+MAX_NAME_LEN-BORDERS_AND_PADDING))
    local text="$1"
    local total_width=$((max_len + 12))

    local text_len=${#text}
    local padding_left=$(( (total_width - text_len) / 2 ))
    local padding_right=$(( total_width - text_len - padding_left ))

    printf "│%${padding_left}s%s%${padding_right}s│\n" "" "$text" ""
}

PRINT_DIVIDER() {
    # either "top" or "bottom", no argument means middle divider
    local side="$1"
    case "$side" in
        "top")
            local left_symbol="├"
            local middle_symbol="┬"
            local right_symbol="┤"
            ;;
        "bottom")
            local left_symbol="└"
            local middle_symbol="┴"
            local right_symbol="┘"
            ;;
        *)
            local left_symbol="├"
            local middle_symbol="┼"
            local right_symbol="┤"
    esac

    local length=$((CURRENT_LEN+MAX_NAME_LEN+BORDERS_AND_PADDING))
    local divider="$left_symbol"
    for (( i = 0; i < length - 3; i++ )); do
        divider+="─"
        if [ "$i" -eq 14 ]; then
            divider+="$middle_symbol"
        fi
    done
    divider+="$right_symbol"
    printf '%s\n' "$divider"
}

PRINT_DATA() {
    local name="$1"
    local data="$2"
    local max_data_len=$CURRENT_LEN

    # Pad name
    local name_len=${#name}
    if (( name_len < MIN_NAME_LEN )); then
        name=$(printf "%-${MIN_NAME_LEN}s" "$name")
    elif (( name_len > MAX_NAME_LEN )); then
        name=$(echo "$name" | cut -c 1-$((MAX_NAME_LEN-3)))...
    else
        name=$(printf "%-${MAX_NAME_LEN}s" "$name")
    fi

    # Truncate or pad data
    local data_len=${#data}
    if (( data_len >= MAX_DATA_LEN || data_len == MAX_DATA_LEN-1 )); then
        data=$(echo "$data" | cut -c 1-$((MAX_DATA_LEN-3-2)))...
    else
        data=$(printf "%-${max_data_len}s" "$data")
    fi

    printf "│ %-${MAX_NAME_LEN}s │ %s │\n" "$name" "$data"
}

PRINT_FOOTER() {
    local length=$((CURRENT_LEN+MAX_NAME_LEN+BORDERS_AND_PADDING))
    local footer="└"
    for (( i = 0; i < length - 3; i++ )); do
        footer+="─"
        if [ "$i" -eq 14 ]; then
            footer+="┴"
        fi
    done
    footer+="┘"
    printf '%s\n' "$footer"
}

bar_graph() {
    local percent
    local num_blocks
    local width=$CURRENT_LEN
    local graph=""
    local used=$1
    local total=$2

    if (( total == 0 )); then
        percent=0
    else
        percent=$(awk -v used="$used" -v total="$total" 'BEGIN { printf "%.2f", (used / total) * 100 }')
    fi

    num_blocks=$(awk -v percent="$percent" -v width="$width" 'BEGIN { printf "%d", (percent / 100) * width }')

    for (( i = 0; i < num_blocks; i++ )); do
        graph+="█"
    done
    for (( i = num_blocks; i < width; i++ )); do
        graph+="░"
    done
    printf "%s" "${graph}"
}

get_ip_addr() {
    # Initialize variables
    ipv4_address=""
    ipv6_address=""

    # OpenWrt typically uses ifconfig (BusyBox)
    if command -v ifconfig &> /dev/null; then
        # Try common OpenWrt interfaces: br-lan, eth0, wlan0
        for iface in br-lan eth0 wlan0; do
            ipv4_address=$(ifconfig "$iface" 2>/dev/null | awk '/inet addr:/ {split($2, a, ":"); print a[2]}')
            if [ -z "$ipv4_address" ]; then
                # Try newer ifconfig format
                ipv4_address=$(ifconfig "$iface" 2>/dev/null | awk '/inet / && !/127.0.0.1/ {print $2}')
            fi
            if [ -n "$ipv4_address" ]; then
                break
            fi
        done

        # Fallback: scan all interfaces
        if [ -z "$ipv4_address" ]; then
            ipv4_address=$(ifconfig | awk '
                /^[a-z]/ {iface=$1}
                iface != "lo" && /inet addr:/ {split($2, a, ":"); if (!found++) print a[2]}')
            if [ -z "$ipv4_address" ]; then
                ipv4_address=$(ifconfig | awk '
                    /^[a-z]/ {iface=$1}
                    iface != "lo:" && /inet / && !/127.0.0.1/ && !found_ipv4 {found_ipv4=1; print $2}')
            fi
        fi
    fi

    # If no IPv4 found, try ip command as fallback
    if [ -z "$ipv4_address" ] && command -v ip &> /dev/null; then
        ipv4_address=$(ip -o -4 addr show 2>/dev/null | awk '
            $2 != "lo" {split($4, a, "/"); if (!found++) print a[1]}')
    fi

    # If neither IPv4 nor IPv6 address is available, assign "No IP found"
    if [ -z "$ipv4_address" ] && [ -z "$ipv6_address" ]; then
        ip_address="No IP found"
    else
        ip_address="${ipv4_address:-$ipv6_address}"
    fi

    printf '%s' "$ip_address"
}

# Operating System Information
if [ -f /etc/openwrt_release ]; then
    . /etc/openwrt_release
    os_name="OpenWrt ${DISTRIB_RELEASE:-Unknown}"
elif [ -f /etc/os-release ]; then
    . /etc/os-release
    os_name="${ID:-Linux} ${VERSION_ID:-}"
else
    os_name="Linux $(uname -r)"
fi
os_kernel=$({ uname; uname -r; } | tr '\n' ' ')

# Network Information
net_current_user=$(whoami)
net_hostname=$(hostname 2>/dev/null)
if [ -z "$net_hostname" ]; then
    net_hostname=$(cat /proc/sys/kernel/hostname 2>/dev/null)
fi
if [ -z "$net_hostname" ]; then net_hostname="Not Defined"; fi

net_machine_ip=$(get_ip_addr)
net_client_ip=$(who am i 2>/dev/null | awk '{print $5}' | tr -d '()')
if [ -z "$net_client_ip" ]; then
    net_client_ip="Not connected"
fi

# DNS from resolv.conf
net_dns_ip=()
if [ -f /etc/resolv.conf ]; then
    while read -r line; do
        if echo "$line" | grep -q '^nameserver'; then
            dns=$(echo "$line" | awk '{print $2}')
            net_dns_ip+=("$dns")
        fi
    done < /etc/resolv.conf
fi

# CPU Information (parse /proc/cpuinfo - no lscpu on OpenWrt)
# Try common cpuinfo fields: model name (x86), system type (MIPS), Processor (ARM)
cpu_model=$(grep -m1 -E 'model name|system type|Processor|cpu model' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | xargs)
if [ -z "$cpu_model" ]; then
    cpu_model="Unknown CPU"
fi

# Count CPU cores from /proc/cpuinfo
cpu_cores=$(grep -c '^processor' /proc/cpuinfo 2>/dev/null)
if [ -z "$cpu_cores" ] || [ "$cpu_cores" -eq 0 ]; then
    cpu_cores=1
fi

# CPU frequency (may not be available on all embedded devices)
cpu_freq_mhz=$(grep -m1 'cpu MHz' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | xargs)
if [ -n "$cpu_freq_mhz" ]; then
    cpu_freq=$(awk -v mhz="$cpu_freq_mhz" 'BEGIN { printf "%.2f", mhz / 1000 }')
else
    # Try BogoMIPS as rough indicator
    bogomips=$(grep -m1 'BogoMIPS' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | xargs)
    if [ -n "$bogomips" ]; then
        cpu_freq="~${bogomips} BogoMIPS"
    else
        cpu_freq="Unknown"
    fi
fi

# No hypervisor detection on embedded hardware
cpu_hypervisor="Bare Metal"

# Load averages from /proc/loadavg
if [ -f /proc/loadavg ]; then
    load_avg_1min=$(awk '{print $1}' /proc/loadavg)
    load_avg_5min=$(awk '{print $2}' /proc/loadavg)
    load_avg_15min=$(awk '{print $3}' /proc/loadavg)
else
    load_avg_1min=$(uptime | awk -F'load average: ' '{print $2}' | cut -d ',' -f1 | tr -d ' ')
    load_avg_5min=$(uptime | awk -F'load average: ' '{print $2}' | cut -d ',' -f2 | tr -d ' ')
    load_avg_15min=$(uptime | awk -F'load average: ' '{print $2}' | cut -d ',' -f3 | tr -d ' ')
fi

# Memory Information from /proc/meminfo
# Note: OpenWrt devices typically have small RAM, show in MiB instead of GiB
mem_total=$(grep 'MemTotal' /proc/meminfo | awk '{print $2}')
mem_available=$(grep 'MemAvailable' /proc/meminfo | awk '{print $2}')
if [ -z "$mem_available" ]; then
    # Fallback for older kernels without MemAvailable
    mem_free=$(grep 'MemFree' /proc/meminfo | awk '{print $2}')
    mem_buffers=$(grep 'Buffers' /proc/meminfo | awk '{print $2}')
    mem_cached=$(grep '^Cached' /proc/meminfo | awk '{print $2}')
    mem_available=$((mem_free + mem_buffers + mem_cached))
fi
mem_used=$((mem_total - mem_available))
mem_percent=$(awk -v used="$mem_used" -v total="$mem_total" 'BEGIN { printf "%.2f", (used / total) * 100 }')
# Show in MiB for embedded devices (typically 128MB RAM)
mem_total_gb=$(echo "$mem_total" | awk '{ printf "%.1f", $1 / 1024 }')
mem_available_gb=$(echo "$mem_available" | awk '{ printf "%.1f", $1 / 1024 }')
mem_used_gb=$(echo "$mem_used" | awk '{ printf "%.1f", $1 / 1024 }')

# Disk Information
root_partition="/"
root_used=$(df -m "$root_partition" 2>/dev/null | awk 'NR==2 {print $3}')
root_total=$(df -m "$root_partition" 2>/dev/null | awk 'NR==2 {print $2}')
if [ -z "$root_total" ] || [ "$root_total" -eq 0 ]; then
    # Fallback for overlayfs/squashfs
    root_used=$(df "$root_partition" 2>/dev/null | awk 'NR==2 {print int($3/1024)}')
    root_total=$(df "$root_partition" 2>/dev/null | awk 'NR==2 {print int($2/1024)}')
fi
root_total_gb=$(awk -v total="${root_total:-0}" 'BEGIN { printf "%.2f", total / 1024 }')
root_used_gb=$(awk -v used="${root_used:-0}" 'BEGIN { printf "%.2f", used / 1024 }')
disk_percent=$(awk -v used="${root_used:-0}" -v total="${root_total:-1}" 'BEGIN { printf "%.2f", (used / total) * 100 }')

# Last login - try 'last' command (may not be available)
if command -v last &> /dev/null; then
    last_login_output=$(last -1 2>/dev/null | head -1)
    if [ -n "$last_login_output" ] && ! echo "$last_login_output" | grep -q "wtmp"; then
        last_login_time=$(echo "$last_login_output" | awk '{print $4, $5, $6, $7}')
    else
        last_login_time="Not available"
    fi
else
    last_login_time="Not available"
fi

# Uptime - parse /proc/uptime (no uptime -p in BusyBox)
uptime_raw=$(cut -d. -f1 /proc/uptime 2>/dev/null)
if [ -n "$uptime_raw" ]; then
    uptime_days=$((uptime_raw / 86400))
    uptime_hours=$(((uptime_raw % 86400) / 3600))
    uptime_mins=$(((uptime_raw % 3600) / 60))
    sys_uptime="${uptime_days}d ${uptime_hours}h ${uptime_mins}m"
else
    sys_uptime="Unknown"
fi

# Set current length before graphs get calculated
set_current_len

# Create graphs
cpu_1min_bar_graph=$(bar_graph "$load_avg_1min" "$cpu_cores")
cpu_5min_bar_graph=$(bar_graph "$load_avg_5min" "$cpu_cores")
cpu_15min_bar_graph=$(bar_graph "$load_avg_15min" "$cpu_cores")

mem_bar_graph=$(bar_graph "$mem_used" "$mem_total")
disk_bar_graph=$(bar_graph "${root_used:-0}" "${root_total:-1}")

# Machine Report
PRINT_HEADER
PRINT_CENTERED_DATA "$report_title"
PRINT_CENTERED_DATA "TR-100 MACHINE REPORT"
PRINT_DIVIDER "top"
PRINT_DATA "OS" "$os_name"
PRINT_DATA "KERNEL" "$os_kernel"
PRINT_DIVIDER
PRINT_DATA "HOSTNAME" "$net_hostname"
PRINT_DATA "MACHINE IP" "$net_machine_ip"
PRINT_DATA "CLIENT  IP" "$net_client_ip"

for dns_num in "${!net_dns_ip[@]}"; do
    PRINT_DATA "DNS  IP $(($dns_num + 1))" "${net_dns_ip[dns_num]}"
done

PRINT_DATA "USER" "$net_current_user"
PRINT_DIVIDER
PRINT_DATA "PROCESSOR" "$cpu_model"
PRINT_DATA "CORES" "$cpu_cores core(s)"
PRINT_DATA "HYPERVISOR" "$cpu_hypervisor"
PRINT_DATA "CPU FREQ" "$cpu_freq"
PRINT_DATA "LOAD  1m" "$cpu_1min_bar_graph"
PRINT_DATA "LOAD  5m" "$cpu_5min_bar_graph"
PRINT_DATA "LOAD 15m" "$cpu_15min_bar_graph"
PRINT_DIVIDER
PRINT_DATA "VOLUME" "$root_used_gb/$root_total_gb GB [$disk_percent%]"
PRINT_DATA "DISK USAGE" "$disk_bar_graph"
PRINT_DIVIDER
PRINT_DATA "MEMORY" "${mem_used_gb}/${mem_total_gb} MiB [${mem_percent}%]"
PRINT_DATA "USAGE" "${mem_bar_graph}"
PRINT_DIVIDER
PRINT_DATA "LAST LOGIN" "$last_login_time"
PRINT_DATA "UPTIME" "$sys_uptime"
PRINT_DIVIDER "bottom"
