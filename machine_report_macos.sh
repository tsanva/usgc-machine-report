#!/bin/bash
# TR-100 Machine Report - macOS Edition
# Copyright © 2024, U.S. Graphics, LLC. BSD-3-Clause License.
# Designed for macOS Sequoia on Apple Silicon (M1/M2/M3/M4)

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
        "$cpu_cores_display"                                     \
        "$cpu_hypervisor"                                        \
        "$cpu_freq"                                              \
        "$cpu_1min_bar_graph"                                    \
        "$cpu_5min_bar_graph"                                    \
        "$cpu_15min_bar_graph"                                   \
        "$root_used_gb/$root_total_gb GB [$disk_percent%]"       \
        "$disk_bar_graph"                                        \
        "${mem_used_gb}/${mem_total_gb} GiB [${mem_percent}%]"   \
        "${mem_bar_graph}"                                       \
        "$last_login_time"                                       \
        "$last_login_ip"                                         \
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

    # macOS uses ifconfig - prioritize en0 (usually WiFi) and en1
    if command -v ifconfig &> /dev/null; then
        # Try en0 first (typically the primary interface on macOS)
        ipv4_address=$(ifconfig en0 2>/dev/null | awk '/inet / && !/127.0.0.1/ {print $2}' | head -1)

        # Try en1 if en0 didn't work
        if [ -z "$ipv4_address" ]; then
            ipv4_address=$(ifconfig en1 2>/dev/null | awk '/inet / && !/127.0.0.1/ {print $2}' | head -1)
        fi

        # Fallback: scan all interfaces
        if [ -z "$ipv4_address" ]; then
            ipv4_address=$(ifconfig | awk '
                /^[a-z]/ {iface=$1}
                iface != "lo0:" && /inet / && !/127.0.0.1/ && !found_ipv4 {found_ipv4=1; print $2}')
        fi

        # If IPv4 address not available, try IPv6
        if [ -z "$ipv4_address" ]; then
            ipv6_address=$(ifconfig | awk '
                /^[a-z]/ {iface=$1}
                iface != "lo0:" && /inet6 / && !/fe80:/ && !found_ipv6 {found_ipv6=1; print $2}')
        fi
    fi

    # If neither IPv4 nor IPv6 address is available, assign "No IP found"
    if [ -z "$ipv4_address" ] && [ -z "$ipv6_address" ]; then
        ip_address="No IP found"
    else
        # Prioritize IPv4 if available, otherwise use IPv6
        ip_address="${ipv4_address:-$ipv6_address}"
    fi

    printf '%s' "$ip_address"
}

# Operating System Information
os_name="$(sw_vers -productName) $(sw_vers -productVersion)"
os_kernel=$({ uname; uname -r; } | tr '\n' ' ')

# Network Information
net_current_user=$(whoami)
net_hostname=$(hostname)
if [ -z "$net_hostname" ]; then net_hostname="Not Defined"; fi

net_machine_ip=$(get_ip_addr)
net_client_ip=$(who am i 2>/dev/null | awk '{print $5}' | tr -d '()')
if [ -z "$net_client_ip" ]; then
    net_client_ip="Not connected"
fi

# DNS from scutil or resolv.conf
if command -v scutil &> /dev/null; then
    net_dns_ip=($(scutil --dns 2>/dev/null | grep 'nameserver\[' | awk '{print $3}' | head -3))
fi
if [ ${#net_dns_ip[@]} -eq 0 ] && [ -f /etc/resolv.conf ]; then
    net_dns_ip=($(grep '^nameserver [0-9.]' /etc/resolv.conf | awk '{print $2}'))
fi

# CPU Information (Apple Silicon / Intel Mac)
cpu_model="$(sysctl -n machdep.cpu.brand_string 2>/dev/null)"
if [ -z "$cpu_model" ]; then
    # Fallback for Apple Silicon where brand_string may not exist
    cpu_model="$(sysctl -n hw.model 2>/dev/null) $(uname -m)"
fi

# Check for hypervisor (virtualization)
hv_present=$(sysctl -n kern.hv_vmm_present 2>/dev/null)
if [ "$hv_present" = "1" ]; then
    cpu_hypervisor="Virtual Machine"
else
    cpu_hypervisor="Bare Metal"
fi

# CPU cores - detect P-cores and E-cores for Apple Silicon
cpu_p_cores=$(sysctl -n hw.perflevel0.logicalcpu 2>/dev/null)
cpu_e_cores=$(sysctl -n hw.perflevel1.logicalcpu 2>/dev/null)
cpu_total_cores=$(sysctl -n hw.logicalcpu 2>/dev/null)

if [ -n "$cpu_p_cores" ] && [ -n "$cpu_e_cores" ]; then
    # Apple Silicon with P and E cores
    cpu_cores_display="${cpu_p_cores}P + ${cpu_e_cores}E cores"
    cpu_cores=$cpu_total_cores
else
    # Intel Mac or fallback
    cpu_cores=$cpu_total_cores
    cpu_cores_display="$cpu_cores vCPU(s)"
fi

# CPU Frequency - Apple Silicon dynamically scales, show "Dynamic" or get max freq
cpu_freq_hz=$(sysctl -n hw.cpufrequency_max 2>/dev/null)
if [ -n "$cpu_freq_hz" ] && [ "$cpu_freq_hz" -gt 0 ]; then
    cpu_freq=$(awk -v freq="$cpu_freq_hz" 'BEGIN { printf "%.2f GHz", freq / 1000000000 }')
else
    cpu_freq="Dynamic (Apple Silicon)"
fi

# Load averages
load_avg_raw=$(sysctl -n vm.loadavg 2>/dev/null | tr -d '{}')
load_avg_1min=$(echo "$load_avg_raw" | awk '{print $1}')
load_avg_5min=$(echo "$load_avg_raw" | awk '{print $2}')
load_avg_15min=$(echo "$load_avg_raw" | awk '{print $3}')

# Memory Information
mem_total_bytes=$(sysctl -n hw.memsize 2>/dev/null)
mem_total=$((mem_total_bytes / 1024)) # Convert to KB for consistency

# Parse vm_stat for memory usage (values are in pages, page size is typically 16384 on Apple Silicon)
page_size=$(sysctl -n hw.pagesize 2>/dev/null)
vm_stat_output=$(vm_stat)
pages_free=$(echo "$vm_stat_output" | awk '/Pages free/ {gsub(/\./, "", $3); print $3}')
pages_inactive=$(echo "$vm_stat_output" | awk '/Pages inactive/ {gsub(/\./, "", $3); print $3}')
pages_speculative=$(echo "$vm_stat_output" | awk '/Pages speculative/ {gsub(/\./, "", $3); print $3}')

# Available = free + inactive + speculative (rough approximation)
mem_available_pages=$((pages_free + pages_inactive + pages_speculative))
mem_available=$((mem_available_pages * page_size / 1024)) # KB

mem_used=$((mem_total - mem_available))
mem_percent=$(awk -v used="$mem_used" -v total="$mem_total" 'BEGIN { printf "%.2f", (used / total) * 100 }')
mem_total_gb=$(echo "$mem_total" | awk '{ printf "%.2f", $1 / (1024 * 1024) }')
mem_available_gb=$(echo "$mem_available" | awk '{ printf "%.2f", $1 / (1024 * 1024) }')
mem_used_gb=$(echo "$mem_used" | awk '{ printf "%.2f", $1 / (1024 * 1024) }')

# Disk Information (APFS)
root_partition="/"
root_used=$(df -m "$root_partition" | awk 'NR==2 {print $3}')
root_total=$(df -m "$root_partition" | awk 'NR==2 {print $2}')
root_total_gb=$(awk -v total="$root_total" 'BEGIN { printf "%.2f", total / 1024 }')
root_used_gb=$(awk -v used="$root_used" 'BEGIN { printf "%.2f", used / 1024 }')
disk_percent=$(awk -v used="$root_used" -v total="$root_total" 'BEGIN { printf "%.2f", (used / total) * 100 }')

# Last login and Uptime
last_login_output=$(last -1 "$USER" 2>/dev/null | head -1)
if [ -n "$last_login_output" ] && ! echo "$last_login_output" | grep -q "wtmp begins"; then
    last_login_time=$(echo "$last_login_output" | awk '{print $4, $5, $6, $7}')
    # Try to extract IP if present (TTY column usually shows pts/N or ttysN)
    potential_ip=$(echo "$last_login_output" | awk '{print $3}')
    if [[ "$potential_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        last_login_ip_present=1
        last_login_ip="$potential_ip"
    fi
else
    last_login_time="Never logged in"
fi

# Uptime (macOS uptime doesn't have -p flag, parse manually)
uptime_seconds=$(sysctl -n kern.boottime | awk '{print $4}' | tr -d ',')
current_time=$(date +%s)
uptime_raw=$((current_time - uptime_seconds))
uptime_days=$((uptime_raw / 86400))
uptime_hours=$(((uptime_raw % 86400) / 3600))
uptime_mins=$(((uptime_raw % 3600) / 60))
sys_uptime="${uptime_days}d ${uptime_hours}h ${uptime_mins}m"

# Set current length before graphs get calculated
set_current_len

# Create graphs
cpu_1min_bar_graph=$(bar_graph "$load_avg_1min" "$cpu_cores")
cpu_5min_bar_graph=$(bar_graph "$load_avg_5min" "$cpu_cores")
cpu_15min_bar_graph=$(bar_graph "$load_avg_15min" "$cpu_cores")

mem_bar_graph=$(bar_graph "$mem_used" "$mem_total")
disk_bar_graph=$(bar_graph "$root_used" "$root_total")

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
PRINT_DATA "CORES" "$cpu_cores_display"
PRINT_DATA "HYPERVISOR" "$cpu_hypervisor"
PRINT_DATA "CPU FREQ" "$cpu_freq"
PRINT_DATA "LOAD  1m" "$cpu_1min_bar_graph"
PRINT_DATA "LOAD  5m" "$cpu_5min_bar_graph"
PRINT_DATA "LOAD 15m" "$cpu_15min_bar_graph"
PRINT_DIVIDER
PRINT_DATA "VOLUME" "$root_used_gb/$root_total_gb GB [$disk_percent%]"
PRINT_DATA "DISK USAGE" "$disk_bar_graph"
PRINT_DIVIDER
PRINT_DATA "MEMORY" "${mem_used_gb}/${mem_total_gb} GiB [${mem_percent}%]"
PRINT_DATA "USAGE" "${mem_bar_graph}"
PRINT_DIVIDER
PRINT_DATA "LAST LOGIN" "$last_login_time"

if [ $last_login_ip_present -eq 1 ]; then
    PRINT_DATA "" "$last_login_ip"
fi

PRINT_DATA "UPTIME" "$sys_uptime"
PRINT_DIVIDER "bottom"
