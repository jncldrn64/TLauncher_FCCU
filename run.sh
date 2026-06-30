#!/usr/bin/env bash
# TLauncher Sandboxed Launcher
# Secure sandbox with comprehensive monitoring capabilities
set -euo pipefail

VERSION="2.3"

# ==========================================
# CONFIGURATION
# ==========================================

# User detection
REAL_USER="${SUDO_USER:-${USER}}"
REAL_UID="${SUDO_UID:-$(id -u)}"
REAL_GID="${SUDO_GID:-$(id -g)}"
REAL_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6 2>/dev/null || echo "$HOME")

# XDG directories
XDG_DATA_HOME="${XDG_DATA_HOME:-${REAL_HOME}/.local/share}"
XDG_STATE_HOME="${XDG_STATE_HOME:-${REAL_HOME}/.local/state}"
XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/${REAL_UID}}"

# Fallback if XDG_RUNTIME_DIR doesn't exist
if [ ! -d "$XDG_RUNTIME_DIR" ]; then
    XDG_RUNTIME_DIR="/tmp"
fi

# Paths
SANDBOX_DIR="${XDG_DATA_HOME}/tlauncher-sandbox"
LOCKFILE="${XDG_RUNTIME_DIR}/tlauncher-${REAL_USER}.lock"

# Options
VERBOSE=false
OFFLINE_MODE=false
MONITOR_ENABLED=false
AUTO_ANALYZE=false
MOZILLA_CHECK=false
TLAUNCHER_PATH=""
MOZILLA_SEARCH_PATH="${REAL_HOME}/.mozilla"

# Monitoring
SESSION_ID=""
SESSION_DIR=""
MONITOR_PIDS=()

# Protected directories
PROTECTED_DIRS=(
    ".mozilla" ".firefox" ".config/google-chrome" ".config/chromium"
    ".local/share/keyrings" ".gnupg" ".ssh"
    "Documents" "Downloads" "Pictures" "Videos" "Music"
)

# Blocked domains (for reference in logs)
BLOCKED_DOMAINS=(
    "telemetry.tlauncher.org" "stats.tlauncher.org" "analytics.tlauncher.org"
    "tracking.tlauncher.org" "metrics.tlauncher.org" "events.tlauncher.org"
    "ads.tlauncher.org" "promo.tlauncher.org" "offers.tlauncher.org"
    "securelogger.top" "securelogger.net" "res.tlauncher.ru"
    "mps.tlauncher.ru" "ruzone.securelogger.top" "mps.fastrepo.org"
    "mps.tlauncher.org" "page.tlauncher.org" "stat.fastrepo.org"
    "stat.tlauncher.ru" "img.fastrepo.org"
)

# Colors
if [ -t 1 ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; NC=''
fi

# ==========================================
# LOGGING
# ==========================================

log_msg() {
    local ts="$(date '+%Y-%m-%d %H:%M:%S.%3N')"
    printf "[%s] %s\n" "$ts" "$*" >&2
    if [ -n "$SESSION_DIR" ] && [ -d "$SESSION_DIR" ]; then
        printf "[%s] %s\n" "$ts" "$*" >> "${SESSION_DIR}/master.log" 2>/dev/null || true
    fi
}

log_verbose() {
    [ "$VERBOSE" = true ] && log_msg "$@"
}

log_error() {
    printf "${RED}[ERROR]${NC} %s\n" "$*" >&2
}

log_warn() {
    printf "${YELLOW}[WARN]${NC} %s\n" "$*" >&2
}

die() {
    log_error "$*"
    cleanup
    exit 1
}

# ==========================================
# REQUIREMENTS
# ==========================================

check_requirements() {
    local missing=()
    
    command -v java >/dev/null 2>&1 || missing+=("default-jre")
    command -v firejail >/dev/null 2>&1 || missing+=("firejail")
    
    if [ "$MONITOR_ENABLED" = true ]; then
        command -v ss >/dev/null 2>&1 || missing+=("iproute2")
        command -v inotifywait >/dev/null 2>&1 || missing+=("inotify-tools")
    fi
    
    if [ ${#missing[@]} -gt 0 ]; then
        log_error "Missing required packages:"
        printf '  - %s\n' "${missing[@]}" >&2
        printf "\nInstall with: sudo apt install %s\n" "${missing[*]}" >&2
        exit 1
    fi
}

# ==========================================
# TLAUNCHER DETECTION
# ==========================================

find_tlauncher() {
    if [ -n "$TLAUNCHER_PATH" ]; then
        if [ ! -f "$TLAUNCHER_PATH" ]; then
            die "Specified TLauncher not found: $TLAUNCHER_PATH"
        fi
        printf "%s" "$TLAUNCHER_PATH"
        return 0
    fi
    
    # Search in common locations
    for path in "./TLauncher.jar" "${REAL_HOME}/TLauncher.jar" "${REAL_HOME}/Downloads/TLauncher.jar"; do
        if [ -f "$path" ]; then
            printf "%s" "$(realpath "$path")"
            return 0
        fi
    done
    
    die "TLauncher.jar not found. Use -f to specify path"
}

# ==========================================
# SANDBOX SETUP
# ==========================================

setup_sandbox() {
    local tlauncher="$1"
    
    log_verbose "Setting up sandbox: $SANDBOX_DIR"
    
    mkdir -p "${SANDBOX_DIR}"/{.minecraft,tmp,bin}
    
    # Copy TLauncher to sandbox
    cp "$tlauncher" "${SANDBOX_DIR}/bin/TLauncher.jar"
    chmod +x "${SANDBOX_DIR}/bin/TLauncher.jar"
    
    log_verbose "Sandbox ready"
}

build_firejail_params() {
    local params=(
        --noprofile
        --private="${SANDBOX_DIR}"
        --private-dev
        --private-tmp
        --seccomp
        --caps.drop=all
        --noroot
        --nodvd --notv --nou2f --novideo --nogroups
        --hostname=mcbox
        --nonewprivs
        --dbus-user=none
        --dbus-system=none
    )
    
    # Network control
    if [ "$OFFLINE_MODE" = true ]; then
        params+=(--net=none)
    fi
    
    # Blacklist protected directories
    for dir in "${PROTECTED_DIRS[@]}"; do
        [ -d "${REAL_HOME}/${dir}" ] && params+=(--blacklist="${REAL_HOME}/${dir}")
    done
    
    # Whitelist only necessary paths
    params+=(
        --whitelist="${SANDBOX_DIR}/.minecraft"
        --whitelist="${SANDBOX_DIR}/tmp"
        --whitelist="${SANDBOX_DIR}/bin"
        --read-only="${SANDBOX_DIR}/bin"
    )
    
    printf '%s\n' "${params[@]}"
}

# ==========================================
# MONITORING SETUP
# ==========================================

monitor_filesystem() {
    log_verbose "Starting filesystem monitor..."
    
    {
        # Small initial delay to ensure directory exists
        sleep 0.3
        
        inotifywait -m -r \
            -e modify,create,delete,move,close_write \
            --timefmt '%Y-%m-%d %H:%M:%S.%3N' \
            --format '[%T] %e %w%f' \
            "$SANDBOX_DIR" 2>&1
    } > "${SESSION_DIR}/files.log" &
    
    local pid=$!
    MONITOR_PIDS+=($pid)
    log_verbose "  → Filesystem monitor PID: $pid"
}

monitor_network() {
    log_verbose "Starting network monitor..."
    
    {
        # Small initial delay before first capture
        sleep 0.5
        
        while true; do
            ts="$(date '+%Y-%m-%d %H:%M:%S.%3N')"
            
            # FIX: Use ss -tn (without -p) to avoid permission issues
            # Capture ALL established TCP connections (not just java)
            # ss -tn = TCP, numeric addresses, no process names (no sudo needed)
            connections=$(ss -tn state established 2>/dev/null | tail -n +2 || true)
            
            if [ -n "$connections" ]; then
                printf "[%s]\n%s\n\n" "$ts" "$connections"
            fi
            
            sleep 2
        done
    } > "${SESSION_DIR}/network.log" &
    
    local pid=$!
    MONITOR_PIDS+=($pid)
    log_verbose "  → Network monitor PID: $pid"
}

monitor_processes() {
    log_verbose "Starting process monitor..."
    
    {
        # Small initial delay
        sleep 0.5
        
        while true; do
            ts="$(date '+%Y-%m-%d %H:%M:%S.%3N')"
            
            # List firejail sandboxes
            sandboxes=$(firejail --list 2>/dev/null || echo "")
            
            if [ -n "$sandboxes" ]; then
                printf "[%s]\n%s\n\n" "$ts" "$sandboxes"
            fi
            
            sleep 8
        done
    } > "${SESSION_DIR}/processes.log" &
    
    local pid=$!
    MONITOR_PIDS+=($pid)
    log_verbose "  → Process monitor PID: $pid"
}

monitor_resources() {
    log_verbose "Starting resource monitor..."
    
    {
        # Small initial delay
        sleep 0.5
        
        while true; do
            ts="$(date '+%Y-%m-%d %H:%M:%S.%3N')"
            
            # FIX: Much more permissive - capture ANY java process
            # ps aux shows processes even if they're in different namespaces
            resources=$(ps auxww 2>/dev/null | grep "[j]ava" | grep -v "grep" | \
                awk '{printf "[CPU: %s%% | MEM: %s%% | VSZ: %s KB | RSS: %s KB] %s\n", $3, $4, $5, $6, $11}')
            
            if [ -n "$resources" ]; then
                printf "[%s] %s\n" "$ts" "$resources"
            fi
            
            sleep 2
        done
    } > "${SESSION_DIR}/resources.log" &
    
    local pid=$!
    MONITOR_PIDS+=($pid)
    log_verbose "  → Resource monitor PID: $pid"
}

monitor_java_processes() {
    log_verbose "Starting Java process monitor..."
    
    {
        # Small initial delay
        sleep 0.5
        
        while true; do
            ts="$(date '+%Y-%m-%d %H:%M:%S.%3N')"
            
            # FIX: More permissive - capture any java-related process
            java_procs=$(ps auxf 2>/dev/null | grep -E "[j]ava" || true)
            
            if [ -n "$java_procs" ]; then
                printf "[%s]\n%s\n\n" "$ts" "$java_procs"
            fi
            
            sleep 2
        done
    } > "${SESSION_DIR}/java-processes.log" &
    
    local pid=$!
    MONITOR_PIDS+=($pid)
    log_verbose "  → Java process monitor PID: $pid"
}

monitor_suspicious_dirs() {
    log_verbose "Starting suspicious directory monitor..."
    
    {
        # Directories to watch for
        local suspicious=(".mozilla" ".firefox" ".config/google-chrome" ".config/chromium" ".cache" ".gnupg")
        
        # Initial delay
        sleep 1
        
        while true; do
            ts="$(date '+%Y-%m-%d %H:%M:%S.%3N')"
            
            for dir in "${suspicious[@]}"; do
                if [ -d "${SANDBOX_DIR}/${dir}" ]; then
                    # Check if we've already logged this
                    if ! grep -q "DETECTED: ${dir}\$" "${SESSION_DIR}/suspicious.log" 2>/dev/null; then
                        printf "[%s] DETECTED: %s\n" "$ts" "$dir"
                        printf "[%s]   Location: %s\n" "$ts" "${SANDBOX_DIR}/${dir}"
                        
                        local file_count=$(find "${SANDBOX_DIR}/${dir}" -type f 2>/dev/null | wc -l)
                        local dir_size=$(du -sh "${SANDBOX_DIR}/${dir}" 2>/dev/null | cut -f1)
                        
                        printf "[%s]   Files: %s\n" "$ts" "$file_count"
                        printf "[%s]   Size: %s\n\n" "$ts" "$dir_size"
                    fi
                fi
            done
            
            sleep 3
        done
    } > "${SESSION_DIR}/suspicious.log" &
    
    local pid=$!
    MONITOR_PIDS+=($pid)
    log_verbose "  → Suspicious directory monitor PID: $pid"
}

# ==========================================
# EXECUTION
# ==========================================

run_sandboxed() {
    local firejail_params
    mapfile -t firejail_params < <(build_firejail_params)
    
    # Log firejail command
    if [ "$MONITOR_ENABLED" = true ]; then
        {
            printf "# Firejail Command\n"
            printf "# Timestamp: %s\n\n" "$(date '+%Y-%m-%d %H:%M:%S')"
            printf "# Note: --private mounts sandbox as new HOME\n"
            printf "firejail"
            printf " %s" "${firejail_params[@]}"
            printf " bash -c 'java -jar bin/TLauncher.jar'\n"
        } > "${SESSION_DIR}/firejail-command.txt"
    fi
    
    (
        flock -n 200 || die "TLauncher already running (lockfile exists)"
        
        if [ "$MONITOR_ENABLED" = true ]; then
            log_msg "Starting all monitors..."
            
            # Start all monitors FIRST
            monitor_filesystem
            monitor_network
            monitor_processes
            monitor_resources
            monitor_java_processes
            monitor_suspicious_dirs
            
            # Give monitors a moment to initialize
            sleep 1
            
            log_msg "All monitors active (PIDs: ${MONITOR_PIDS[*]})"
        fi
        
        log_msg "Launching TLauncher in sandbox..."
        
        # Run firejail
        if [ "$VERBOSE" = true ]; then
            if [ "$MONITOR_ENABLED" = true ]; then
                firejail "${firejail_params[@]}" \
                    bash -c "java -jar bin/TLauncher.jar" \
                    2>&1 | tee "${SESSION_DIR}/tlauncher.log"
            else
                firejail "${firejail_params[@]}" \
                    bash -c "java -jar bin/TLauncher.jar"
            fi
        else
            if [ "$MONITOR_ENABLED" = true ]; then
                firejail "${firejail_params[@]}" \
                    bash -c "java -jar bin/TLauncher.jar" \
                    > "${SESSION_DIR}/tlauncher.log" 2>&1
            else
                firejail "${firejail_params[@]}" \
                    bash -c "java -jar bin/TLauncher.jar" \
                    >/dev/null 2>&1
            fi
        fi
        
    ) 200>"$LOCKFILE"
    
    local exit_code=$?
    
    if [ "$MONITOR_ENABLED" = true ]; then
        log_msg "TLauncher exited (code: $exit_code)"
        log_msg "Stopping monitors..."
        
        # Stop monitors gracefully
        for pid in "${MONITOR_PIDS[@]}"; do
            if kill -0 "$pid" 2>/dev/null; then
                kill "$pid" 2>/dev/null || true
            fi
        done
        
        # Wait a bit for monitors to flush their buffers
        sleep 1
        
        # Force kill any remaining
        for pid in "${MONITOR_PIDS[@]}"; do
            kill -9 "$pid" 2>/dev/null || true
        done
        
        log_verbose "All monitors stopped"
        
        # Take post-execution snapshot
        {
            printf "# Post-execution snapshot\n"
            printf "# Timestamp: %s\n" "$(date '+%Y-%m-%d %H:%M:%S')"
            find "$SANDBOX_DIR" -printf "%T@ %M %u %g %s %p\n" 2>/dev/null | sort
        } > "${SESSION_DIR}/snapshot-after.txt"
        
        # Generate summary and timeline
        generate_summary
        generate_timeline "$SESSION_DIR"
        
        # Auto-analyze if requested
        if [ "$AUTO_ANALYZE" = true ]; then
            printf "\n"
            analyze_session "$SESSION_DIR"
        else
            printf "\n${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
            printf "${GREEN}✓${NC} Session complete\n"
            printf "${BLUE}Logs:${NC} %s\n" "$SESSION_DIR"
            printf "${BLUE}Analyze with:${NC} $0 -A\n"
            printf "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
        fi
    fi
    
    return $exit_code
}

# ==========================================
# SUMMARY GENERATION
# ==========================================

generate_summary() {
    local summary="${SESSION_DIR}/SUMMARY.txt"
    
    {
        printf "═══════════════════════════════════════════════════════════════════════════\n"
        printf "TLauncher Session Summary\n"
        printf "═══════════════════════════════════════════════════════════════════════════\n\n"
        
        printf "Session ID: %s\n" "$SESSION_ID"
        printf "Start Time: %s\n" "$(head -n1 "${SESSION_DIR}/master.log" 2>/dev/null | cut -d']' -f1 | tr -d '[' || echo 'Unknown')"
        printf "End Time: %s\n\n" "$(date '+%Y-%m-%d %H:%M:%S')"
        
        # Files summary
        if [ -f "${SESSION_DIR}/snapshot-before.txt" ] && [ -f "${SESSION_DIR}/snapshot-after.txt" ]; then
            local new_count=$(comm -13 \
                <(awk '{print $NF}' "${SESSION_DIR}/snapshot-before.txt" 2>/dev/null | sort) \
                <(awk '{print $NF}' "${SESSION_DIR}/snapshot-after.txt" 2>/dev/null | sort) | wc -l)
            printf "Files Created: %d\n" "$new_count"
        fi
        
        # Network summary
        if [ -s "${SESSION_DIR}/network.log" ]; then
            local unique_ips=$(grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' "${SESSION_DIR}/network.log" 2>/dev/null | sort -u | wc -l)
            printf "Unique IP Connections: %d\n" "$unique_ips"
        fi
        
        # File system events
        if [ -s "${SESSION_DIR}/files.log" ]; then
            local total_events=$(wc -l < "${SESSION_DIR}/files.log" 2>/dev/null || echo 0)
            local creates=$(grep -c "CREATE" "${SESSION_DIR}/files.log" 2>/dev/null || echo 0)
            local modifies=$(grep -c "MODIFY" "${SESSION_DIR}/files.log" 2>/dev/null || echo 0)
            local deletes=$(grep -c "DELETE" "${SESSION_DIR}/files.log" 2>/dev/null || echo 0)
            printf "File System Events: %d (CREATE: %d, MODIFY: %d, DELETE: %d)\n" "$total_events" "$creates" "$modifies" "$deletes"
        fi
        
        printf "\n═══════════════════════════════════════════════════════════════════════════\n"
        
    } > "$summary"
    
    log_verbose "Summary generated"
}

# ==========================================
# TIMELINE
# ==========================================

generate_timeline() {
    local session="$1"
    local timeline="${session}/TIMELINE.txt"
    
    {
        printf "═══════════════════════════════════════════════════════════════════════════\n"
        printf "Event Timeline - Session $(basename "$session")\n"
        printf "═══════════════════════════════════════════════════════════════════════════\n\n"
        
        # Combine all timestamped events
        local temp_timeline=$(mktemp)
        
        # Files (limit to important events)
        if [ -f "${session}/files.log" ] && [ -s "${session}/files.log" ]; then
            grep -E "CREATE|DELETE" "${session}/files.log" 2>/dev/null | sed 's/^/[FILE] /' >> "$temp_timeline" || true
        fi
        
        # Network  
        if [ -f "${session}/network.log" ] && [ -s "${session}/network.log" ]; then
            grep '^\[' "${session}/network.log" 2>/dev/null | sed 's/^/[NET]  /' >> "$temp_timeline" || true
        fi
        
        # Suspicious dirs
        if [ -f "${session}/suspicious.log" ] && [ -s "${session}/suspicious.log" ]; then
            sed 's/^/[SUSP] /' "${session}/suspicious.log" 2>/dev/null >> "$temp_timeline" || true
        fi
        
        # Java processes (sample only)
        if [ -f "${session}/java-processes.log" ] && [ -s "${session}/java-processes.log" ]; then
            grep '^\[' "${session}/java-processes.log" 2>/dev/null | head -20 | sed 's/^/[JAVA] /' >> "$temp_timeline" || true
        fi
        
        if [ -s "$temp_timeline" ]; then
            sort "$temp_timeline" 2>/dev/null | head -100 || cat "$temp_timeline" | head -100
            local total_events=$(wc -l < "$temp_timeline" 2>/dev/null || echo 0)
            if [ "$total_events" -gt 100 ]; then
                printf "\n(Showing first 100 of %d events - see individual logs for complete data)\n" "$total_events"
            fi
        else
            printf "No timeline events recorded.\n"
        fi
        
        rm -f "$temp_timeline"
        
    } > "$timeline" 2>/dev/null || true
    
    log_verbose "Timeline generated"
}

# ==========================================
# ANALYSIS
# ==========================================

analyze_session() {
    local session="${1:-}"
    
    # If no session provided, find latest
    if [ -z "$session" ] || [ ! -d "$session" ]; then
        session=$(find "${XDG_STATE_HOME}/tlauncher-logs" -maxdepth 1 -type d -name "session_*" 2>/dev/null | sort -r | head -n1)
        if [ -z "$session" ]; then
            log_error "No session found to analyze"
            printf "${YELLOW}Tip: Run with -M to enable monitoring${NC}\n" >&2
            return 1
        fi
    fi
    
    printf "\n${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
    printf "${CYAN}Session Analysis${NC}\n"
    printf "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n\n"
    
    printf "Session: ${BLUE}$(basename "$session")${NC}\n\n"
    
    # Show summary if exists
    if [ -f "${session}/SUMMARY.txt" ]; then
        cat "${session}/SUMMARY.txt"
        printf "\n"
    fi
    
    # Filesystem changes
    printf "${YELLOW}┌── Filesystem Changes ──┐${NC}\n\n"
    if [ -f "${session}/snapshot-before.txt" ] && [ -f "${session}/snapshot-after.txt" ]; then
        local new_files
        new_files=$(comm -13 \
            <(awk '{print $NF}' "${session}/snapshot-before.txt" 2>/dev/null | sort) \
            <(awk '{print $NF}' "${session}/snapshot-after.txt" 2>/dev/null | sort) || true)
        
        local new_count=$(printf "%s" "$new_files" | grep -c . || echo 0)
        
        if [ "$new_count" -gt 0 ]; then
            printf "${YELLOW}New files: %d${NC}\n\n" "$new_count"
            
            # Check for suspicious patterns
            if printf "%s" "$new_files" | grep -qE "\.(mozilla|firefox|chrome)"; then
                printf "${RED}⚠ WARNING: Browser directories detected!${NC}\n"
                printf "%s\n" "$new_files" | grep -E "\.(mozilla|firefox|chrome)" | sed 's/^/  /'
                printf "\n"
            fi
            
            if printf "%s" "$new_files" | grep -qE "\.jar$"; then
                printf "${YELLOW}ℹ New JAR files (updates):${NC}\n"
                printf "%s\n" "$new_files" | grep "\.jar$" | sed 's/^/  /'
                printf "\n"
            fi
            
            # Show first 20 files
            printf "${BLUE}Recent files (first 20):${NC}\n"
            printf "%s\n" "$new_files" | head -20 | sed 's/^/  /'
            if [ "$new_count" -gt 20 ]; then
                printf "  ... and %d more\n" $((new_count - 20))
            fi
        else
            printf "${GREEN}✓ No new files created${NC}\n"
        fi
    fi
    
    # Network activity
    printf "\n${YELLOW}┌── Network Activity ──┐${NC}\n\n"
    if [ -s "${session}/network.log" ]; then
        local ips
        ips=$(grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' "${session}/network.log" 2>/dev/null | sort -u || true)
        local ip_count=$(printf "%s" "$ips" | grep -c . || echo 0)
        
        if [ "$ip_count" -gt 0 ]; then
            printf "${BLUE}Unique IPs contacted: %d${NC}\n\n" "$ip_count"
            printf "%s\n" "$ips" | sed 's/^/  /' | head -20
            if [ "$ip_count" -gt 20 ]; then
                printf "  ... and %d more\n" $((ip_count - 20))
            fi
        else
            printf "${YELLOW}⚠ No IPs captured (connections may have been too fast)${NC}\n"
            printf "${BLUE}Tip: Check files.log for actual network activity patterns${NC}\n"
        fi
    else
        printf "${GREEN}✓ No network activity logged${NC}\n"
    fi
    
    # Resource usage
    printf "\n${YELLOW}┌── Resource Usage ──┐${NC}\n\n"
    if [ -s "${session}/resources.log" ]; then
        printf "${BLUE}Peak resource usage:${NC}\n"
        awk -F'[|:]' '
            {
                gsub(/CPU: | |%/, "", $2); gsub(/MEM: | |%/, "", $3);
                cpu = $2 + 0; mem = $3 + 0;
                if (cpu > max_cpu) max_cpu = cpu;
                if (mem > max_mem) max_mem = mem;
            } 
            END {
                if (max_cpu > 0 || max_mem > 0) {
                    printf "  CPU: %.1f%%\n  Memory: %.1f%%\n", max_cpu, max_mem
                } else {
                    print "  (no data captured)"
                }
            }
        ' "${session}/resources.log" 2>/dev/null || printf "  (parsing failed)\n"
    else
        printf "${YELLOW}⚠ No resource data captured${NC}\n"
    fi
    
    # Suspicious directories
    printf "\n${YELLOW}┌── Suspicious Directory Detection ──┐${NC}\n\n"
    if [ -s "${session}/suspicious.log" ]; then
        printf "${RED}⚠ ALERT: Suspicious directories detected!${NC}\n\n"
        cat "${session}/suspicious.log"
        printf "\n${YELLOW}Note: .cache is normal, but .mozilla/.firefox would be suspicious${NC}\n"
    else
        printf "${GREEN}✓ No suspicious directories detected${NC}\n"
    fi
    
    # Java subprocess activity
    printf "\n${YELLOW}┌── Java Process Activity ──┐${NC}\n\n"
    if [ -s "${session}/java-processes.log" ]; then
        local unique_jars=$(grep -oE '/[^ ]+\.jar' "${session}/java-processes.log" 2>/dev/null | sort -u || true)
        if [ -n "$unique_jars" ]; then
            printf "${BLUE}JAR files executed:${NC}\n"
            printf "%s\n" "$unique_jars" | sed 's/^/  /'
            printf "\n${YELLOW}Note: Multiple JARs may indicate auto-update behavior${NC}\n"
        else
            printf "${YELLOW}⚠ No JAR processes captured${NC}\n"
        fi
    else
        printf "${YELLOW}⚠ No Java process data captured${NC}\n"
    fi
    
    printf "\n${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
    printf "\n${BLUE}Full logs:${NC} %s\n" "$session"
    printf "${BLUE}Available files:${NC}\n"
    ls -1 "$session" 2>/dev/null | sed 's/^/  - /' || printf "  (no files found)\n"
    
    # Timeline preview
    if [ -f "${session}/TIMELINE.txt" ]; then
        printf "\n${YELLOW}┌── Timeline Preview (first 10 events) ──┐${NC}\n\n"
        head -15 "${session}/TIMELINE.txt" 2>/dev/null | tail -10 || echo "  (empty)"
        printf "\n${BLUE}Full timeline:${NC} %s/TIMELINE.txt\n" "$session"
    fi
    
    # Mozilla check if requested
    if [ "$MOZILLA_CHECK" = true ]; then
        check_mozilla_directory
    fi
    
    printf "\n${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
    printf "${GREEN}Analysis complete!${NC}\n"
    printf "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n\n"
}

check_mozilla_directory() {
    printf "\n${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
    printf "${CYAN}Mozilla Directory Check${NC}\n"
    printf "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n\n"
    
    local sandbox_mozilla="${SANDBOX_DIR}/.mozilla"
    
    if [ ! -d "$sandbox_mozilla" ]; then
        printf "${GREEN}✓ .mozilla does not exist in sandbox${NC}\n"
        printf "${GREEN}  (No browser data access attempted)${NC}\n"
        return 0
    fi
    
    printf "${YELLOW}⚠ .mozilla directory EXISTS in sandbox${NC}\n\n"
    
    # Count files
    local file_count=$(find "$sandbox_mozilla" -type f 2>/dev/null | wc -l)
    local dir_count=$(find "$sandbox_mozilla" -type d 2>/dev/null | wc -l)
    
    printf "Structure: %d directories, %d files\n\n" "$dir_count" "$file_count"
    
    if [ "$file_count" -eq 0 ]; then
        printf "${BLUE}Status: Empty structure (likely safe)${NC}\n"
    else
        printf "${RED}Status: Contains data - manual inspection recommended${NC}\n"
        printf "\nLargest files:\n"
        find "$sandbox_mozilla" -type f -printf "%s %p\n" 2>/dev/null | \
            sort -rn | head -10 | \
            awk '{printf "  %8d bytes  %s\n", $1, $2}' || echo "  (none found)"
    fi
    
    # Compare with real mozilla if it exists
    if [ -d "$MOZILLA_SEARCH_PATH" ]; then
        printf "\n${BLUE}Comparing with real Mozilla directory...${NC}\n"
        printf "Real path: %s\n\n" "$MOZILLA_SEARCH_PATH"
        
        if diff -rq "$MOZILLA_SEARCH_PATH" "$sandbox_mozilla" >/dev/null 2>&1; then
            printf "${RED}⚠⚠⚠ CRITICAL: Exact copy of real Mozilla directory!${NC}\n"
            printf "${RED}     This indicates potential data exfiltration attempt!${NC}\n"
        else
            local common_files=$(comm -12 \
                <(find "$MOZILLA_SEARCH_PATH" -type f -printf "%P\n" 2>/dev/null | sort) \
                <(find "$sandbox_mozilla" -type f -printf "%P\n" 2>/dev/null | sort) | wc -l)
            
            if [ "$common_files" -gt 0 ]; then
                printf "${YELLOW}Warning: %d files have matching paths${NC}\n" "$common_files"
            else
                printf "${GREEN}Different structure from real home${NC}\n"
            fi
        fi
    fi
    
    printf "\n"
}

# ==========================================
# CLEANUP
# ==========================================

cleanup() {
    # Stop monitors
    if [ ${#MONITOR_PIDS[@]} -gt 0 ]; then
        for pid in "${MONITOR_PIDS[@]}"; do
            kill "$pid" 2>/dev/null || true
        done
    fi
    
    # Remove lockfile
    rm -f "$LOCKFILE"
}

trap cleanup EXIT INT TERM

# ==========================================
# USAGE
# ==========================================

usage() {
    printf "${CYAN}╔═════════════════════════════════════════════════════════════════════════════╗${NC}\n"
    printf "${CYAN}║       TLauncher Sandboxed Launcher v%-8s                                  ║${NC}\n" "$VERSION"
    printf "${CYAN}╚═════════════════════════════════════════════════════════════════════════════╝${NC}\n\n"
    
    printf "${GREEN}✓ No root/sudo required - works without special permissions!${NC}\n\n"
    
    printf "${YELLOW}PURPOSE${NC}\n"
    printf "  Runs TLauncher in a secure Firejail sandbox while capturing complete\n"
    printf "  activity logs including operations that don't appear in normal logs.\n\n"
    
    printf "${YELLOW}USAGE${NC}\n"
    printf "  %s [OPTIONS]\n\n" "$0"
    
    printf "${YELLOW}BASIC OPTIONS${NC}\n"
    printf "  ${BLUE}-v, --verbose${NC}          Show TLauncher output in terminal\n"
    printf "  ${BLUE}-n, --offline${NC}          Block ALL network (force offline mode)\n"
    printf "  ${BLUE}-f, --file PATH${NC}        Specify TLauncher.jar location\n"
    printf "  ${BLUE}-h, --help${NC}             Show this help\n\n"
    
    printf "${YELLOW}MONITORING OPTIONS${NC}\n"
    printf "  ${BLUE}-M, --monitor${NC}          Enable comprehensive monitoring:\n"
    printf "                           • Filesystem events (inotifywait)\n"
    printf "                           • Network connections (ss)\n"
    printf "                           • Process activity (ps)\n"
    printf "                           • Suspicious directory detection\n"
    printf "                           • Java subprocess tracking\n"
    printf "  ${BLUE}-a, --analyze${NC}          Auto-analyze results after execution\n"
    printf "  ${BLUE}-A, --analyze-only${NC}     Analyze latest session WITHOUT running\n\n"
    
    printf "${YELLOW}SECURITY CHECKS${NC}\n"
    printf "  ${BLUE}-m, --mozilla${NC}          Check for .mozilla directory access\n"
    printf "  ${BLUE}-ml, --mozilla-path${NC}    Custom mozilla path (default: ~/.mozilla)\n\n"
    
    printf "${YELLOW}COMMON USAGE PATTERNS${NC}\n"
    printf "  ${GREEN}Quick run:${NC}\n"
    printf "    %s\n\n" "$0"
    
    printf "  ${GREEN}First time / security audit:${NC}\n"
    printf "    %s -v -M -a -m\n" "$0"
    printf "    ${CYAN}→ Full monitoring with immediate analysis${NC}\n\n"
    
    printf "  ${GREEN}Normal monitoring:${NC}\n"
    printf "    %s -M -a\n" "$0"
    printf "    ${CYAN}→ Silent monitoring with analysis after${NC}\n\n"
    
    printf "  ${GREEN}Review previous session:${NC}\n"
    printf "    %s -A\n" "$0"
    printf "    ${CYAN}→ Analyze logs without running TLauncher${NC}\n\n"
    
    printf "${YELLOW}WHAT'S NEW IN v2.3${NC}\n"
    printf "  ${GREEN}✓${NC} Fixed network.log (now captures ALL connections)\n"
    printf "  ${GREEN}✓${NC} Improved monitor timing (catches fast processes)\n"
    printf "  ${GREEN}✓${NC} Better process detection (more permissive grep)\n"
    printf "  ${GREEN}✓${NC} Enhanced error handling\n"
    printf "  ${GREEN}✓${NC} More precise timestamps (milliseconds)\n\n"
    
    printf "${YELLOW}OUTPUT LOCATION${NC}\n"
    printf "  ${XDG_STATE_HOME}/tlauncher-logs/session_YYYYMMDD_HHMMSS/\n\n"
    
    printf "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
    printf "${GREEN}Uses only standard Linux tools - no special permissions needed!${NC}\n"
    printf "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n\n"
    
    exit 0
}

# ==========================================
# MAIN
# ==========================================

main() {
    local analyze_only=false
    
    # Parse arguments
    while [ $# -gt 0 ]; do
        case "$1" in
            -v|--verbose) VERBOSE=true; shift ;;
            -n|--offline) OFFLINE_MODE=true; shift ;;
            -M|--monitor) MONITOR_ENABLED=true; shift ;;
            -a|--analyze) AUTO_ANALYZE=true; shift ;;
            -A|--analyze-only) analyze_only=true; shift ;;
            -m|--mozilla) MOZILLA_CHECK=true; shift ;;
            -ml|--mozilla-path)
                if [ -z "${2:-}" ]; then
                    die "--mozilla-path requires a path argument"
                fi
                MOZILLA_SEARCH_PATH="$2"
                shift 2
                ;;
            -f|--file)
                if [ -z "${2:-}" ]; then
                    die "--file requires a path argument"
                fi
                TLAUNCHER_PATH="$2"
                shift 2
                ;;
            -h|--help) usage ;;
            -*)
                printf "${RED}Error: Unknown option '%s'${NC}\n\n" "$1" >&2
                printf "Run '${BLUE}%s --help${NC}' for usage information\n" "$0" >&2
                exit 1
                ;;
            *)
                printf "${RED}Error: Unexpected argument '%s'${NC}\n\n" "$1" >&2
                printf "If specifying TLauncher file, use: ${BLUE}-f %s${NC}\n" "$1" >&2
                printf "Run '${BLUE}%s --help${NC}' for usage\n" "$0" >&2
                exit 1
                ;;
        esac
    done
    
    # Validate flag combinations
    if [ "$AUTO_ANALYZE" = true ] && [ "$MONITOR_ENABLED" = false ] && [ "$analyze_only" = false ]; then
        log_warn "Flag -a (auto-analyze) requires -M (monitor) to generate logs"
        printf "${YELLOW}Tip: Use '%s -M -a' to enable both${NC}\n" "$0" >&2
        AUTO_ANALYZE=false
    fi
    
    # Analyze-only mode
    if [ "$analyze_only" = true ]; then
        analyze_session
        exit 0
    fi
    
    # Normal execution
    check_requirements
    
    local tlauncher
    tlauncher=$(find_tlauncher)
    
    # Setup sandbox first (always needed)
    setup_sandbox "$tlauncher"
    
    # Show configuration summary if verbose or monitoring
    if [ "$VERBOSE" = true ] || [ "$MONITOR_ENABLED" = true ]; then
        printf "\n${CYAN}╔═════════════════════════════════════════════════════════════════════════════╗${NC}\n"
        printf "${CYAN}║                    Configuration Summary                                    ║${NC}\n"
        printf "${CYAN}╚═════════════════════════════════════════════════════════════════════════════╝${NC}\n\n"
        
        printf "${BLUE}Mode:${NC}            "
        if [ "$MONITOR_ENABLED" = true ]; then
            printf "${GREEN}Full Monitoring${NC}"
        else
            printf "${YELLOW}Basic Sandbox${NC}"
        fi
        printf "\n"
        
        printf "${BLUE}Output:${NC}          "
        if [ "$VERBOSE" = true ]; then
            printf "${GREEN}Verbose${NC}"
        else
            printf "${YELLOW}Silent${NC}"
        fi
        printf "\n"
        
        printf "${BLUE}Network:${NC}         "
        if [ "$OFFLINE_MODE" = true ]; then
            printf "${RED}Blocked${NC}"
        else
            printf "${GREEN}Allowed${NC}"
        fi
        printf "\n"
        
        printf "${BLUE}TLauncher:${NC}       %s\n" "$tlauncher"
        printf "${BLUE}Sandbox:${NC}         %s\n" "$SANDBOX_DIR"
        
        if [ "$MONITOR_ENABLED" = true ]; then
            SESSION_ID=$(date +%Y%m%d_%H%M%S)
            SESSION_DIR="${XDG_STATE_HOME}/tlauncher-logs/session_${SESSION_ID}"
            mkdir -p "$SESSION_DIR"
            printf "${BLUE}Logs:${NC}            %s\n" "$SESSION_DIR"
        fi
        
        printf "\n${CYAN}────────────────────────────────────────────────────────────────────────────────${NC}\n"
        printf "${YELLOW}Starting in 2 seconds... (Ctrl+C to cancel)${NC}\n"
        sleep 2
        printf "\n"
    fi
    
    # Setup sandbox is already done above
    
    if [ "$MONITOR_ENABLED" = true ]; then
        # Ensure session directory exists
        if [ -z "$SESSION_DIR" ]; then
            SESSION_ID=$(date +%Y%m%d_%H%M%S)
            SESSION_DIR="${XDG_STATE_HOME}/tlauncher-logs/session_${SESSION_ID}"
        fi
        mkdir -p "$SESSION_DIR"
        
        # Take pre-execution snapshot
        {
            printf "# Pre-execution snapshot\n"
            printf "# Timestamp: %s\n" "$(date '+%Y-%m-%d %H:%M:%S')"
            find "$SANDBOX_DIR" -printf "%T@ %M %u %g %s %p\n" 2>/dev/null | sort
        } > "${SESSION_DIR}/snapshot-before.txt"
        
        # Log system info
        {
            printf "# System Information\n"
            printf "# Timestamp: %s\n\n" "$(date '+%Y-%m-%d %H:%M:%S')"
            printf "User: %s (UID: %s)\n" "$REAL_USER" "$REAL_UID"
            printf "Home: %s\n" "$REAL_HOME"
            printf "Sandbox: %s\n" "$SANDBOX_DIR"
            printf "Java: %s\n" "$(java -version 2>&1 | head -n1)"
            printf "Firejail: %s\n" "$(firejail --version 2>&1 | head -n1)"
            printf "\nConfiguration:\n"
            printf "  Verbose: %s\n" "$VERBOSE"
            printf "  Offline: %s\n" "$OFFLINE_MODE"
            printf "  Monitor: %s\n" "$MONITOR_ENABLED"
            printf "  Auto-Analyze: %s\n" "$AUTO_ANALYZE"
        } > "${SESSION_DIR}/system-info.txt"
    fi
    
    run_sandboxed
}

main "$@"
