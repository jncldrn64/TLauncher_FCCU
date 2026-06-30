#!/usr/bin/env bash
# TLauncher Sandboxed Launcher
# Secure sandbox with comprehensive monitoring capabilities
#
# Hardening goals of this revision (see also the inline "WHY" comments):
#   - Background monitors must ALWAYS be reaped — no orphaned inotifywait/ss/ps
#     processes left writing into old session logs.
#   - Logs must stay small enough for a human (or an LLM) to read: noise filtering
#     for the filesystem monitor and "first-seen" semantics for process monitors.
#   - A short, post-session INCIDENT_REPORT.md aggregates the signal.
#   - Log retention so the directory never silently grows into the GBs.
#   - Optional, opt-in real HTTP(S) capture via mitmproxy.
#
# HARD CONSTRAINT: this script must NEVER call sudo, prompt for a password, or
# require elevated capabilities beyond what firejail already uses internally.
# (Installing packages like mitmproxy/sqlite3 by hand, outside this script, is
# the user's responsibility and is fine — the script itself stays unprivileged.)
set -euo pipefail

VERSION="2.4"

# ==========================================
# CONFIGURATION
# ==========================================

# User detection ( :-$(id -un) guards against USER being unset under set -u )
REAL_USER="${SUDO_USER:-${USER:-$(id -un)}}"
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
LOG_ROOT="${XDG_STATE_HOME}/tlauncher-logs"
LOCKFILE="${XDG_RUNTIME_DIR}/tlauncher-${REAL_USER}.lock"

# Options
VERBOSE=false
OFFLINE_MODE=false
MONITOR_ENABLED=false
AUTO_ANALYZE=false
MOZILLA_CHECK=false
TLAUNCHER_PATH=""
MOZILLA_SEARCH_PATH="${REAL_HOME}/.mozilla"

# New standalone / opt-in modes
KILL_ORPHANS=false       # -K: just reap stray monitors, don't launch
REPORT_SESSION=""        # -R DIR: (re)generate INCIDENT_REPORT.md for a session
CLEANUP_LOGS_FLAG=false   # -c: run log retention, don't launch
CLEANUP_DAYS=7           # default retention window (days)
LOG_SIZE_CAP_MB=500      # delete old compressed sessions once dir exceeds this
PROXY_ENABLED=false      # -P: opt-in mitmproxy HTTP(S) capture
PROXY_PORT=8080          # default mitmproxy listen port

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

# Filesystem noise: extended-regex fragments matched against each inotifywait
# event line. Anything that matches is considered benign engine churn and kept
# ONLY in files.log (lossless) — it is excluded from signal.log, which is the
# small file humans/analysis read first. Edit freely to tune your environment.
NOISE_PATTERNS=(
    'mesa_shader_cache/'
    '\.sqlite-wal$'
    '\.sqlite-shm$'
    '-journal$'
    'webview/\.test'
    '\.tmp$'
    'GPUCache/'
    'Code Cache/'
    'ShaderCache/'
    '\.lock$'
)
# Pre-joined into a single ERE; exported so the (separate-process) monitors see it.
NOISE_REGEX="$(IFS='|'; printf '%s' "${NOISE_PATTERNS[*]}")"

# Hosts considered benign for the mitmproxy summary (full request bodies are only
# surfaced for hosts NOT in this list, or for non-empty POST/PUT bodies).
MITM_ALLOWLIST=(
    "tlauncher.org" "fastrepo.org" "mojang.com" "forgecdn.net"
    "curseforge.com" "minecraft.net" "microsoft.com" "live.com" "xboxlive.com"
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
    # NOTE: explicit `return 0` — otherwise, when VERBOSE=false the `&&` chain
    # yields exit status 1 and, under `set -e`, a bare `log_verbose ...` call
    # aborts the whole script. This previously broke any non-verbose run (e.g.
    # the documented `-M -a` "normal monitoring" pattern).
    [ "$VERBOSE" = true ] && log_msg "$@"
    return 0
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
# PROCESS HELPERS (orphan-proof cleanup)
# ==========================================

# Recursively kill a process and all of its descendants.
#
# WHY: the background monitors are bash shells that spawn long-running leaf tools
# (inotifywait -m, ss, ps, mitmdump). If we only `kill $pid` the shell, the leaf
# tool is reparented to init and KEEPS WRITING to the inherited log fd — this is
# exactly how a single orphaned inotifywait grew one session's files.log to 51MB.
# Killing children first (depth-first) avoids that reparent race.
kill_tree() {
    local pid="$1" sig="${2:-TERM}" child
    for child in $(pgrep -P "$pid" 2>/dev/null); do
        kill_tree "$child" "$sig"
    done
    kill "-${sig}" "$pid" 2>/dev/null || true
}

# Print PIDs of stray monitor processes left over from previous sessions, matched
# by command-line pattern. Used by -K and by the start-of-run orphan warning.
# Each of our monitors is launched as `bash -c <body> tlauncher-mon-<sid>-<name>`
# (argv[0] tag), plus we match the known leaf tools as a deeper safety net.
find_orphan_pids() {
    # Build an exclusion list of THIS process plus its whole ancestor chain, so a
    # fuzzy `pgrep -f` can never flag (and kill) the very shell that launched us —
    # e.g. an interactive shell whose history/command line happens to contain the
    # tag string. Genuine strays from previous sessions are never our ancestors.
    local excl="$$" pid="$$"
    while :; do
        pid="$(ps -o ppid= -p "$pid" 2>/dev/null | tr -d ' ')"
        { [ -z "$pid" ] || [ "$pid" = 0 ] || [ "$pid" = 1 ]; } && break
        excl="${excl}|${pid}"
    done
    {
        pgrep -f "tlauncher-mon-"                          2>/dev/null || true
        pgrep -f "inotifywait -m -r.*tlauncher-sandbox"    2>/dev/null || true
        pgrep -f "mitmdump .*tlauncher-logs"               2>/dev/null || true
    } | sort -un | grep -vE "^(${excl})\$" || true
}

# Non-fatal: warn (stderr + session log) if prior-session monitors are still alive.
warn_orphans() {
    local pids; pids="$(find_orphan_pids)"
    [ -z "$pids" ] && return 0
    log_warn "Detected orphaned monitor process(es) from a previous session:"
    local p
    for p in $pids; do
        printf "    PID %s: %s\n" "$p" "$(ps -o args= -p "$p" 2>/dev/null | head -c 100)" >&2
    done
    log_warn "These are NOT being killed automatically. Run '$0 -K' to terminate them."
}

# -K/--kill-orphans implementation: find and kill stray monitors, loudly.
kill_orphans() {
    local pids; pids="$(find_orphan_pids)"
    if [ -z "$pids" ]; then
        log_msg "No orphaned monitor processes found."
        return 0
    fi
    log_warn "Found orphaned monitor process(es); terminating:"
    local p
    for p in $pids; do
        printf "    PID %s: %s\n" "$p" "$(ps -o args= -p "$p" 2>/dev/null | head -c 120)" >&2
    done
    for p in $pids; do kill_tree "$p" TERM; done
    sleep 1
    # Re-scan and force-kill anything still standing.
    pids="$(find_orphan_pids)"
    for p in $pids; do kill_tree "$p" KILL; done
    log_msg "Orphaned monitors terminated."
}

# Stop the monitors started in THIS run (TERM, then KILL), then a tag-based
# pkill safety net for anything that slipped the PID list.
stop_monitors() {
    if [ "${#MONITOR_PIDS[@]}" -gt 0 ]; then
        local pid
        for pid in "${MONITOR_PIDS[@]}"; do kill_tree "$pid" TERM; done
        sleep 1
        for pid in "${MONITOR_PIDS[@]}"; do kill_tree "$pid" KILL; done
    fi
    [ -n "${SESSION_ID:-}" ] && pkill -f "tlauncher-mon-${SESSION_ID}" 2>/dev/null || true
    MONITOR_PIDS=()
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
        # pgrep/pkill power the orphan-proof cleanup.
        command -v pgrep >/dev/null 2>&1 || missing+=("procps")
        command -v pkill >/dev/null 2>&1 || missing+=("procps")
    fi

    if [ ${#missing[@]} -gt 0 ]; then
        log_error "Missing required packages:"
        printf '  - %s\n' "${missing[@]}" >&2
        # NOTE: this is a printed HINT for the user to run manually. The script
        # itself never invokes sudo (hard constraint).
        printf "\nInstall manually with: sudo apt install %s\n" "${missing[*]}" >&2
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

    # Proxy capture (-P): expose HTTP(S)_PROXY to non-JVM helpers inside the
    # sandbox. The JVM itself does NOT honour these env vars by default — that is
    # handled separately via -Dhttp.proxyHost/-Dhttps.proxyHost on the java
    # command (see run_sandboxed). Without --net the sandbox shares the host net
    # namespace, so 127.0.0.1:PORT reaches the host mitmdump.
    if [ "$PROXY_ENABLED" = true ]; then
        params+=(--env=HTTP_PROXY=http://127.0.0.1:${PROXY_PORT})
        params+=(--env=HTTPS_PROXY=http://127.0.0.1:${PROXY_PORT})
        params+=(--env=http_proxy=http://127.0.0.1:${PROXY_PORT})
        params+=(--env=https_proxy=http://127.0.0.1:${PROXY_PORT})
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

# True when this run produces a session directory (full monitoring OR proxy capture).
session_logging_active() {
    [ "$MONITOR_ENABLED" = true ] || [ "$PROXY_ENABLED" = true ]
}

# ==========================================
# MONITORING SETUP
# ==========================================

# Shared shell preamble injected into every backgrounded monitor. Because each
# monitor is a separate `bash -c` process (so we can tag its argv[0]), it does
# NOT inherit this script's functions — we ship the helpers it needs as text.
read -r -d '' MONITOR_PREAMBLE <<'PREAMBLE' || true
# first_seen_loop LOGFILE SEENFILE PRODUCER_CMD INTERVAL
# Emits a line to LOGFILE only when PRODUCER_CMD output contains a line not seen
# before ("NEW:"), and once when a previously-seen line disappears ("ENDED:").
# WHY: the old monitors dumped a full `ps auxf`/`ss` snapshot every 2s, producing
# tens of MB of near-identical noise. First-seen keeps the same detection power
# (new/suspicious processes still surface immediately) at ~1-2 orders of magnitude
# less volume.
first_seen_loop() {
    local logfile="$1" seen="$2" producer="$3" interval="${4:-2}"
    local ended="${seen}.ended"
    : > "$seen"; : > "$ended"
    local ts cur line
    while true; do
        ts="$(date '+%Y-%m-%d %H:%M:%S.%3N')"
        cur="$(mktemp)"
        eval "$producer" > "$cur" 2>/dev/null || true
        # Newly appeared lines.
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            if ! grep -Fxq -- "$line" "$seen" 2>/dev/null; then
                printf '%s\n' "$line" >> "$seen"
                printf '[%s] NEW: %s\n' "$ts" "$line" >> "$logfile"
            fi
        done < "$cur"
        # Lines that were seen before but are gone now (log the termination once).
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            if ! grep -Fxq -- "$line" "$cur" 2>/dev/null && ! grep -Fxq -- "$line" "$ended" 2>/dev/null; then
                printf '%s\n' "$line" >> "$ended"
                printf '[%s] ENDED: %s\n' "$ts" "$line" >> "$logfile"
            fi
        done < "$seen"
        rm -f "$cur"
        sleep "$interval"
    done
}
PREAMBLE

# Launch a monitor body as a tagged background process and track its PID.
#
# WHY the tag: argv[0] = "tlauncher-mon-<session>-<name>" lets cleanup()/-K find
# and kill strays by pattern even if PID tracking is ever lost. We deliberately
# do NOT use setsid here so that $! is the bash PID we can track precisely;
# descendants are reaped by kill_tree().
spawn_monitor() {
    local name="$1" body="$2"
    bash -c "${MONITOR_PREAMBLE}
${body}" "tlauncher-mon-${SESSION_ID}-${name}" &
    local pid=$!
    MONITOR_PIDS+=("$pid")
    log_verbose "  → ${name} monitor PID: $pid"
}

monitor_filesystem() {
    log_verbose "Starting filesystem monitor..."
    # Every event goes to files.log (lossless). Events that do NOT match the noise
    # regex are ALSO copied to signal.log — the small file analysis reads first.
    spawn_monitor "filesystem" '
        sleep 0.3
        inotifywait -m -r \
            -e modify,create,delete,move,close_write \
            --timefmt "%Y-%m-%d %H:%M:%S.%3N" \
            --format "[%T] %e %w%f" \
            "$SANDBOX_DIR" 2>&1 | while IFS= read -r line; do
                printf "%s\n" "$line" >> "$SESSION_DIR/files.log"
                if [ -z "$NOISE_REGEX" ] || ! printf "%s" "$line" | grep -qE "$NOISE_REGEX"; then
                    printf "%s\n" "$line" >> "$SESSION_DIR/signal.log"
                fi
            done
    '
}

monitor_network() {
    log_verbose "Starting network monitor (first-seen connections)..."
    # First-seen of established peer endpoints (no -p, so no privileges needed).
    spawn_monitor "network" '
        sleep 0.5
        first_seen_loop "$SESSION_DIR/network.log" "$SESSION_DIR/.seen_net" \
            '\''ss -tn state established 2>/dev/null | tail -n +2 | awk "{print \$4\" -> \"\$5}"'\'' 2
    '
}

monitor_processes() {
    log_verbose "Starting process monitor (first-seen sandboxes)..."
    spawn_monitor "processes" '
        sleep 0.5
        first_seen_loop "$SESSION_DIR/processes.log" "$SESSION_DIR/.seen_fj" \
            '\''firejail --list 2>/dev/null'\'' 8
    '
}

monitor_resources() {
    log_verbose "Starting resource monitor..."
    spawn_monitor "resources" '
        sleep 0.5
        while true; do
            ts="$(date "+%Y-%m-%d %H:%M:%S.%3N")"
            resources=$(ps auxww 2>/dev/null | grep "[j]ava" | grep -v "grep" | \
                awk "{printf \"[CPU: %s%% | MEM: %s%% | VSZ: %s KB | RSS: %s KB] %s\n\", \$3, \$4, \$5, \$6, \$11}")
            if [ -n "$resources" ]; then
                printf "[%s] %s\n" "$ts" "$resources" >> "$SESSION_DIR/resources.log"
            fi
            sleep 2
        done
    '
}

monitor_java_processes() {
    log_verbose "Starting Java process monitor (first-seen)..."
    spawn_monitor "java" '
        sleep 0.5
        first_seen_loop "$SESSION_DIR/java-processes.log" "$SESSION_DIR/.seen_java" \
            '\''ps -ww -eo args= 2>/dev/null | grep -E "[j]ava" | grep -v "grep" | grep -v "tlauncher-mon"'\'' 2
    '
}

monitor_suspicious_dirs() {
    log_verbose "Starting suspicious directory monitor..."
    spawn_monitor "suspicious" '
        suspicious=(".mozilla" ".firefox" ".config/google-chrome" ".config/chromium" ".cache" ".gnupg")
        sleep 1
        while true; do
            ts="$(date "+%Y-%m-%d %H:%M:%S.%3N")"
            for dir in "${suspicious[@]}"; do
                if [ -d "${SANDBOX_DIR}/${dir}" ]; then
                    if ! grep -q "DETECTED: ${dir}\$" "${SESSION_DIR}/suspicious.log" 2>/dev/null; then
                        file_count=$(find "${SANDBOX_DIR}/${dir}" -type f 2>/dev/null | wc -l)
                        dir_size=$(du -sh "${SANDBOX_DIR}/${dir}" 2>/dev/null | cut -f1)
                        {
                            printf "[%s] DETECTED: %s\n" "$ts" "$dir"
                            printf "[%s]   Location: %s\n" "$ts" "${SANDBOX_DIR}/${dir}"
                            printf "[%s]   Files: %s\n" "$ts" "$file_count"
                            printf "[%s]   Size: %s\n\n" "$ts" "$dir_size"
                        } >> "${SESSION_DIR}/suspicious.log"
                    fi
                fi
            done
            sleep 3
        done
    '
}

monitor_mitmproxy() {
    # -P/--proxy: opt-in real HTTP(S) capture. Strictly optional — if mitmdump is
    # not installed we disable the flag for this run and keep going (we never abort
    # the whole launch over a missing optional dependency).
    if ! command -v mitmdump >/dev/null 2>&1; then
        log_warn "mitmdump not found — -P/--proxy disabled for this run."
        log_warn "Install manually (no sudo for the script itself): pip install mitmproxy --break-system-packages"
        PROXY_ENABLED=false
        return 1
    fi
    if [ "$OFFLINE_MODE" = true ]; then
        log_warn "-P/--proxy with -n/--offline: sandbox has no network, nothing will be captured."
    fi
    log_msg "Starting mitmproxy capture on 127.0.0.1:${PROXY_PORT} (flow → mitm.flow)"
    # exec replaces the tag-bash with mitmdump; $! stays valid for kill_tree, and
    # -K still matches it via the "mitmdump .*tlauncher-logs" pattern.
    spawn_monitor "mitm" '
        exec mitmdump -p "$PROXY_PORT" -w "$SESSION_DIR/mitm.flow" --flow-detail 1 \
            > "$SESSION_DIR/mitm.log" 2>&1
    '
}

# ==========================================
# EXECUTION
# ==========================================

run_sandboxed() {
    local firejail_params
    mapfile -t firejail_params < <(build_firejail_params)

    # Build the in-sandbox java command. With -P we add the JVM proxy system
    # properties: the JVM does NOT read HTTP_PROXY/HTTPS_PROXY env vars by default,
    # so the firejail --env settings alone would NOT route Java traffic through
    # mitmproxy — these -D properties are what actually do it.
    local java_opts=""
    if [ "$PROXY_ENABLED" = true ]; then
        java_opts="-Dhttp.proxyHost=127.0.0.1 -Dhttp.proxyPort=${PROXY_PORT} -Dhttps.proxyHost=127.0.0.1 -Dhttps.proxyPort=${PROXY_PORT}"
    fi
    local java_cmd="java ${java_opts} -jar bin/TLauncher.jar"

    # Log firejail command
    if session_logging_active; then
        {
            printf "# Firejail Command\n"
            printf "# Timestamp: %s\n\n" "$(date '+%Y-%m-%d %H:%M:%S')"
            printf "# Note: --private mounts sandbox as new HOME\n"
            printf "firejail"
            printf " %s" "${firejail_params[@]}"
            printf " bash -c '%s'\n" "$java_cmd"
        } > "${SESSION_DIR}/firejail-command.txt"
    fi

    # ----------------------------------------------------------------------
    # WHY (critical fix): this used to be wrapped in a ( ... ) 200>"$LOCKFILE"
    # subshell. MONITOR_PIDS is a global array, but the monitor_* helpers ran
    # INSIDE that subshell, so the PIDs they appended never propagated to the
    # parent shell. The later cleanup loop therefore always iterated an EMPTY
    # array and every background monitor (inotifywait/ss/ps) was orphaned —
    # which is what retroactively contaminated old logs (a stray inotifywait
    # grew one files.log to 51MB).
    #
    # Fix: hold the lock via an exec'd fd in the CURRENT shell. Now the monitors,
    # MONITOR_PIDS, and the code that kills them all live in the same scope.
    # ----------------------------------------------------------------------
    exec 200>"$LOCKFILE"
    flock -n 200 || die "TLauncher already running (lockfile exists)"

    # Export the handful of vars the (separate-process) monitors reference.
    export SANDBOX_DIR SESSION_DIR SESSION_ID NOISE_REGEX PROXY_PORT

    if [ "$MONITOR_ENABLED" = true ]; then
        log_msg "Starting all monitors..."

        monitor_filesystem
        monitor_network
        monitor_processes
        monitor_resources
        monitor_java_processes
        monitor_suspicious_dirs

        sleep 1
        log_msg "All monitors active (PIDs: ${MONITOR_PIDS[*]})"
    fi

    if [ "$PROXY_ENABLED" = true ]; then
        monitor_mitmproxy || true
    fi

    log_msg "Launching TLauncher in sandbox..."

    # Run firejail. errexit is disabled around this block so a non-zero TLauncher
    # exit does not skip monitor cleanup / report generation.
    local exit_code=0
    set +e
    if [ "$VERBOSE" = true ]; then
        if session_logging_active; then
            firejail "${firejail_params[@]}" \
                bash -c "$java_cmd" \
                2>&1 | tee "${SESSION_DIR}/tlauncher.log"
            exit_code=${PIPESTATUS[0]}
        else
            firejail "${firejail_params[@]}" \
                bash -c "$java_cmd"
            exit_code=$?
        fi
    else
        if session_logging_active; then
            firejail "${firejail_params[@]}" \
                bash -c "$java_cmd" \
                > "${SESSION_DIR}/tlauncher.log" 2>&1
            exit_code=$?
        else
            firejail "${firejail_params[@]}" \
                bash -c "$java_cmd" \
                >/dev/null 2>&1
            exit_code=$?
        fi
    fi
    set -e

    if session_logging_active; then
        log_msg "TLauncher exited (code: $exit_code)"
        log_msg "Stopping monitors..."

        stop_monitors

        log_verbose "All monitors stopped"

        # Take post-execution snapshot
        {
            printf "# Post-execution snapshot\n"
            printf "# Timestamp: %s\n" "$(date '+%Y-%m-%d %H:%M:%S')"
            find "$SANDBOX_DIR" -printf "%T@ %M %u %g %s %p\n" 2>/dev/null | sort
        } > "${SESSION_DIR}/snapshot-after.txt"

        # Generate summary, timeline and the aggregated incident report.
        generate_summary
        generate_timeline "$SESSION_DIR"
        generate_incident_report "$SESSION_DIR"

        # Auto-analyze if requested
        if [ "$AUTO_ANALYZE" = true ]; then
            printf "\n"
            analyze_session "$SESSION_DIR"
        else
            printf "\n${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
            printf "${GREEN}✓${NC} Session complete\n"
            printf "${BLUE}Logs:${NC} %s\n" "$SESSION_DIR"
            printf "${BLUE}Report:${NC} %s/INCIDENT_REPORT.md\n" "$SESSION_DIR"
            printf "${BLUE}Analyze with:${NC} $0 -A\n"
            printf "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
        fi
    fi

    return $exit_code
}

# Return the preferred filesystem-event log for a session: signal.log (noise
# filtered) when present, else files.log (older sessions / lossless fallback).
fs_event_log() {
    local s="$1"
    if [ -s "${s}/signal.log" ]; then
        printf "%s" "${s}/signal.log"
    else
        printf "%s" "${s}/files.log"
    fi
}

# ==========================================
# SUMMARY GENERATION
# ==========================================

generate_summary() {
    local summary="${SESSION_DIR}/SUMMARY.txt"
    local fslog; fslog="$(fs_event_log "$SESSION_DIR")"

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

        # File system events (from the noise-filtered signal log when available)
        if [ -s "$fslog" ]; then
            # NOTE: `grep -c` already prints 0 on no match (and exits 1). The old
            # `|| echo 0` ADDED a second 0, yielding "0\n0" and a printf %d crash
            # under set -e — which now happens routinely because signal.log is
            # noise-filtered and often has zero MODIFY events. `|| true` keeps the
            # single clean 0 and only swallows the exit code.
            local total_events=$(wc -l < "$fslog" 2>/dev/null || true); total_events=${total_events:-0}
            local creates=$(grep -c "CREATE" "$fslog" 2>/dev/null || true); creates=${creates:-0}
            local modifies=$(grep -c "MODIFY" "$fslog" 2>/dev/null || true); modifies=${modifies:-0}
            local deletes=$(grep -c "DELETE" "$fslog" 2>/dev/null || true); deletes=${deletes:-0}
            printf "File System Events [%s]: %d (CREATE: %d, MODIFY: %d, DELETE: %d)\n" \
                "$(basename "$fslog")" "$total_events" "$creates" "$modifies" "$deletes"
        fi

        printf "\n═══════════════════════════════════════════════════════════════════════════\n"

    } > "$summary"

    log_verbose "Summary generated"
}

# ==========================================
# INCIDENT REPORT (aggregated, KB-sized)
# ==========================================

generate_incident_report() {
    local session="${1:-${SESSION_DIR:-}}"
    if [ -z "$session" ]; then
        log_error "generate_incident_report: no session directory given"
        return 1
    fi
    if [ ! -d "$session" ]; then
        log_error "generate_incident_report: session not found: $session"
        return 1
    fi

    local report="${session}/INCIDENT_REPORT.md"
    local baseline="${XDG_DATA_HOME}/tlauncher-sandbox-baseline-ips.txt"
    local fslog; fslog="$(fs_event_log "$session")"

    {
        printf "# TLauncher Sandbox — Incident Report\n\n"
        printf -- "- Session: \`%s\`\n" "$(basename "$session")"
        printf -- "- Generated: %s\n" "$(date '+%Y-%m-%d %H:%M:%S')"
        printf -- "- Filesystem source: \`%s\`\n\n" "$(basename "$fslog")"

        # --- New processes (first-seen) ---
        printf "## New processes observed\n\n"
        local any_proc=false
        if [ -f "${session}/java-processes.log" ] && grep -q "NEW:" "${session}/java-processes.log" 2>/dev/null; then
            printf '```\n'
            grep "NEW:" "${session}/java-processes.log" 2>/dev/null | head -40
            printf '```\n'
            any_proc=true
        fi
        if [ -f "${session}/processes.log" ] && grep -q "NEW:" "${session}/processes.log" 2>/dev/null; then
            printf "\n_Sandboxes:_\n\n\`\`\`\n"
            grep "NEW:" "${session}/processes.log" 2>/dev/null | head -20
            printf '```\n'
            any_proc=true
        fi
        [ "$any_proc" = true ] || printf "_None recorded._\n"
        printf "\n"

        # --- Network endpoints vs baseline ---
        printf "## Network endpoints\n\n"
        if [ -s "${session}/network.log" ]; then
            local ips; ips="$(grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' "${session}/network.log" 2>/dev/null | sort -u)"
            if [ -f "$baseline" ]; then
                printf "_Compared against baseline: \`%s\`_\n\n" "$baseline"
                local newips; newips="$(comm -23 <(printf '%s\n' "$ips") <(sort -u "$baseline") 2>/dev/null)"
                if [ -n "$newips" ]; then
                    printf "**IPs NOT in baseline (review these):**\n\n\`\`\`\n%s\n\`\`\`\n" "$newips"
                else
                    printf "_All observed IPs are present in the baseline._\n"
                fi
            else
                printf "_No baseline file at \`%s\` — listing ALL observed IPs (populate that file from a run you consider clean to enable diffing)._\n\n" "$baseline"
                printf '```\n%s\n```\n' "${ips:-(none)}"
            fi
        else
            printf "_No network activity logged._\n"
        fi
        printf "\n"

        # --- New files (noise-filtered) ---
        printf "## New files created (noise-filtered)\n\n"
        if [ -s "$fslog" ]; then
            local nf; nf="$(grep -E "CREATE|MOVED_TO" "$fslog" 2>/dev/null | awk '{print $NF}' | sort -u)"
            if [ -n "$nf" ]; then
                local total; total="$(printf '%s\n' "$nf" | grep -c . || true)"; total=${total:-0}
                printf '```\n%s\n```\n' "$(printf '%s\n' "$nf" | head -60)"
                [ "$total" -gt 60 ] && printf "\n_…%d more — see signal.log / files.log._\n" "$((total - 60))"
            else
                printf "_None._\n"
            fi
        else
            printf "_No filesystem event log for this session._\n"
        fi
        printf "\n"

        # --- Mozilla / browser data check ---
        printf "## Browser data (.mozilla) check\n\n"
        if [ -d "${SANDBOX_DIR}/.mozilla" ]; then
            local mfiles; mfiles="$(find "${SANDBOX_DIR}/.mozilla" -type f 2>/dev/null | wc -l)"
            if [ "$mfiles" -eq 0 ]; then
                printf "⚠ \`.mozilla\` exists in sandbox but is empty (likely benign).\n"
            else
                printf "🚨 \`.mozilla\` exists in sandbox with **%d files** — manual inspection recommended.\n" "$mfiles"
            fi
        else
            printf "✓ No \`.mozilla\` directory in sandbox.\n"
        fi
        printf "\n"

        # --- mitmproxy capture summary ---
        if [ -f "${session}/mitm.flow" ]; then
            printf "## HTTP(S) capture (mitmproxy)\n\n"
            if command -v python3 >/dev/null 2>&1; then
                MITM_ALLOW="$(IFS=,; printf '%s' "${MITM_ALLOWLIST[*]}")" \
                python3 - "${session}/mitm.flow" <<'PYEOF' 2>/dev/null || printf "_Could not parse mitm.flow (mitmproxy python module missing?). Raw flow kept at mitm.flow._\n"
import os, sys
try:
    from mitmproxy import io, http
except Exception:
    print("_mitmproxy python module not available; raw flow saved at mitm.flow._")
    sys.exit(0)
allow = tuple(d for d in os.environ.get("MITM_ALLOW", "").split(",") if d)
def allowed(h):
    return any(h == d or h.endswith("." + d) for d in allow)
rows, bodies = [], []
try:
    with open(sys.argv[1], "rb") as f:
        for fl in io.FlowReader(f).stream():
            if not isinstance(fl, http.HTTPFlow):
                continue
            req, res = fl.request, fl.response
            host = req.pretty_host
            status = res.status_code if res else "-"
            size = len(res.raw_content) if (res and res.raw_content) else 0
            rows.append((host, req.method, req.path, status, size))
            interesting = (not allowed(host)) or (req.method in ("POST", "PUT") and req.raw_content)
            if interesting:
                try:
                    body = req.get_text() or ""
                except Exception:
                    body = ""
                bodies.append((req.method, host, req.path, body))
except Exception as e:
    print("_Error reading flow: %s_" % e)
    sys.exit(0)
print("| Host | Method | Path | Status | Resp bytes |")
print("|------|--------|------|--------|-----------|")
for h, m, p, s, sz in rows[:80]:
    pp = (p[:58] + "…") if len(p) > 58 else p
    pp = pp.replace("|", "%7C")
    print("| %s | %s | %s | %s | %s |" % (h, m, pp, s, sz))
if len(rows) > 80:
    print("\n_…%d more requests omitted._" % (len(rows) - 80))
if bodies:
    print("\n### Request bodies (non-allowlisted hosts or POST/PUT)\n")
    for m, h, p, b in bodies[:20]:
        print("- **%s %s%s**" % (m, h, p))
        b = (b or "").strip()
        if b:
            print("\n```\n%s\n```\n" % b[:1000])
PYEOF
            else
                printf "_python3 not available to summarize; raw flow at mitm.flow._\n"
            fi
            printf "\n"
        fi

        # --- Sizes (growth sanity check) ---
        printf "## Sizes\n\n"
        printf -- "- Session dir: %s\n" "$(du -sh "$session" 2>/dev/null | cut -f1 || echo '?')"
        printf -- "- Sandbox dir: %s\n" "$(du -sh "$SANDBOX_DIR" 2>/dev/null | cut -f1 || echo '?')"
        printf "\n"

    } > "$report"

    log_verbose "Incident report generated: $report"
}

# ==========================================
# TIMELINE
# ==========================================

generate_timeline() {
    local session="$1"
    local timeline="${session}/TIMELINE.txt"
    local fslog; fslog="$(fs_event_log "$session")"

    {
        printf "═══════════════════════════════════════════════════════════════════════════\n"
        printf "Event Timeline - Session $(basename "$session")\n"
        printf "═══════════════════════════════════════════════════════════════════════════\n\n"

        # Combine all timestamped events
        local temp_timeline=$(mktemp)

        # Files (limit to important events, from the noise-filtered log)
        if [ -f "$fslog" ] && [ -s "$fslog" ]; then
            grep -E "CREATE|DELETE" "$fslog" 2>/dev/null | sed 's/^/[FILE] /' >> "$temp_timeline" || true
        fi

        # Network
        if [ -f "${session}/network.log" ] && [ -s "${session}/network.log" ]; then
            grep '^\[' "${session}/network.log" 2>/dev/null | sed 's/^/[NET]  /' >> "$temp_timeline" || true
        fi

        # Suspicious dirs
        if [ -f "${session}/suspicious.log" ] && [ -s "${session}/suspicious.log" ]; then
            sed 's/^/[SUSP] /' "${session}/suspicious.log" 2>/dev/null >> "$temp_timeline" || true
        fi

        # Java processes (first-seen events)
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
# LOG RETENTION
# ==========================================

# cleanup_logs [DAYS] [SILENT]
# - Compress every session older than DAYS into logs.tar.gz, keeping SUMMARY.txt
#   and INCIDENT_REPORT.md uncompressed for quick reading.
# - If the whole log root exceeds LOG_SIZE_CAP_MB, delete already-compressed
#   sessions older than 2*DAYS.
# WHY: prevents the silent multi-GB accumulation that motivated this rewrite.
cleanup_logs() {
    local days="${1:-$CLEANUP_DAYS}" silent="${2:-false}"
    local root="$LOG_ROOT"

    if [ ! -d "$root" ]; then
        [ "$silent" = true ] || log_msg "No log directory to clean: $root"
        return 0
    fi

    # 1) Compress old, not-yet-compressed sessions.
    local d
    while IFS= read -r d; do
        [ -z "$d" ] && continue
        [ -f "${d}/logs.tar.gz" ] && continue   # already compressed
        [ "$silent" = true ] || log_msg "Compressing old session: $(basename "$d")"
        (
            cd "$d" || exit 0
            # Everything EXCEPT the quick-read reports and the archive itself.
            local files=()
            local f
            for f in $(ls -A 2>/dev/null); do
                case "$f" in
                    SUMMARY.txt|INCIDENT_REPORT.md|logs.tar.gz) ;;
                    *) files+=("$f") ;;
                esac
            done
            if [ "${#files[@]}" -gt 0 ]; then
                tar -czf logs.tar.gz --remove-files "${files[@]}" 2>/dev/null || true
            fi
        ) || true
    done < <(find "$root" -maxdepth 1 -type d -name 'session_*' -mtime +"$days" 2>/dev/null)

    # 2) If over the size cap, drop compressed sessions older than 2*DAYS.
    local total_mb
    total_mb="$(du -sm "$root" 2>/dev/null | cut -f1)"
    if [ -n "$total_mb" ] && [ "$total_mb" -gt "$LOG_SIZE_CAP_MB" ]; then
        [ "$silent" = true ] || log_warn "Log dir ${total_mb}MB > ${LOG_SIZE_CAP_MB}MB cap; pruning old compressed sessions."
        while IFS= read -r d; do
            [ -z "$d" ] && continue
            if [ -f "${d}/logs.tar.gz" ]; then
                [ "$silent" = true ] || log_warn "Removing: $(basename "$d")"
                rm -rf "$d"
            fi
        done < <(find "$root" -maxdepth 1 -type d -name 'session_*' -mtime +"$((days * 2))" 2>/dev/null)
    fi
}

# ==========================================
# ANALYSIS
# ==========================================

analyze_session() {
    local session="${1:-}"

    # If no session provided, find latest
    if [ -z "$session" ] || [ ! -d "$session" ]; then
        session=$(find "${LOG_ROOT}" -maxdepth 1 -type d -name "session_*" 2>/dev/null | sort -r | head -n1)
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

    # Prefer the aggregated incident report when present.
    if [ -f "${session}/INCIDENT_REPORT.md" ]; then
        printf "${BLUE}Incident report:${NC} %s/INCIDENT_REPORT.md\n\n" "$session"
    fi

    # Filesystem changes
    printf "${YELLOW}┌── Filesystem Changes ──┐${NC}\n\n"
    if [ -f "${session}/snapshot-before.txt" ] && [ -f "${session}/snapshot-after.txt" ]; then
        local new_files
        new_files=$(comm -13 \
            <(awk '{print $NF}' "${session}/snapshot-before.txt" 2>/dev/null | sort) \
            <(awk '{print $NF}' "${session}/snapshot-after.txt" 2>/dev/null | sort) || true)

        local new_count=$(printf "%s" "$new_files" | grep -c . || true); new_count=${new_count:-0}

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
        local ip_count=$(printf "%s" "$ips" | grep -c . || true); ip_count=${ip_count:-0}

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
    # Stop monitors started in this run, reaping their whole process trees so no
    # inotifywait/ss/ps/mitmdump leaf survives to write into old logs. This runs
    # from the EXIT/INT/TERM trap too (e.g. the user Ctrl+C's mid-session), so it
    # mirrors stop_monitors' TERM→KILL escalation rather than a single TERM pass —
    # a lone TERM can lose a leaf to a reparent race and leave exactly the kind of
    # orphan this whole revision exists to prevent.
    if [ "${#MONITOR_PIDS[@]}" -gt 0 ]; then
        local pid
        for pid in "${MONITOR_PIDS[@]}"; do kill_tree "$pid" TERM; done
        sleep 0.3
        for pid in "${MONITOR_PIDS[@]}"; do kill_tree "$pid" KILL; done
    fi
    # Safety net: kill anything still tagged with THIS session id.
    [ -n "${SESSION_ID:-}" ] && pkill -f "tlauncher-mon-${SESSION_ID}" 2>/dev/null || true

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
    printf "                           • Filesystem events (inotifywait, noise-filtered)\n"
    printf "                           • Network connections (ss, first-seen)\n"
    printf "                           • Process activity (first-seen, not full dumps)\n"
    printf "                           • Suspicious directory detection\n"
    printf "                           • Java subprocess tracking (first-seen)\n"
    printf "  ${BLUE}-a, --analyze${NC}          Auto-analyze results after execution\n"
    printf "  ${BLUE}-A, --analyze-only${NC}     Analyze latest session WITHOUT running\n\n"

    printf "${YELLOW}MAINTENANCE / REPORTING${NC}\n"
    printf "  ${BLUE}-K, --kill-orphans${NC}     Find & kill stray monitor processes from old\n"
    printf "                           sessions, then exit (does NOT launch TLauncher)\n"
    printf "  ${BLUE}-R, --report DIR${NC}       (Re)generate INCIDENT_REPORT.md for a session\n"
    printf "                           directory, then exit\n"
    printf "  ${BLUE}-c, --cleanup-logs [N]${NC} Compress sessions older than N days (default %d),\n" "$CLEANUP_DAYS"
    printf "                           prune compressed ones over the %dMB cap, then exit.\n" "$LOG_SIZE_CAP_MB"
    printf "                           ${CYAN}This also runs automatically (silently) at the${NC}\n"
    printf "                           ${CYAN}start of every -M run so logs never balloon.${NC}\n\n"

    printf "${YELLOW}NETWORK CAPTURE (opt-in, no sudo)${NC}\n"
    printf "  ${BLUE}-P, --proxy [PORT]${NC}     Route sandbox HTTP(S) through mitmproxy on\n"
    printf "                           127.0.0.1:PORT (default %d) and record mitm.flow.\n" "$PROXY_PORT"
    printf "                           Requires 'mitmdump' (pip install mitmproxy\n"
    printf "                           --break-system-packages). If missing, the flag is\n"
    printf "                           skipped and the run continues normally.\n"
    printf "                           ${CYAN}HTTPS note:${NC} the JVM must trust the mitmproxy CA.\n"
    printf "                           After the first run, trust it inside the sandbox e.g.:\n"
    printf "                             keytool -importcert -noprompt -alias mitmproxy \\\\\n"
    printf "                               -file ~/.mitmproxy/mitmproxy-ca-cert.pem \\\\\n"
    printf "                               -keystore \"\$SANDBOX/.mitm-truststore\" -storepass changeit\n"
    printf "                           then add -Djavax.net.ssl.trustStore=... to the java cmd.\n"
    printf "                           Without trust, HTTPS requests will fail TLS inside.\n\n"

    printf "${YELLOW}SECURITY CHECKS${NC}\n"
    printf "  ${BLUE}-m, --mozilla${NC}          Check for .mozilla directory access\n"
    printf "  ${BLUE}-ml, --mozilla-path${NC}    Custom mozilla path (default: ~/.mozilla)\n\n"

    printf "${YELLOW}COMMON USAGE PATTERNS${NC}\n"
    printf "  ${GREEN}Quick run:${NC}\n"
    printf "    %s\n\n" "$0"

    printf "  ${GREEN}First time / security audit:${NC}\n"
    printf "    %s -v -M -a -m\n" "$0"
    printf "    ${CYAN}→ Full monitoring with immediate analysis${NC}\n\n"

    printf "  ${GREEN}With real HTTP(S) capture:${NC}\n"
    printf "    %s -M -a -P\n" "$0"
    printf "    ${CYAN}→ Adds a mitmproxy summary to the incident report${NC}\n\n"

    printf "  ${GREEN}Reap leftover monitors / tidy logs:${NC}\n"
    printf "    %s -K        %s -c 7\n\n" "$0" "$0"

    printf "  ${GREEN}Review previous session:${NC}\n"
    printf "    %s -A\n" "$0"
    printf "    ${CYAN}→ Analyze logs without running TLauncher${NC}\n\n"

    printf "${YELLOW}WHAT'S NEW IN v2.4${NC}\n"
    printf "  ${GREEN}✓${NC} Fixed monitor cleanup (no more orphaned inotifywait/ss/ps)\n"
    printf "  ${GREEN}✓${NC} -K to reap strays from previous sessions\n"
    printf "  ${GREEN}✓${NC} Noise-filtered filesystem signal.log (small, readable)\n"
    printf "  ${GREEN}✓${NC} First-seen process logging (orders of magnitude less volume)\n"
    printf "  ${GREEN}✓${NC} Aggregated INCIDENT_REPORT.md per session\n"
    printf "  ${GREEN}✓${NC} Automatic log retention (-c) so the dir never balloons\n"
    printf "  ${GREEN}✓${NC} Opt-in mitmproxy capture (-P), no sudo\n\n"

    printf "${YELLOW}OUTPUT LOCATION${NC}\n"
    printf "  %s/session_YYYYMMDD_HHMMSS/\n\n" "$LOG_ROOT"

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
            -K|--kill-orphans) KILL_ORPHANS=true; shift ;;
            -R|--report)
                if [ -z "${2:-}" ]; then
                    die "--report requires a session directory argument"
                fi
                REPORT_SESSION="$2"
                shift 2
                ;;
            -c|--cleanup-logs)
                CLEANUP_LOGS_FLAG=true
                # Optional numeric [DAYS] argument.
                if [ -n "${2:-}" ] && [[ "${2:-}" =~ ^[0-9]+$ ]]; then
                    CLEANUP_DAYS="$2"
                    shift 2
                else
                    shift
                fi
                ;;
            -P|--proxy)
                PROXY_ENABLED=true
                # Optional numeric [PORT] argument.
                if [ -n "${2:-}" ] && [[ "${2:-}" =~ ^[0-9]+$ ]]; then
                    PROXY_PORT="$2"
                    shift 2
                else
                    shift
                fi
                ;;
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
                printf "Run '${BLUE}%s --help${NC}' for usage\n" "$1" >&2
                exit 1
                ;;
        esac
    done

    # ---- Standalone modes that never launch TLauncher ----
    if [ "$KILL_ORPHANS" = true ]; then
        kill_orphans
        exit 0
    fi

    if [ -n "$REPORT_SESSION" ]; then
        generate_incident_report "$REPORT_SESSION"
        printf "${GREEN}✓${NC} Report: %s/INCIDENT_REPORT.md\n" "$REPORT_SESSION" >&2
        exit 0
    fi

    if [ "$CLEANUP_LOGS_FLAG" = true ]; then
        cleanup_logs "$CLEANUP_DAYS" false
        exit 0
    fi

    # Proxy preflight: decide mitmdump availability NOW, before any session
    # directory, firejail --env, or java -Dproxy settings are derived from
    # PROXY_ENABLED. Otherwise a missing mitmdump would still inject proxy
    # settings that point at a dead port and break TLauncher's networking.
    if [ "$PROXY_ENABLED" = true ] && ! command -v mitmdump >/dev/null 2>&1; then
        log_warn "mitmdump not found — -P/--proxy disabled for this run."
        log_warn "Install manually (no sudo for the script): pip install mitmproxy --break-system-packages"
        PROXY_ENABLED=false
    fi

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

    # Warn (do not fail) if monitors from a previous session are still alive.
    warn_orphans

    # Normal execution
    check_requirements

    # Auto-retention: keep the log dir from silently growing into the GBs.
    if [ "$MONITOR_ENABLED" = true ]; then
        cleanup_logs "$CLEANUP_DAYS" true
    fi

    local tlauncher
    tlauncher=$(find_tlauncher)

    # Setup sandbox first (always needed)
    setup_sandbox "$tlauncher"

    # Show configuration summary if verbose or session logging is active
    if [ "$VERBOSE" = true ] || session_logging_active; then
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

        printf "${BLUE}Proxy:${NC}           "
        if [ "$PROXY_ENABLED" = true ]; then
            printf "${GREEN}mitmproxy 127.0.0.1:%s${NC}" "$PROXY_PORT"
        else
            printf "${YELLOW}Off${NC}"
        fi
        printf "\n"

        printf "${BLUE}TLauncher:${NC}       %s\n" "$tlauncher"
        printf "${BLUE}Sandbox:${NC}         %s\n" "$SANDBOX_DIR"

        if session_logging_active; then
            SESSION_ID=$(date +%Y%m%d_%H%M%S)
            SESSION_DIR="${LOG_ROOT}/session_${SESSION_ID}"
            mkdir -p "$SESSION_DIR"
            printf "${BLUE}Logs:${NC}            %s\n" "$SESSION_DIR"
        fi

        printf "\n${CYAN}────────────────────────────────────────────────────────────────────────────────${NC}\n"
        printf "${YELLOW}Starting in 2 seconds... (Ctrl+C to cancel)${NC}\n"
        sleep 2
        printf "\n"
    fi

    if session_logging_active; then
        # Ensure session directory exists
        if [ -z "$SESSION_DIR" ]; then
            SESSION_ID=$(date +%Y%m%d_%H%M%S)
            SESSION_DIR="${LOG_ROOT}/session_${SESSION_ID}"
        fi
        mkdir -p "$SESSION_DIR"

        # Pre-execution snapshot (filesystem diffing) is only meaningful with -M.
        if [ "$MONITOR_ENABLED" = true ]; then
            {
                printf "# Pre-execution snapshot\n"
                printf "# Timestamp: %s\n" "$(date '+%Y-%m-%d %H:%M:%S')"
                find "$SANDBOX_DIR" -printf "%T@ %M %u %g %s %p\n" 2>/dev/null | sort
            } > "${SESSION_DIR}/snapshot-before.txt"
        fi

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
            printf "  Proxy: %s (port %s)\n" "$PROXY_ENABLED" "$PROXY_PORT"
            printf "  Auto-Analyze: %s\n" "$AUTO_ANALYZE"
        } > "${SESSION_DIR}/system-info.txt"
    fi

    run_sandboxed
}

main "$@"
