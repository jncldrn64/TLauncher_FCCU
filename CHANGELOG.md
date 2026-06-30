# Changelog

All notable changes to the TLauncher Sandbox launcher (`run.sh` and helpers).
Format loosely follows [Keep a Changelog](https://keepachangelog.com/). This is a
single growing file — never one file per round.

## v2.5 — Round 2

### Added
- **Sandbox-only mode (no arguments)** is now explicit: a bare `./run.sh` prints a
  start line (`...no monitoring — use -M to enable...`) and a symmetric end line
  with TLauncher's exit code on stderr, while still creating nothing under
  `tlauncher-logs/`. It previously launched correctly but gave no end feedback, so
  it looked dead — a UX gap, not a logic bug.
- **Network payload summary** for `-P` captures, via the new
  `scripts/mitm_report.py`: one compact line per request
  (host/method/path/status/req+resp bytes) plus a **Flagged requests** subsection
  (non-allowlist hosts, or POST/PUT with a body) with truncated bodies — the part
  that answers "did it actually send anything?".
- **Domain regression check**: new baseline
  `tlauncher-sandbox-baseline-domains.txt` and `-B/--save-baseline SESSION_DIR` to
  derive it (plus the IP baseline) from a session you trust. The incident report's
  **Regression check** section flags first-seen domains (`⚠ NEW DOMAIN`) and
  hard-flags known risk patterns (`🚨 NEW RISKY DOMAIN`, e.g. `advancedrepository`)
  even if already baselined. Pure text, no extra network.
- **`DESIGN.md`** documenting the project's conventions.

### Changed
- `usage()` audited line-by-line against the real parser (documents sandbox-only
  mode, corrects `-M`/`-a`/`-m`, notes the standalone flags, lists baseline files).
- The payload section distinguishes "capture disabled" from "nothing suspicious"
  instead of conflating them under the same silence.

## v2.4 — Round 1

### Fixed
- **Orphaned monitors (critical).** The monitor block used to run inside a
  `( ... ) 200>"$LOCKFILE"` subshell, so the PIDs the monitors appended to the
  global `MONITOR_PIDS` never reached the parent shell and the cleanup loop always
  ran over an empty array. Every `inotifywait`/`ss`/`ps` was orphaned and kept
  writing into old logs (one stray `inotifywait` grew a `files.log` to 51 MB). Now
  the lock is held via an `exec`'d fd in the current shell, and cleanup reaps whole
  process trees (`kill_tree`, TERM→KILL) so no reparented leaf survives.
- Latent `set -e` traps: `log_verbose` now `return 0`s (a bare call returning
  non-zero aborted non-verbose runs); the `grep -c ... || echo 0` idiom that
  emitted `0\n0` and crashed `printf %d` was corrected; `USER` is guarded when
  unset.

### Added
- `-K/--kill-orphans` to reap strays from previous sessions (excludes the script's
  own ancestor chain so it can't kill its launching shell).
- Filesystem **noise filtering**: lossless `files.log` plus a small, readable
  `signal.log` driven by `NOISE_PATTERNS`.
- **First-seen** process/network logging instead of full periodic dumps — orders of
  magnitude less volume while still surfacing anything new.
- Aggregated, KB-sized **`INCIDENT_REPORT.md`** per session.
- **Log retention** (`-c/--cleanup-logs [DAYS]`), also run silently at the start of
  every `-M` run so the directory never balloons.
- Opt-in **mitmproxy capture** (`-P/--proxy [PORT]`), no sudo; injects the JVM
  proxy properties (the JVM ignores `HTTP(S)_PROXY` env vars by default) and
  disables itself cleanly if `mitmdump` is absent.

## Round 3 — documentation only

### Fixed
- Added `tl.vg` to `MITM_ALLOWLIST` — a legitimate TLauncher domain seen alongside
  `repo.tlauncher.org` in a real session. Without it, `-P` captures would flag
  benign `tl.vg` traffic as off-allowlist. (Data correction, not a logic change.)

### Added
- This `CHANGELOG.md`.
- `AGENTS.md` onboarding entry point for anyone (human or agent) resuming the
  project cold.
- `DESIGN.md` §6: verbosity is a function of who invokes a tool, not an absolute —
  human-invoked tools are never mute, auto-fired ones (hotkey/cron/hook) may and
  should fail in total silence.
