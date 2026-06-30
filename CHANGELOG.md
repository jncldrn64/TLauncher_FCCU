# Changelog

Every notable change to the launcher (`run.sh` & its helpers). The format follows
[Keep a Changelog](https://keepachangelog.com/). One file that grows by section,
never one file per round.

## v2.5: Round 2

### Added
- Sandbox-only mode for a bare `./run.sh`. It prints one start line
  (`...no monitoring, use -M to enable...`) & one end line carrying TLauncher's
  exit code to stderr, & it writes nothing under `tlauncher-logs/`. Before this it
  launched fine but printed no end line, so it looked dead. That was a feedback
  gap, not a logic bug.
- Network payload summary for `-P` captures, through the new
  `scripts/mitm_report.py`. It prints one line per request
  (host, method, path, status, request bytes, response bytes) & a
  "Flagged requests" block for any off-allowlist host or any POST/PUT that carried
  a body, with the body truncated at 2048 bytes. That block answers the only
  question that matters: did it send anything.
- Domain regression check. A new baseline file,
  `tlauncher-sandbox-baseline-domains.txt`, plus `-B/--save-baseline SESSION_DIR`
  to build it from a session you trust. The report's "Regression check" section
  marks a first-seen domain with `NEW DOMAIN` & a known-risky one with
  `NEW RISKY DOMAIN`, flagging `advancedrepository` even when it's already in the
  baseline. Text comparison only, no extra network.
- `DESIGN.md`, the first written copy of the project's conventions.

### Changed
- Audited `usage()` line by line against the real parser: it now documents the
  sandbox-only mode, corrects the `-M`/`-a`/`-m` descriptions, names the
  standalone flags, & lists the baseline files.
- The payload section says "capture disabled" when there's no `mitm.flow`, so
  "nothing captured" & "nothing suspicious" stop hiding under the same silence.

## v2.4: Round 1

### Fixed
- Orphaned monitors, the critical bug. The monitor block ran inside a
  `( ... ) 200>"$LOCKFILE"` subshell, so the PIDs it appended to the global
  `MONITOR_PIDS` never reached the parent shell, & the cleanup loop ran over an
  empty array. Every `inotifywait`/`ss`/`ps` got orphaned & kept writing into old
  logs; one stray `inotifywait` grew a single `files.log` to 51 MB. The lock now
  lives on an `exec`'d descriptor in the current shell, & cleanup reaps whole
  process trees with `kill_tree`, TERM then KILL, so no reparented leaf survives.
- Three `set -e` traps. `log_verbose` now ends with `return 0`, because a bare
  call returning non-zero aborted every non-verbose run. The `grep -c ... || echo 0`
  idiom that printed `0\n0` & crashed `printf %d` got fixed. `USER` is guarded when
  unset.

### Added
- `-K/--kill-orphans` to reap strays from earlier sessions. It excludes the
  script's own ancestor chain so it can't kill the shell that launched it.
- Filesystem noise filtering: a lossless `files.log` plus a small `signal.log`
  driven by `NOISE_PATTERNS`. One real session logged 5,346 events into
  `signal.log` against 178,756 raw MODIFY events seen in about 30 minutes.
- First-seen process & network logging instead of a full `ps`/`ss` dump every 2
  seconds, which had produced a 42 MB `java-processes.log` per session.
- `INCIDENT_REPORT.md`, one aggregated report per session, 5.7 KB on a real run.
- Log retention through `-c/--cleanup-logs [DAYS]`, default 7 days, with a 500 MB
  cap. It also runs silently at the start of every `-M` run, after the directory
  reached 2 GB on its own.
- Opt-in mitmproxy capture through `-P/--proxy [PORT]`, default port 8080, no
  sudo. It sets the JVM proxy properties, because the JVM ignores `HTTP_PROXY`
  environment variables by default, & it turns itself off cleanly when `mitmdump`
  is absent.

## Round 3: documentation only

### Fixed
- Added `tl.vg` to `MITM_ALLOWLIST`. It's a legitimate TLauncher domain seen in
  the same session as `repo.tlauncher.org`. Without it a `-P` capture would flag
  benign `tl.vg` traffic as off-allowlist. Data correction, no logic change.

### Added
- This `CHANGELOG.md`.
- `AGENTS.md`, a short cold-start entry point with an honest "Known gaps" section.
  It records that `-P` never ran end to end against a real `mitmdump`, & that the
  `tlauncher.ru` family isn't yet a hard risk pattern.
- `DESIGN.md` section 6: verbosity depends on who invokes a tool. A human-invoked
  tool never goes mute (rule 5); a hotkey, cron, or window-manager hook may fail
  in total silence.
