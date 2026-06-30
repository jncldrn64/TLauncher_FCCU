# TLauncher Sandbox — Design Conventions

This file is the project's style guide. `run.sh` is meant to read like a
**standard Unix program**; any new feature (added by a human or by an agent)
must respect the conventions below so the script stays coherent. When in doubt,
match the existing code rather than introducing a new idiom.

## 1. XDG Base Directory, always

No hardcoded `~/.something`. Everything resolves through the XDG variables with a
sane fallback:

```sh
XDG_DATA_HOME="${XDG_DATA_HOME:-${REAL_HOME}/.local/share}"
XDG_STATE_HOME="${XDG_STATE_HOME:-${REAL_HOME}/.local/state}"
XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/${REAL_UID}}"   # → /tmp if absent
```

Derived paths:

- Sandbox HOME: `$XDG_DATA_HOME/tlauncher-sandbox`
- Session logs: `$XDG_STATE_HOME/tlauncher-logs/session_<ts>/`
- Lockfile: `$XDG_RUNTIME_DIR/tlauncher-<user>.lock`
- Baselines: `$XDG_DATA_HOME/tlauncher-sandbox-baseline-{ips,domains}.txt`

Any new file the script reads or writes follows the same pattern. The baselines
added in Round 2 already do — keep it that way.

## 2. Zero `sudo`, ever

The script must never call `sudo`, prompt for a password, or need capabilities
beyond what firejail uses internally. Optional dependencies (`mitmdump`, …) are
probed with `command -v` and **degraded with a warning + a manual install hint**,
never auto-installed. Lines that print `sudo apt install …` are *hints for the
user to run by hand* — that is allowed; invoking it from the script is not.

## 3. Avoid race conditions explicitly

The established pattern for a protected resource is `flock` over an fd opened with
`exec N>FILE` **in the same shell scope** where the resource is used:

```sh
exec 200>"$LOCKFILE"
flock -n 200 || die "already running"
```

Lesson from the Round 1 bug: never wrap stateful logic in `( … )` if that state
(e.g. `MONITOR_PIDS`) must survive outside the subshell — a subshell's variable
writes do not propagate to the parent, which is exactly how background monitors
were orphaned.

Background jobs are tracked by their **real PID via `$!`, captured immediately**
after launch (see `spawn_monitor`). `pgrep`/tag-based matching
(`find_orphan_pids`, the `tlauncher-mon-<session>` argv tag) is a **secondary
safety net only**, never the primary handle. Cleanup reaps whole process trees
(`kill_tree`, TERM→KILL) so no reparented leaf (inotifywait/ss/mitmdump) survives.

## 4. Standard CLI idioms

- Short flag + long alias for everything: `-v/--verbose`, `-M/--monitor`, …
- `-h/--help` prints usage and exits `0`.
- Unknown option → message to **stderr** suggesting `--help`, exit `1`.
- Flags stay combinable unless genuinely incompatible — and an incompatible or
  no-op combination **warns**, it does not fail silently (see the `-a` without
  `-M` check).
- Standalone modes (`-K`, `-R`, `-B`, `-c`, `-A`) do their job and exit without
  launching TLauncher.
- `usage()` is part of the contract: it must describe the **real** behavior of
  the current parser. Audit it whenever a flag is added or changed.

## 5. Silent by default, verbose opt-in — but never mute

"Silent" must not mean "no sign of life." The balance:

- A minimal **start and end line** is printed in *every* mode (including the
  no-arg sandbox-only mode) via `log_msg`, which always writes to stderr.
- The full configuration summary, 2-second countdown, and per-monitor detail
  appear only with `-v` or when a logging session is active.
- `log_verbose` must `return 0` (a bare call returning non-zero aborts the
  script under `set -e`).

## 6. Verbosity is a function of who invokes you, not an absolute

Rule 5 ("never mute") is **not universal** — it is the correct behavior for *this*
tool because of how it is invoked. The right verbosity depends on who pulls the
trigger:

- **Invoked consciously by a human watching a terminal** (like `run.sh`): never
  mute. A person is waiting to see a result, so an invisible failure is worse than
  a little noise. Always emit at least a start/end line, surface errors on stderr,
  exit with a meaningful code. This is rule 5.
- **Fired automatically with nobody watching** (a keyboard-shortcut helper, a cron
  job, a window-manager hook): the *opposite* is correct on purpose. These should
  fail in total silence — chained `|| exit 0` at each step — because an error
  message there only interrupts; no one will ever read it. Silence is the feature.

So a sibling utility that swallows every error without a peep is **not** violating
rule 5 — it is a different rule for a different context. When adding or judging a
script, first ask "who launches this, and is anyone looking?"; pick the verbosity
from the answer, not from a fixed notion of "correct". (Principle only — do not
copy code from those other tools into this repo.)

## 7. Idempotence & cleanup

Every resource the script creates has an explicit teardown/regeneration path,
and `usage()` tells the user about it:

| Resource            | Created by        | Reset / regenerate                          |
|---------------------|-------------------|---------------------------------------------|
| Lockfile            | `run_sandboxed`   | Removed by `cleanup` (EXIT/INT/TERM trap)   |
| Sandbox dir         | `setup_sandbox`   | Safe to `rm -rf`; recreated next run        |
| Session dirs        | `-M` / `-P` runs  | `-c/--cleanup-logs` compresses/prunes them  |
| Baseline files      | `-B/--save-baseline` | Delete to reset; re-run `-B` to recreate |
| Orphaned monitors   | (shouldn't happen)| `-K/--kill-orphans` reaps strays            |

## 8. Report size discipline

`INCIDENT_REPORT.md` (and any summary fed to a human or an LLM) stays in the **KB**
range, never MB. Full captures (`files.log`, `mitm.flow`) are kept on disk but
only *summarized* in the report — one line per item, truncated bodies, head-capped
lists. Helpers that could be heavy (e.g. `scripts/mitm_report.py`) live as separate
files so they don't bloat `run.sh`, and always degrade to a short Markdown note
rather than crashing the report.
