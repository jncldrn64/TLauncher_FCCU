# AGENTS.md — start here

**Purpose.** This repo is a personal **security-audit sandbox** for running
TLauncher under `firejail` and observing what it touches (filesystem, processes,
network). It is *not* a production launcher and never tries to be — usability is
secondary to visibility and isolation.

## Hard constraints (do not violate)

- **Zero `sudo`**, ever — in any file, any flag, present or future. Optional deps
  (`mitmdump`, …) are probed with `command -v` and degraded with a manual hint.
- **Always XDG** for paths (`XDG_DATA_HOME`/`XDG_STATE_HOME`/`XDG_RUNTIME_DIR`),
  never hardcoded `~/.something`.
- **Never wrap shared state in `( … )` subshells** — that exact bug orphaned the
  background monitors. Hold locks via `exec N>FILE` + `flock` in the same scope;
  track background jobs by `$!`.
- See **`DESIGN.md`** for the full style guide before writing any code.

## Map of the repo

- `run.sh` — the whole launcher (single bash script).
- `scripts/mitm_report.py` — summarizes a `-P` mitmproxy capture into Markdown.
- `DESIGN.md` — conventions/style guide (read before coding).
- `CHANGELOG.md` — what changed and when.

## Known gaps / not verified against real data

Be honest about these — do **not** report them as "working" without a fresh,
real-environment verification.

- **`-P/--proxy` end-to-end was never run for real.** The proxy capture and
  `scripts/mitm_report.py` passed static review and tests against a *mock*
  mitmproxy module — never a full TLauncher session through a real `mitmdump`
  with real request bodies. Treat the payload summary as unproven in production.
- **Agent-side testing used stubs/mocks.** The dev/CI environment has no
  `firejail`/`inotifywait`/`ss`, so end-to-end runs were exercised with fake
  binaries. Real-environment confirmation is the user's; don't claim otherwise.
- **`RISK_DOMAIN_PATTERNS` does not include the `tlauncher.ru` family**
  (`res.tlauncher.ru`, `mps.tlauncher.ru`, `stat.tlauncher.ru`). These appear in
  `BLOCKED_DOMAINS` as historical reference, but whether they deserve a *hard*
  risk flag is the author's call — do not add them without explicit confirmation.
- **Baseline IP list flags the local sandbox IP** (e.g. `10.x`) as "not in
  baseline" until the user populates the baseline from a clean run that includes
  it — by design, but worth knowing before reading a first report.

If you find another open item while reading `DESIGN.md`/`CHANGELOG.md` that isn't
closed with verified evidence, add it here rather than silently fixing or
re-scoping it. New documentation ideas also go here as a note for the author to
decide on — do not add a fourth doc file on your own initiative.
