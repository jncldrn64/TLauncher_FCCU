#!/usr/bin/env python3
"""Summarize a mitmproxy capture (mitm.flow) into compact Markdown.

run.sh's generate_incident_report() calls this (Round 2, Task 2). It answers one
question without making the user open mitmproxy by hand: did TLauncher send
anything to a host outside the expected set, and what was it.

Contract, kept stable so run.sh can rely on it:
  argv[1]            path to a mitmproxy flow file (written by `mitmdump -w`)
  env MITM_ALLOW     comma-separated allowlist of benign domains (suffix match)
  env MITM_TRUNCATE  max bytes of a flagged request body to print (default 2048)

Output is Markdown on stdout & stays in the KB range: one line per request, then
a "Flagged requests" block with bodies for anything off the allowlist or any
POST/PUT that carried a body. It never dumps the whole flow. It exits 0 even when
it can't parse, printing a Markdown note instead, so the report still renders. No
network, no sudo, one file read.
"""
import os
import sys


def _esc(cell: str) -> str:
    # Keep table cells single-line and pipe-safe.
    return str(cell).replace("|", "%7C").replace("\n", " ").replace("\r", " ")


def main() -> int:
    if len(sys.argv) < 2:
        print("_mitm_report.py: no flow file given._")
        return 0
    flow_path = sys.argv[1]

    try:
        from mitmproxy import io, http
    except Exception:
        print("_mitmproxy python module not available; raw flow saved at `mitm.flow`._")
        return 0

    allow = tuple(d for d in os.environ.get("MITM_ALLOW", "").split(",") if d)
    try:
        truncate = int(os.environ.get("MITM_TRUNCATE", "2048"))
    except ValueError:
        truncate = 2048

    def allowed(host: str) -> bool:
        return any(host == d or host.endswith("." + d) for d in allow)

    rows = []
    flagged = []
    try:
        with open(flow_path, "rb") as fh:
            for flow in io.FlowReader(fh).stream():
                if not isinstance(flow, http.HTTPFlow):
                    continue
                req = flow.request
                res = flow.response
                host = req.pretty_host
                status = res.status_code if res else "-"
                req_size = len(req.raw_content) if req.raw_content else 0
                res_size = len(res.raw_content) if (res and res.raw_content) else 0
                rows.append((host, req.method, req.path, status, req_size, res_size))

                # The whole point of the report: surface anything off-allowlist,
                # or any POST/PUT that actually carried a body.
                is_flagged = (not allowed(host)) or (
                    req.method in ("POST", "PUT") and req.raw_content
                )
                if is_flagged:
                    try:
                        body = req.get_text() or ""
                    except Exception:
                        body = ""
                    flagged.append((req.method, host, req.path, allowed(host), body))
    except Exception as exc:  # noqa: BLE001; degrade to a note, never crash the report
        print("_Could not read mitm.flow: %s_" % _esc(str(exc)))
        return 0

    if not rows:
        print("_Capture file present but contained no HTTP(S) flows._")
        return 0

    print("| Host | Method | Path | Status | Req bytes | Resp bytes |")
    print("|------|--------|------|--------|-----------|------------|")
    for host, method, path, status, req_size, res_size in rows[:120]:
        short = (path[:58] + "…") if len(path) > 58 else path
        print(
            "| %s | %s | %s | %s | %s | %s |"
            % (_esc(host), _esc(method), _esc(short), status, req_size, res_size)
        )
    if len(rows) > 120:
        print("\n_%d more requests in mitm.flow._" % (len(rows) - 120))

    # The section that must be impossible to miss: "did it send anything?"
    print("\n### Flagged requests (non-allowlist or non-empty POST/PUT)\n")
    if not flagged:
        print("_None. Every request went to an allowlisted host with no POST/PUT body._")
        return 0
    for method, host, path, host_ok, body in flagged[:25]:
        reason = "POST/PUT body" if host_ok else "off-allowlist host"
        print("- **%s %s%s**  _(%s)_" % (_esc(method), _esc(host), _esc(path), reason))
        body = (body or "").strip()
        if body:
            shown = body[:truncate]
            print("\n```\n%s\n```" % shown)
            if len(body) > truncate:
                print("_Body truncated at %d bytes; full body in mitm.flow._" % truncate)
        print("")
    if len(flagged) > 25:
        print("_%d more flagged requests in mitm.flow._" % (len(flagged) - 25))
    return 0


if __name__ == "__main__":
    sys.exit(main())
