# findings/

Output from the 2026-03-09 → 2026-03-16 run. Every number cites the query or
script that produces it; no `[FILL]` marker remains.

| File | What it is |
| --- | --- |
| `REPORT.md` | The written findings report, §1–§12. |
| `attack_ttps.md` | ATT&CK mapping. 16 of 19 techniques observed, 3 recorded as `not observed` — that is a result, not a gap. |
| `iocs.csv` | 16,771 indicators: 612 IPs, 14,206 credential pairs, 1,893 usernames, 37 URLs, 23 hassh. |
| `summary.json` | Run-level counts and parse diagnostics. The report cites it by key path. |

`make parse` rewrites `iocs.csv` and `summary.json` from `findings/raw/`. Their
totals reconcile with the report: indicator counts sum to
`totals.events` (ip), `totals.login_attempts` (credential, username),
`payload_downloads.attempts_logged` (url) and `totals.sessions` (hassh).

Re-running `make parse` against a different capture will overwrite both files
and invalidate every figure in `REPORT.md`. Regenerate the report's numbers
alongside them or the two will disagree silently.

`findings/raw/` is where `make fetch` puts the logs synced from S3. It is
gitignored: it holds attacker source addresses and credential guesses, and a
public repository is not the place for a week of unreviewed raw telemetry.
