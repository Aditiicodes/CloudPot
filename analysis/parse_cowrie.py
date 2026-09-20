#!/usr/bin/env python3
"""Extract indicators and a run summary from Cowrie JSON logs.

Standard library only, on purpose. This script runs against raw honeypot
output, which is attacker-controlled text; the fewer third-party parsers in
that path, the smaller the surface. It also means the script runs on a stock
Python 3.8+ with no virtualenv, including on the sensor itself.

Outputs two files:

  iocs.csv      indicator, type, first_seen, last_seen, count
  summary.json  run-level counts, the event breakdown, and parse diagnostics

Nothing is invented. If the input is empty, or a field is absent, the script
says so and writes nothing rather than emitting a zero or a placeholder.

Usage:
    python3 parse_cowrie.py --input findings/raw/ --out-dir findings/
    python3 parse_cowrie.py --input cowrie.json.2026-03-14.gz --types ip,url
"""

from __future__ import annotations

import argparse
import csv
import gzip
import json
import os
import sys
from collections import Counter, defaultdict
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Indicator extraction
#
# Each indicator type names the Cowrie events it is drawn from and how the
# value is built. Keeping this as data rather than as a chain of ifs makes it
# obvious what the script does and does not look at - which matters, because
# an IOC file is something other people act on.
#
# Deliberately NOT extracted by default:
#
#   commands  - a typed command is behaviour, not an indicator. Blocking on
#               "uname -a" is meaningless. Available behind --types for
#               frequency analysis, but it does not belong in a blocklist.
#   passwords - publishing a password list from a honeypot is at best noise
#               and at worst a credential-stuffing dictionary with a nice
#               provenance story attached. The username:password pair is kept
#               as a "credential" indicator because the pairing is what
#               characterises a campaign; the password alone is not emitted.
# ---------------------------------------------------------------------------

LOGIN_EVENTS = ("cowrie.login.failed", "cowrie.login.success")
COMMAND_EVENTS = ("cowrie.command.input", "cowrie.command.failed")
DOWNLOAD_EVENTS = (
    "cowrie.session.file_download",
    "cowrie.session.file_download.failed",
    "cowrie.session.file_upload",
)

DEFAULT_TYPES = ("ip", "credential", "username", "url", "hash", "hassh")
ALL_TYPES = DEFAULT_TYPES + ("command", "client_version")


def extract_indicators(event: Dict[str, Any], types: Tuple[str, ...]) -> Iterator[Tuple[str, str]]:
    """Yield (type, value) pairs for one Cowrie event."""
    eventid = event.get("eventid") or ""

    if "ip" in types:
        src_ip = event.get("src_ip")
        if src_ip:
            yield ("ip", str(src_ip))

    if eventid in LOGIN_EVENTS:
        username = event.get("username")
        password = event.get("password")
        if "username" in types and username is not None:
            yield ("username", str(username))
        # The pair, not the password on its own. See the note above.
        if "credential" in types and username is not None and password is not None:
            yield ("credential", "{}:{}".format(username, password))

    if eventid in DOWNLOAD_EVENTS:
        url = event.get("url")
        if "url" in types and url:
            yield ("url", str(url))
        # shasum is expected to be absent in this deployment: downloads are
        # blocked, so Cowrie never stores a file to hash. It is extracted
        # anyway so that a hash appearing in someone else's dataset is not
        # silently dropped - and so that its presence here is visible rather
        # than assumed away.
        shasum = event.get("shasum")
        if "hash" in types and shasum:
            yield ("hash", str(shasum))

    if "hassh" in types:
        hassh = event.get("hassh")
        if hassh:
            yield ("hassh", str(hassh))

    if "client_version" in types:
        version = event.get("version")
        if version and eventid == "cowrie.client.version":
            yield ("client_version", str(version))

    if "command" in types and eventid in COMMAND_EVENTS:
        command = event.get("input")
        if command:
            yield ("command", str(command))


# ---------------------------------------------------------------------------
# Input handling
# ---------------------------------------------------------------------------


def is_log_name(name: str) -> bool:
    """Decide whether a filename looks like a Cowrie JSON log.

    Matched by name rather than by sniffing content, because the log directory
    on the sensor also holds .shipped upload markers, tty recordings and
    Cowrie's own textual log, none of which are JSON events.
    """
    if name.endswith(".shipped"):
        return False
    if "cowrie" not in name:
        return False
    return ".json" in name or name.endswith(".gz")


def iter_log_files(paths: Iterable[str]) -> Iterator[str]:
    """Expand the --input arguments into a sorted list of candidate files.

    Directories are walked recursively, and within each directory a file is
    read once per logical name. That matters because the same day can easily
    be present twice: the nightly shipper uploads cowrie.json.2026-03-14.gz to
    S3, an operator syncs it down next to a plain copy pulled off the sensor,
    and every count in the output silently doubles. Deduplication is scoped to
    a single directory on purpose - two directories holding a same-named file
    is the multi-sensor case, and those are genuinely different data.
    """
    seen_paths = set()
    for path in paths:
        if os.path.isdir(path):
            for root, _dirs, files in os.walk(path):
                logical_seen: Dict[str, str] = {}
                for name in sorted(files):
                    if not is_log_name(name):
                        continue
                    # cowrie.json.2026-03-14 and cowrie.json.2026-03-14.gz are
                    # the same day. Sorted order puts the plain file first, so
                    # first-wins is deterministic.
                    logical = name[:-3] if name.endswith(".gz") else name
                    if logical in logical_seen:
                        print(
                            "warning: skipping {} - already reading {} from the same "
                            "directory".format(name, logical_seen[logical]),
                            file=sys.stderr,
                        )
                        continue
                    logical_seen[logical] = name
                    full = os.path.join(root, name)
                    if full not in seen_paths:
                        seen_paths.add(full)
                        yield full
        elif os.path.isfile(path):
            if path not in seen_paths:
                seen_paths.add(path)
                yield path
        else:
            print("warning: no such file or directory: {}".format(path), file=sys.stderr)


def open_log(path: str):
    """Open a log file, transparently handling gzip.

    Detection is by magic bytes rather than by extension: the nightly shipper
    on the sensor writes .gz, but an operator who gunzips a file for a quick
    look and forgets to rename it should not get a wall of binary.
    """
    with open(path, "rb") as probe:
        magic = probe.read(2)
    if magic == b"\x1f\x8b":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "rt", encoding="utf-8", errors="replace")


def iter_events(paths: Iterable[str], stats: Counter) -> Iterator[Dict[str, Any]]:
    """Yield one parsed event per well-formed JSON line.

    Malformed input is counted and skipped, never fatal. Two things produce it
    in practice: a log file torn mid-write when an instance is terminated, and
    whatever an attacker decides to put in a field that ends up echoed into a
    message. Neither should stop the run - and the second is a reminder that
    every string in here is hostile input.
    """
    for path in paths:
        stats["files_read"] += 1
        try:
            handle = open_log(path)
        except OSError as exc:
            print("warning: cannot open {}: {}".format(path, exc), file=sys.stderr)
            stats["files_unreadable"] += 1
            continue

        with handle:
            for lineno, line in enumerate(handle, start=1):
                line = line.strip()
                if not line:
                    continue
                stats["lines_read"] += 1
                try:
                    event = json.loads(line)
                except (ValueError, UnicodeDecodeError):
                    stats["lines_malformed"] += 1
                    continue
                if not isinstance(event, dict):
                    # Valid JSON, wrong shape - a bare string or array is not
                    # a Cowrie event.
                    stats["lines_not_object"] += 1
                    continue
                if not event.get("eventid"):
                    stats["lines_no_eventid"] += 1
                    continue
                stats["events_parsed"] += 1
                yield event


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------


class IndicatorTable:
    """First seen, last seen and count, keyed by (type, value)."""

    def __init__(self) -> None:
        self._rows: Dict[Tuple[str, str], Dict[str, Any]] = {}

    def add(self, itype: str, value: str, timestamp: Optional[str]) -> None:
        key = (itype, value)
        row = self._rows.get(key)
        if row is None:
            self._rows[key] = {"first": timestamp, "last": timestamp, "count": 1}
            return
        row["count"] += 1
        # Cowrie writes ISO-8601 in UTC, which sorts correctly as a string.
        # That avoids a datetime parse per line and, more importantly, avoids
        # silently coercing an unparseable attacker-influenced value to now().
        if timestamp:
            if not row["first"] or timestamp < row["first"]:
                row["first"] = timestamp
            if not row["last"] or timestamp > row["last"]:
                row["last"] = timestamp

    def __len__(self) -> int:
        return len(self._rows)

    def type_counts(self) -> Dict[str, int]:
        counts: Counter = Counter()
        for (itype, _value) in self._rows:
            counts[itype] += 1
        return dict(counts)

    def sorted_rows(self, min_count: int) -> List[Tuple[str, str, Dict[str, Any]]]:
        rows = [
            (itype, value, meta)
            for (itype, value), meta in self._rows.items()
            if meta["count"] >= min_count
        ]
        rows.sort(key=lambda r: (r[0], -r[2]["count"], r[1]))
        return rows


def build_summary(
    stats: Counter,
    events_by_id: Counter,
    sessions: Dict[str, Dict[str, Any]],
    table: IndicatorTable,
    src_ips: Counter,
    usernames: Counter,
    credentials: Counter,
    urls: Counter,
    days: Counter,
    args: argparse.Namespace,
) -> Dict[str, Any]:
    """Assemble summary.json.

    Every number here is counted from the input. Where a value cannot be
    derived - an empty window, an absent field - it is null, not zero, so that
    a reader can tell "we measured nothing" apart from "we measured zero".
    """
    timestamps = [meta["first"] for _t, _v, meta in table.sorted_rows(1) if meta["first"]]
    window_start = min(timestamps) if timestamps else None
    window_end = max(
        (meta["last"] for _t, _v, meta in table.sorted_rows(1) if meta["last"]),
        default=None,
    )

    durations = [
        s["duration"] for s in sessions.values() if isinstance(s.get("duration"), (int, float))
    ]
    durations.sort()

    def percentile(values: List[float], pct: float) -> Optional[float]:
        if not values:
            return None
        idx = min(int(round((len(values) - 1) * pct)), len(values) - 1)
        return round(float(values[idx]), 2)

    return {
        "generated_by": "analysis/parse_cowrie.py",
        "inputs": list(args.input),
        "indicator_types": list(args.types),
        "parse": {
            "files_read": stats["files_read"],
            "files_unreadable": stats["files_unreadable"],
            "lines_read": stats["lines_read"],
            "events_parsed": stats["events_parsed"],
            "lines_malformed": stats["lines_malformed"],
            "lines_not_object": stats["lines_not_object"],
            "lines_without_eventid": stats["lines_no_eventid"],
        },
        "window": {
            "first_event": window_start,
            "last_event": window_end,
            "days_with_events": len(days),
            "events_per_day": dict(sorted(days.items())),
        },
        "totals": {
            "events": stats["events_parsed"],
            "sessions": len(sessions),
            "unique_source_ips": len(src_ips),
            "unique_usernames": len(usernames),
            "unique_credential_pairs": len(credentials),
            "unique_attempted_payload_urls": len(urls),
            "login_attempts": events_by_id.get("cowrie.login.failed", 0)
            + events_by_id.get("cowrie.login.success", 0),
            "login_successes": events_by_id.get("cowrie.login.success", 0),
            "commands_entered": events_by_id.get("cowrie.command.input", 0)
            + events_by_id.get("cowrie.command.failed", 0),
        },
        "session_duration_seconds": {
            "measured_sessions": len(durations),
            "p50": percentile(durations, 0.50),
            "p90": percentile(durations, 0.90),
            "max": round(float(durations[-1]), 2) if durations else None,
        },
        "payload_downloads": {
            # Restated in the output itself so that anyone reading summary.json
            # in isolation cannot mistake a URL list for a malware collection.
            "policy": "blocked - egress restricted and Cowrie download limit set to 1 byte",
            "attempts_logged": sum(
                events_by_id.get(e, 0) for e in DOWNLOAD_EVENTS
            ),
            "unique_urls": len(urls),
            "artifacts_retrieved": 0,
            "hashes_observed": table.type_counts().get("hash", 0),
        },
        "events_by_id": dict(events_by_id.most_common()),
        "indicators_by_type": table.type_counts(),
        "top_source_ips": [
            {"src_ip": ip, "events": n} for ip, n in src_ips.most_common(args.top)
        ],
        "top_credentials": [
            {"credential": c, "attempts": n} for c, n in credentials.most_common(args.top)
        ],
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract indicators and a run summary from Cowrie JSON logs.",
        epilog="Nothing is fabricated: absent data produces null, not a placeholder.",
    )
    parser.add_argument(
        "--input",
        nargs="+",
        required=True,
        metavar="PATH",
        help="Cowrie JSON files or directories to read. .gz is handled transparently.",
    )
    parser.add_argument(
        "--out-dir",
        default="findings",
        metavar="DIR",
        help="Where to write iocs.csv and summary.json (default: findings).",
    )
    parser.add_argument(
        "--types",
        default=",".join(DEFAULT_TYPES),
        help="Comma-separated indicator types. Available: {} (default: {}).".format(
            ",".join(ALL_TYPES), ",".join(DEFAULT_TYPES)
        ),
    )
    parser.add_argument(
        "--min-count",
        type=int,
        default=1,
        metavar="N",
        help="Omit indicators seen fewer than N times (default: 1, keep everything).",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=20,
        metavar="N",
        help="How many entries to include in the summary's top-N lists (default: 20).",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress progress output on stderr.",
    )

    args = parser.parse_args(argv)

    requested = tuple(t.strip() for t in args.types.split(",") if t.strip())
    unknown = [t for t in requested if t not in ALL_TYPES]
    if unknown:
        parser.error(
            "unknown indicator type(s): {}. Available: {}".format(
                ", ".join(unknown), ", ".join(ALL_TYPES)
            )
        )
    args.types = requested
    return args


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    def note(message: str) -> None:
        if not args.quiet:
            print(message, file=sys.stderr)

    files = list(iter_log_files(args.input))
    if not files:
        # A clean exit, not an error. "No log files here" is a normal state
        # before the first deployment, and it must not look like a crash in a
        # Makefile or a CI run.
        print(
            "No Cowrie log files found under: {}\n"
            "Nothing to parse, so nothing was written. Fetch logs first:\n"
            "  aws s3 sync s3://<telemetry-bucket>/cowrie/ findings/raw/".format(
                ", ".join(args.input)
            )
        )
        return 0

    note("reading {} file(s)".format(len(files)))

    stats: Counter = Counter()
    events_by_id: Counter = Counter()
    days: Counter = Counter()
    src_ips: Counter = Counter()
    usernames: Counter = Counter()
    credentials: Counter = Counter()
    urls: Counter = Counter()
    sessions: Dict[str, Dict[str, Any]] = defaultdict(dict)
    table = IndicatorTable()

    for event in iter_events(files, stats):
        eventid = str(event.get("eventid"))
        timestamp = event.get("timestamp")
        timestamp = str(timestamp) if timestamp else None

        events_by_id[eventid] += 1
        if timestamp and len(timestamp) >= 10:
            days[timestamp[:10]] += 1

        session = event.get("session")
        if session:
            record = sessions[str(session)]
            if event.get("src_ip"):
                record["src_ip"] = event["src_ip"]
            if eventid == "cowrie.session.closed" and isinstance(
                event.get("duration"), (int, float)
            ):
                record["duration"] = event["duration"]

        for itype, value in extract_indicators(event, args.types):
            table.add(itype, value, timestamp)
            if itype == "ip":
                src_ips[value] += 1
            elif itype == "username":
                usernames[value] += 1
            elif itype == "credential":
                credentials[value] += 1
            elif itype == "url":
                urls[value] += 1

    if stats["events_parsed"] == 0:
        print(
            "Read {} line(s) across {} file(s) but found no valid Cowrie events "
            "({} malformed).\nNothing was written - check that these are "
            "cowrie.json files and not tty recordings.".format(
                stats["lines_read"], stats["files_read"], stats["lines_malformed"]
            )
        )
        return 0

    os.makedirs(args.out_dir, exist_ok=True)
    iocs_path = os.path.join(args.out_dir, "iocs.csv")
    summary_path = os.path.join(args.out_dir, "summary.json")

    rows = table.sorted_rows(args.min_count)
    with open(iocs_path, "w", newline="", encoding="utf-8") as fh:
        # QUOTE_ALL because indicator values are attacker-controlled and
        # routinely contain commas, quotes and semicolons. A command line or a
        # password with a comma in it must not become two columns in someone
        # else's spreadsheet.
        writer = csv.writer(fh, quoting=csv.QUOTE_ALL)
        writer.writerow(["indicator", "type", "first_seen", "last_seen", "count"])
        for itype, value, meta in rows:
            writer.writerow(
                [value, itype, meta["first"] or "", meta["last"] or "", meta["count"]]
            )

    summary = build_summary(
        stats, events_by_id, sessions, table, src_ips, usernames, credentials, urls, days, args
    )
    with open(summary_path, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2, sort_keys=False)
        fh.write("\n")

    note(
        "parsed {} events from {} lines ({} malformed)".format(
            stats["events_parsed"], stats["lines_read"], stats["lines_malformed"]
        )
    )
    print("wrote {} ({} indicators)".format(iocs_path, len(rows)))
    print("wrote {}".format(summary_path))
    if stats["lines_malformed"]:
        print(
            "note: {} malformed line(s) were skipped; see parse.lines_malformed "
            "in summary.json".format(stats["lines_malformed"])
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
