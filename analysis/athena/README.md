# Athena queries

Run `create_table.sql` once, then the rest in any order.

Every query has a `dt BETWEEN` clause hardcoded to a March 2026 window.
That is not decoration - `dt` is the partition key, and a query without it
scans every partition in the projected range and bills you for all of it.
Change the dates to your own window; do not delete the clause.

`make athena-ddl` renders `create_table.sql` with your real bucket name from
the Terraform outputs.

| File | Question it answers |
| --- | --- |
| `create_table.sql` | Schema, partition projection, and the `timestamp` -> `ts` rename |
| `top_source_ips.sql` | Who generated the traffic, and did they get in |
| `credential_frequency.sql` | What credentials are being sprayed |
| `session_duration.sql` | Scripted or human |
| `post_auth_commands.sql` | What they did once inside |
| `payload_urls.sql` | Where the second stage would have come from (nothing was fetched) |

Each file leads with a primary query and carries two or three commented-out
follow-ups. The follow-ups are where most of the actual analysis lives - the
primary query is usually just the shape of the data.
