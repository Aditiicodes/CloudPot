# CloudPot — SSH Honeypot Findings

**Status: TEMPLATE.** Every `[FILL]` below is a placeholder for a number or a
statement taken from real output. Nothing here is pre-filled, and nothing here
should be filled from memory or estimated — each section names the query or
script that produces its value.

If a figure cannot be produced from the data, write "not measured" and say why.
An honest gap is a finding; an invented number is a career problem.

---

## 1. Summary

[FILL — three or four sentences. What was deployed, for how long, what the
headline observation was, and what a reader should take away. Write this last.]

---

## 2. Methodology

**Sensor.** Cowrie in shell-emulation mode (not proxy mode) on a single
Ubuntu 22.04 LTS `t3.micro` in a dedicated AWS VPC, `us-east-1`. Cowrie binds
2222 as an unprivileged user; a netfilter PREROUTING REDIRECT presents it on
port 22. The real sshd was relocated to port 62222 and restricted to a single
operator CIDR.

**Presentation.** The sensor advertised the hostname `svr-prod-01` and an
OpenSSH 8.9p1 / Ubuntu banner matching a stock 22.04 host. Authentication
accepted a fixed list of weak credentials (`cowrie/userdb.example`) and
rejected everything else, so the success/failure ratio remains meaningful.

**Containment.** Outbound traffic was restricted to TCP 443 and DNS to the VPC
resolver. Payload retrieval was blocked (see §8). VPC Flow Logs recorded all
network activity independently of the instance.

**Telemetry path.** Cowrie JSON → CloudWatch agent → CloudWatch Logs (14-day
retention) → S3 (`dt=`-partitioned) → Athena. A nightly on-host uploader wrote
the same rotated files to S3 as a second, independent path.

**Analysis.** Athena queries in `analysis/athena/`, indicator extraction via
`analysis/parse_cowrie.py`, figures via `analysis/plots.py`.

**Deployment window.** March 2026, 7 days.
Precise window: `[FILL — first and last event timestamp, UTC, from
summary.json → window.first_event / window.last_event]`

**Collection completeness.** `[FILL — did the no-log-ingest alarm fire at any
point? If the sensor was down for part of the window, say so here and state
the affected hours. If it never fired, say that: it is the evidence that a
quiet period was genuinely quiet.]`

---

## 3. Volume

| Metric | Value | Source |
| --- | --- | --- |
| Total events | `[FILL]` | summary.json → totals.events |
| Sessions | `[FILL]` | summary.json → totals.sessions |
| Login attempts | `[FILL]` | summary.json → totals.login_attempts |
| Successful logins | `[FILL]` | summary.json → totals.login_successes |
| Commands entered | `[FILL]` | summary.json → totals.commands_entered |
| Unique source IPs | `[FILL]` | summary.json → totals.unique_source_ips |
| Unique credential pairs | `[FILL]` | summary.json → totals.unique_credential_pairs |
| Days with events | `[FILL]` | summary.json → window.days_with_events |

**Time to first contact:** `[FILL — interval between the instance receiving its
public IP and the first inbound connection. This single number is usually the
most quoted line in the whole report.]`

![Attempts per day](../analysis/figures/attempts_per_day.png)

`[FILL — one paragraph. Was volume flat or bursty? Did any single day dominate,
and if so was it one source or many? Resist reading a trend into seven points.]`

![Hourly distribution](../analysis/figures/hourly_distribution.png)

`[FILL — one paragraph. Note explicitly whether the distribution is flat. A
flat 24-hour profile is itself the finding: it means automation, not people.]`

---

## 4. Source analysis

Query: `analysis/athena/top_source_ips.sql`

| Source IP | Sessions | Login attempts | Successes | First seen | Last seen |
| --- | --- | --- | --- | --- | --- |
| `[FILL]` | `[FILL]` | `[FILL]` | `[FILL]` | `[FILL]` | `[FILL]` |

**Top ASNs / networks:** `[FILL — resolve the top source addresses to their
announcing ASN using a source you are licensed to use. Record the lookup date:
BGP announcements change.]`

![Source country](../analysis/figures/source_country_bar.png)

**Distinct actors vs distinct addresses.** `[FILL — run the hassh clustering
query at the bottom of top_source_ips.sql. State how many client fingerprints
account for the bulk of traffic. If a handful of hassh values span most of the
source IPs, then the unique-IP count in §3 overstates the actor count by an
order of magnitude, and you should say so here rather than letting the big
number stand unqualified.]`

**Attribution.** None is offered. Source IP indicates the last network hop,
not an actor, an organisation, or a country of origin. Proxies, VPNs,
compromised hosts and cloud egress all misattribute.

---

## 5. Credential analysis

Query: `analysis/athena/credential_frequency.sql`

![Top credentials](../analysis/figures/top_credentials.png)

| Username | Password | Attempts | Distinct sources |
| --- | --- | --- | --- |
| `[FILL]` | `[FILL]` | `[FILL]` | `[FILL]` |

**Username distribution:** `[FILL — what share went to root? What non-obvious
service accounts appeared, and what do they imply about the target list?]`

**Interesting tail:** `[FILL — vendor default credentials, application service
accounts, or passwords that encode a campaign name or year. The tail is where
the analysis is; the head is root/123456 in every published dataset.]`

**Note on the sample.** The credential distribution is shaped by what the
sensor accepted. Cowrie's allow-list means a bot that succeeds stops guessing,
so pairs on the accept list are under-represented in the failure counts
relative to a honeypot that rejects everything.

---

## 6. Post-authentication behaviour

Query: `analysis/athena/post_auth_commands.sql`

| Command | Times run | Sessions | Distinct sources |
| --- | --- | --- | --- |
| `[FILL]` | `[FILL]` | `[FILL]` | `[FILL]` |

**Opening move:** `[FILL — the most common first command per session. This is
the most diagnostic single field in the dataset: it is chosen before the
attacker has learned anything about the host.]`

**Observed playbooks:** `[FILL — describe each distinct command sequence seen,
in order. A playbook is a repeated sequence, not a single command.]`

**Persistence attempts:** `[FILL — authorized_keys writes, cron entries, user
creation, systemd units. Quote the command lines.]`

**Defence evasion:** `[FILL — history clearing, log removal, HISTFILE unset.]`

**Human or script?** `[FILL — support with session duration from
session_duration.sql and with typing artefacts visible in the tty recordings.
Typos and backspaces in a tty log are the strongest human indicator available.]`

---

## 7. Session characteristics

Query: `analysis/athena/session_duration.sql`

| Metric | Value |
| --- | --- |
| Sessions with a recorded duration | `[FILL]` |
| Median duration (s) | `[FILL]` |
| p90 duration (s) | `[FILL]` |
| Longest session (s) | `[FILL]` |
| Sessions censored at the 300 s timeout | `[FILL]` |

`[FILL — interpretation. Note that any session at ~300 s was terminated by
Cowrie's interactive_timeout, so its duration is a lower bound, not a
measurement.]`

---

## 8. Attempted payload retrieval

Query: `analysis/athena/payload_urls.sql`

> **No binaries were downloaded, stored, or analysed.** Payload retrieval was
> blocked at two layers: the security group permitted no outbound connection
> to attacker infrastructure, and Cowrie's download size limit was set to
> 1 byte. What follows is a record of *attempts* — URLs and the commands that
> referenced them. Rationale in [docs/SAFETY.md](../docs/SAFETY.md).

| Attempted URL | Attempts | Distinct sources | First seen |
| --- | --- | --- | --- |
| `[FILL]` | `[FILL]` | `[FILL]` | `[FILL]` |

**Staging hosts:** `[FILL — group by host rather than by full URL. One operator
typically rotates the filename and keeps the host, so a distinct-URL count
overstates the amount of infrastructure in play.]`

**Hashes:** `[FILL — expected to be none. With downloads blocked Cowrie never
stores a file to hash. If a hash IS present in your data, stop and re-read
SAFETY.md before proceeding: something was retrieved.]`

**What this costs the analysis:** without the sample there is no static
analysis, no family attribution and no capability assessment. What remains —
attacker-controlled URLs and hosts, and the exact commands used to reach them —
is still directly actionable for blocklists and detection rules, and is
pivotable against passive DNS and public sandbox reporting without anyone here
handling a sample.

---

## 9. MITRE ATT&CK mapping

See [attack_ttps.md](attack_ttps.md) for the full table with observations.

Summary of techniques with supporting evidence in this run:
`[FILL — list only the technique IDs for which you have concrete, citable
evidence in the data. Leave the rest marked "not observed" in the table. A
mapping that claims every plausible technique is worth nothing.]`

---

## 10. Indicators of compromise

Machine-readable: [iocs.csv](iocs.csv), generated by
`python3 analysis/parse_cowrie.py --input findings/raw/`.

| Type | Count |
| --- | --- |
| Source IPs | `[FILL]` |
| Credential pairs | `[FILL]` |
| Attempted payload URLs | `[FILL]` |
| Client fingerprints (hassh) | `[FILL]` |

**Handling note.** These indicators describe traffic to one host over one week.
They are observations, not a blocklist. Several will be shared infrastructure —
NAT gateways, VPN exits, cloud egress — and blocking them wholesale will
generate false positives against legitimate traffic.

---

## 11. Limitations

State every one of these that applies. They are not caveats to bury; a reviewer
who spots an unstated limitation stops trusting the rest of the document.

- **Single sensor, single region, single address.** One `t3.micro` in
  `us-east-1` for seven days. Nothing here generalises to global attack
  volumes, and a different region or address block would see a different
  population.
- **Short window.** Seven days. Weekly and monthly periodicity is not
  measurable, and a single busy day moves every average in the report.
- **Emulation is detectable.** Cowrie is fingerprintable by a determined
  operator. Sophisticated actors who identified the sensor and left are, by
  construction, absent from this data — so the population is biased toward
  automation and toward operators who did not check.
- **No payload analysis.** Deliberate; see §8.
- **Source IP is not an actor.** See §4.
- **Geolocation is inference.** Country is derived from IP registration and is
  routinely wrong for proxied and cloud-egress traffic.
- **The credential sample is shaped by the accept-list.** See §5.
- `[FILL — anything specific to your run: downtime, a misconfiguration
  discovered mid-run, a day of missing data, a query you could not complete.]`

---

## 12. Reproducing this

```bash
cp terraform/terraform.tfvars.example terraform/terraform.tfvars   # edit first
make deploy
# ... let it run ...
make fetch      # sync telemetry from S3 into findings/raw/
make parse      # -> findings/iocs.csv, findings/summary.json
make plot       # -> analysis/figures/*.png
make destroy
```

Full instructions: [docs/SETUP.md](../docs/SETUP.md).
Teardown checklist: [docs/TEARDOWN.md](../docs/TEARDOWN.md).
