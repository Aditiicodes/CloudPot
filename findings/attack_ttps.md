# MITRE ATT&CK mapping

Techniques observed during the 2026-03-09 → 2026-03-16 run. The rows below are
the ones an internet-facing SSH honeypot in shell-emulation mode can plausibly
observe; **16 of 19 carry evidence and 3 are marked `not observed`.**

How this table was filled, and how to read it:

1. Every **Observed** cell carries a count and the source that produces it — a
   query name or a `summary.json` path. No cell is ticked on plausibility.
2. `not observed` is a result, not a gap. It means the sensor did not see the
   technique during the window, which is information about this population.
3. No technique is mapped that was not observed. An ATT&CK table that claims
   every plausible technique tells a reader that the author mapped the
   framework rather than the data, and it is the fastest way to lose their
   trust in the rest of the report.
4. **Cowrie emulates.** A command appearing in the logs means it was **typed**,
   not that it executed or that it would have worked. Everything below is
   attempted behaviour, recorded as attempted.

| ID | Technique | Tactic | What it looks like here | Where to look | Observed |
| --- | --- | --- | --- | --- | --- |
| **T1110.001** | Brute Force: Password Guessing | Credential Access | Repeated authentication attempts against a small username set with a password dictionary | `cowrie.login.failed`, `credential_frequency.sql` | **Yes — 71,442 attempts, 68,340 failed, from 612 sources over 14,206 distinct pairs.** `root` alone took 66.2%. `summary.json → totals.login_attempts` |
| **T1110.003** | Brute Force: Password Spraying | Credential Access | One or two passwords tried across many usernames, low rate per account | `credential_frequency.sql`, group by password | **Yes — `root/123456` seen from 318 distinct sources, `root/password` from 276, at ≤3 attempts per source per hour.** Distinct-source count exceeds attempt rank for all 10 accepted pairs, which is the spray signature |
| **T1078** | Valid Accounts | Initial Access / Persistence / Defense Evasion | Successful authentication with a weak or default credential from the accept-list | `cowrie.login.success` | **Yes — 3,102 successes across 20 accept-list pairs (79.4% of sessions).** Note §5: this rate is a property of `userdb.example`, not of the attackers |
| **T1059.004** | Command and Scripting Interpreter: Unix Shell | Execution | Any command entered after authentication | `cowrie.command.input`, `post_auth_commands.sql` | **Yes — 2,147 commands in 418 sessions.** Only 13.5% of successful logins ran anything at all |
| **T1105** | Ingress Tool Transfer | Command and Control | `wget` / `curl` / `tftp` reaching for a second stage. **Blocked in this deployment** — the attempt and the URL are recorded, nothing was retrieved | `cowrie.session.file_download.failed`, `payload_urls.sql` | **Attempted, 0 achieved — 41 attempts, 37 URLs, 24 hosts, 19 sources. `artifacts_retrieved: 0`, `hashes_observed: 0`.** All `wget`; no `curl`, no `tftp` |
| **T1046** | Network Service Discovery | Discovery | Scanning or connection attempts from the host toward other addresses, or inbound probing of the bait ports | `post_auth_commands.sql`, VPC Flow Logs, the port-80 netfilter log stream | **Yes — 288 `direct-tcpip` channel requests (destinations: 25/tcp ×171, 443/tcp ×64, 80/tcp ×53), all refused. 4,113 inbound SYNs to the port-80 bait from 486 sources** |
| **T1082** | System Information Discovery | Discovery | `uname -a`, `cat /proc/cpuinfo`, `lscpu`, `free -m`, `lsb_release -a` | `post_auth_commands.sql` | **Yes — `uname -a` ×389, `cat /proc/cpuinfo` ×302, `free -m` ×204, `uname -m` ×94, `nproc` ×61.** The single most common opening move (271 of 418 sessions) |
| **T1033** | System Owner/User Discovery | Discovery | `whoami`, `id`, `w`, `last` | `post_auth_commands.sql` | **Yes — `whoami` ×281, `id` ×88, `w` ×12, `last` ×7** |
| **T1087.001** | Account Discovery: Local Account | Discovery | `cat /etc/passwd`, `cat /etc/shadow` | `post_auth_commands.sql` | **Yes — `cat /etc/passwd` ×151 from 63 sources; `cat /etc/shadow` ×9.** In 31 sessions the read was followed within 2 s by a login attempt against an account it disclosed (§5) |
| **T1098.004** | Account Manipulation: SSH Authorized Keys | Persistence | Writing a key into `~/.ssh/authorized_keys`, usually via `echo ... >>` | `post_auth_commands.sql` | **Yes — 23 sessions from 7 sources, all via `echo ... >>`. 4 distinct public keys, one recurring across sources sharing no /16** |
| **T1053.003** | Scheduled Task/Job: Cron | Persistence | `crontab -l`, `crontab -e`, writes under `/etc/cron.*` | `post_auth_commands.sql` | **Yes — 11 sessions: 8 × `crontab -l` then `crontab -`, 3 × direct write to `/etc/cron.d/`.** `crontab -l` alone ran 118 times, mostly as reconnaissance without a follow-up write |
| **T1136.001** | Create Account: Local Account | Persistence | `useradd`, `adduser`, direct `/etc/passwd` append | `post_auth_commands.sql` | `not observed` — no `useradd`, `adduser` or `/etc/passwd` write in any of the 418 command sessions |
| **T1070.003** | Indicator Removal: Clear Command History | Defense Evasion | `history -c`, `unset HISTFILE`, `export HISTFILE=/dev/null`, `rm ~/.bash_history` | `post_auth_commands.sql` | **Yes — `history -c` ×97, `unset HISTFILE` ×34, `export HISTFILE=/dev/null` ×19, `rm -f ~/.bash_history` ×12.** 89 of the 97 ran immediately before disconnect, concealing nothing |
| **T1070.004** | Indicator Removal: File Deletion | Defense Evasion | `rm -rf /var/log/*`, removal of the staging directory after execution | `post_auth_commands.sql` | **Yes — 6 sessions ran `rm -rf /var/log/wtmp /var/log/btmp`; 4 removed a `/tmp` staging directory after the failed fetch** |
| **T1562.004** | Impair Defenses: Disable or Modify System Firewall | Defense Evasion | `iptables -F`, `ufw disable`, `systemctl stop firewalld` | `post_auth_commands.sql` | `not observed` — no `iptables`, `ufw`, `nft` or `firewalld` command in any session |
| **T1496** | Resource Hijacking | Impact | Cryptominer deployment — `xmrig`, `minerd`, a `stratum+tcp://` pool URL, or CPU-capability checks immediately before a fetch | `post_auth_commands.sql`, `payload_urls.sql` | **Attempted — `http://198.51.100.77/xmrig` requested ×2 and blocked. 196 sessions ran the CPU/memory capability survey (`cat /proc/cpuinfo`, `free -m`, `nproc`) with no follow-up.** No `stratum+tcp://` URL appeared |
| **T1021.004** | Remote Services: SSH | Lateral Movement | Outbound `ssh` from the honeypot toward other hosts, or key reuse attempts | `post_auth_commands.sql`, VPC Flow Logs | `not observed` — no outbound `ssh`, `scp` or `sftp` command was entered, and VPC Flow Logs record no egress to 22/tcp. The 288 `direct-tcpip` requests under T1046 are tunnelling *through* the host, not movement *from* it |
| **T1027** | Obfuscated Files or Information | Defense Evasion | `base64 -d \| sh`, hex-encoded payloads, long single-line one-liners | `post_auth_commands.sql` | **Yes — 14 sessions: 9 × `echo <b64> \| base64 -d \| sh`, 3 × `echo -e '\x..'` hex construction, 2 single-line chains over 400 characters** |
| **T1071.001** | Application Layer Protocol: Web Protocols | Command and Control | HTTP(S) callbacks embedded in a command line. **Constrained here** — outbound is limited to 443 and the VPC resolver | `post_auth_commands.sql`, VPC Flow Logs | **Attempted, 0 succeeded — all 41 fetch attempts were plaintext HTTP to a bare IP across 24 hosts, 4 on non-standard ports. None used HTTPS or a hostname, so all 41 would also have failed at the security group** |

## Techniques this sensor structurally cannot observe

Worth stating in the report, because their absence is a property of the
deployment and not a finding about the threat landscape:

- Anything requiring a real kernel or a real filesystem — privilege escalation
  via a local exploit, kernel module loading, container escape. Cowrie emulates
  a shell; there is nothing underneath it to escalate into.
- Successful second-stage execution. Downloads are blocked, so no payload ever
  ran.
- Long-dwell activity. The sensor ran for seven days and was then destroyed.
  The 23 banked SSH keys (T1098.004) would only pay off after that window, so
  whatever they were for is outside this dataset by construction.
- Anything on a protocol other than SSH. Telnet is disabled, port 80 has no
  listener — the 4,113 SYNs counted under T1046 are connection attempts logged
  by netfilter, with no application-layer content behind them.
