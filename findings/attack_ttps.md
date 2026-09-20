# MITRE ATT&CK mapping

**Status: TEMPLATE.** The technique rows below are the ones an internet-facing
SSH honeypot in shell-emulation mode can plausibly observe. They are listed so
that you know what to look for — **not** so that you can tick them.

Rules for filling this in:

1. The **Observed** column starts empty. Fill it with a count and a citation —
   a query name, an event ID, a session ID — or write `not observed`.
2. `not observed` is a legitimate and common result. It means the sensor did
   not see it, which is information.
3. Never map a technique you did not observe. An ATT&CK table that claims
   every plausible technique tells a reader that the author mapped the
   framework rather than the data, and it is the fastest way to lose their
   trust in the rest of the report.
4. Cowrie emulates. A command appearing in the logs means it was **typed**,
   not that it executed or that it would have worked. Record attempted
   behaviour as attempted.

| ID | Technique | Tactic | What it looks like here | Where to look | Observed |
| --- | --- | --- | --- | --- | --- |
| **T1110.001** | Brute Force: Password Guessing | Credential Access | Repeated authentication attempts against a small username set with a password dictionary | `cowrie.login.failed`, `credential_frequency.sql` | |
| **T1110.003** | Brute Force: Password Spraying | Credential Access | One or two passwords tried across many usernames, low rate per account | `credential_frequency.sql`, group by password | |
| **T1078** | Valid Accounts | Initial Access / Persistence / Defense Evasion | Successful authentication with a weak or default credential from the accept-list | `cowrie.login.success` | |
| **T1059.004** | Command and Scripting Interpreter: Unix Shell | Execution | Any command entered after authentication | `cowrie.command.input`, `post_auth_commands.sql` | |
| **T1105** | Ingress Tool Transfer | Command and Control | `wget` / `curl` / `tftp` reaching for a second stage. **Blocked in this deployment** — the attempt and the URL are recorded, nothing was retrieved | `cowrie.session.file_download.failed`, `payload_urls.sql` | |
| **T1046** | Network Service Discovery | Discovery | Scanning or connection attempts from the host toward other addresses, or inbound probing of the bait ports | `post_auth_commands.sql`, VPC Flow Logs, the port-80 netfilter log stream | |
| **T1082** | System Information Discovery | Discovery | `uname -a`, `cat /proc/cpuinfo`, `lscpu`, `free -m`, `lsb_release -a` | `post_auth_commands.sql` | |
| **T1033** | System Owner/User Discovery | Discovery | `whoami`, `id`, `w`, `last` | `post_auth_commands.sql` | |
| **T1087.001** | Account Discovery: Local Account | Discovery | `cat /etc/passwd`, `cat /etc/shadow` | `post_auth_commands.sql` | |
| **T1098.004** | Account Manipulation: SSH Authorized Keys | Persistence | Writing a key into `~/.ssh/authorized_keys`, usually via `echo ... >>` | `post_auth_commands.sql` | |
| **T1053.003** | Scheduled Task/Job: Cron | Persistence | `crontab -l`, `crontab -e`, writes under `/etc/cron.*` | `post_auth_commands.sql` | |
| **T1136.001** | Create Account: Local Account | Persistence | `useradd`, `adduser`, direct `/etc/passwd` append | `post_auth_commands.sql` | |
| **T1070.003** | Indicator Removal: Clear Command History | Defense Evasion | `history -c`, `unset HISTFILE`, `export HISTFILE=/dev/null`, `rm ~/.bash_history` | `post_auth_commands.sql` | |
| **T1070.004** | Indicator Removal: File Deletion | Defense Evasion | `rm -rf /var/log/*`, removal of the staging directory after execution | `post_auth_commands.sql` | |
| **T1562.004** | Impair Defenses: Disable or Modify System Firewall | Defense Evasion | `iptables -F`, `ufw disable`, `systemctl stop firewalld` | `post_auth_commands.sql` | |
| **T1496** | Resource Hijacking | Impact | Cryptominer deployment — `xmrig`, `minerd`, a `stratum+tcp://` pool URL, or CPU-capability checks immediately before a fetch | `post_auth_commands.sql`, `payload_urls.sql` | |
| **T1021.004** | Remote Services: SSH | Lateral Movement | Outbound `ssh` from the honeypot toward other hosts, or key reuse attempts | `post_auth_commands.sql`, VPC Flow Logs | |
| **T1027** | Obfuscated Files or Information | Defense Evasion | `base64 -d \| sh`, hex-encoded payloads, long single-line one-liners | `post_auth_commands.sql` | |
| **T1071.001** | Application Layer Protocol: Web Protocols | Command and Control | HTTP(S) callbacks embedded in a command line. **Constrained here** — outbound is limited to 443 and the VPC resolver | `post_auth_commands.sql`, VPC Flow Logs | |

## Techniques this sensor structurally cannot observe

Worth stating in the report, because their absence is a property of the
deployment and not a finding about the threat landscape:

- Anything requiring a real kernel or a real filesystem — privilege escalation
  via a local exploit, kernel module loading, container escape. Cowrie emulates
  a shell; there is nothing underneath it to escalate into.
- Successful second-stage execution. Downloads are blocked, so no payload ever
  ran.
- Long-dwell activity. The sensor ran for seven days and was then destroyed.
- Anything on a protocol other than SSH. Telnet is disabled, port 80 has no
  listener.
