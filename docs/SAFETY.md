# Safety, legality and containment

A honeypot is a machine you are inviting strangers to break into, running on
infrastructure you rent, under an account with your name on it. This document
is the reasoning behind every restriction in the Terraform, and it is the part
of the project that matters most.

The governing question is never "will someone get in" — someone will, that is
the design. It is **"what can they do with the host afterwards, and who gets
hurt if I am wrong?"**

---

## 1. AWS Acceptable Use Policy

Running a honeypot on EC2 is permitted. AWS's AUP prohibits using their
infrastructure to attack, abuse or disrupt others; it does not prohibit
operating a deliberately vulnerable host. What would violate it is the
honeypot being used as a launch point — outbound scanning, spam, a DDoS
reflector, C2 relay — and that is the specific outcome the containment below
exists to prevent.

Two AWS policies interact here and are often confused:

- **Penetration testing policy.** Permits testing *your own* resources for a
  defined list of services without prior approval. Not what this is: nothing
  here attacks anything.
- **Acceptable Use Policy.** Governs what your resources may do to others.
  This is the one that applies, and the one an escaped attacker would breach
  on your behalf.

Operating practices that follow from this:

- **Your own account.** Never an employer's account without written
  authorisation. A trust-and-safety complaint lands on the account owner.
- **Every resource is tagged** with `Purpose=SecurityResearch-SSHHoneypot` and
  a `Contact`, set via `default_tags` in `versions.tf`. If AWS ever asks about
  traffic from this VPC, the answer should be visible from the account without
  you in the room.
- **Watch for abuse notifications.** If AWS contacts you about traffic
  originating from this instance, destroy it first and investigate from the
  logs afterwards. The instance is disposable; the account is not.
- **Fixed, short window.** Seven days, then `terraform destroy`. An
  indefinitely-running unattended honeypot is how this goes wrong.

---

## 2. Egress containment

This is the core security decision of the project. The entire threat model
reduces to one question: *can a compromised honeypot reach a third party?*

Two layers enforce it, and they work differently — neither is sufficient alone.

### Security groups (stateful)

Return traffic for an allowed inbound connection is permitted automatically,
so the egress list can be exactly the set of destinations the host may
**initiate** to:

| Destination | Port | Why |
| --- | --- | --- |
| S3 service prefix list | 443 | Telemetry upload, flow log delivery |
| `0.0.0.0/0` | 443 | CloudWatch Logs (no public prefix list exists) |
| VPC resolver (`10.42.0.2/32`) | 53 TCP+UDP | DNS |

That is the whole list. An attacker who escapes Cowrie and runs a real process
**cannot open a socket to a C2 listener on port 4444**, because no egress rule
matches. No SMTP, no IRC, no ICMP, no arbitrary UDP.

Restricting DNS to the VPC resolver is a specific choice: it closes DNS
tunnelling and DNS-based C2, which are the two most common ways out of a
"443-only" environment.

### Network ACLs (stateless)

NACLs evaluate every packet independently with no connection tracking. That
forces one compromise: **the NACL must allow outbound TCP 1024–65535**, or the
SYN-ACK replies to inbound SSH connections are dropped and the honeypot never
completes a handshake with anyone.

That looks like a hole and is not, because of evaluation order. For traffic
the instance originates, the **security group is evaluated first**, and the
security group has no egress rule permitting a new connection to a high port.
The NACL's ephemeral allowance can therefore only ever carry replies to
connections that arrived from outside.

Stated as a rule: **the NACL is the coarse blast-radius limit for the subnet,
the security group is the precise per-instance control.**

### The residual risk, stated plainly

Outbound 443 to `0.0.0.0/0` is the widest rule in the project. An attacker who
fully escapes Cowrie could use it for C2 or exfiltration to an arbitrary host.

It is accepted, knowingly, because:

- Closing it requires an interface VPC endpoint for CloudWatch Logs at
  ~$7.30/month plus data processing — roughly doubling the cost of a project
  budgeted at ~$9/week.
- The host holds nothing worth exfiltrating: no data, no credentials, no keys,
  and an instance role that can only append to one log group and write to one
  S3 prefix.
- **VPC Flow Logs** record every connection from outside the instance, where an
  attacker on the box cannot edit them. If something did get out, there is an
  independent record of it.
- The VPC is isolated — no peering, no transit gateway, no shared subnets — so
  there is no path from here into anything else.

If you are running this somewhere the risk calculus differs, the interface
endpoint is the fix and the cost is the price.

---

## 3. Why payload downloads are blocked

**No binaries were downloaded, stored, hashed or analysed.** Two independent
mechanisms enforce it:

1. **Network.** The security group permits no outbound connection to attacker
   infrastructure. The emulated `wget`/`curl` fails at connect time.
2. **Application.** Cowrie's `download_limit_size` is set to `1` byte.

> A note on that setting, because the obvious value does the opposite of what
> it looks like: **in Cowrie, `download_limit_size = 0` means *no limit*.**
> Setting it to zero to "disable downloads" enables unlimited ones. `1` is the
> smallest value Cowrie treats as a limit at all.

### The trade-off

Capturing samples would give more: static analysis, family attribution,
capability assessment, hashes to pivot on. That is real analytical value and
this deployment gives it up. Here is why that was the right call for this
project.

**Malware handling burden.** A captured sample is live malware on
infrastructure you rent. Handling it responsibly means an isolated analysis
environment, storage that cannot be accidentally shared or synced, and a
disposal process. Getting that wrong once — an S3 bucket policy loosened for
convenience, a sample pulled to a laptop for "a quick look" — is worse than
never having collected it.

**Legal ambiguity.** Possession and transfer of malicious code sits
differently across jurisdictions, and "I collected it from my honeypot" is an
explanation you would rather not be giving. Storing it in cloud object storage
is arguably distribution. For a personal research project, that ambiguity
buys nothing.

**AWS AUP exposure.** Fetching a payload means the honeypot making an outbound
connection to attacker infrastructure. That is precisely the class of traffic
the containment above exists to prevent, and allowing it would mean punching a
hole in the control that keeps the account safe.

**What is kept is still actionable.** The URL, the staging host and port, the
exact command used to reach it, the session, the source address and the
timing. That is enough to build blocklists and detection rules, and it pivots
against passive DNS and public sandbox reporting — where someone with the
right environment has *already* analysed the sample — without anyone here
touching a binary.

**What is lost, stated honestly.** No static analysis, no family attribution,
no capability assessment, and in almost all cases no hash — with downloads
blocked, Cowrie never stores a file to hash, so the `shasum` field is expected
to be empty. A report from this deployment cannot say "the payload was X".
That limitation belongs in the report, not buried here.

If a hash *does* appear in your data, something was retrieved. Stop and work
out what, before publishing anything.

---

## 4. If the host is compromised outside Cowrie's jail

Cowrie emulates a shell; there is no real shell underneath it. But assume a
remote hole in Cowrie itself, or in `sshd`, and plan for it.

**Signals that it happened:**

- Outbound connections in VPC Flow Logs that do not match the egress
  allowlist, or volume that does not match telemetry upload.
- The `cloudpot-no-log-ingest` alarm firing while the instance is up — logs
  stopping is what tampering looks like from outside.
- An unexplained billing jump (an alarm you already have).
- Cowrie's local JSON disagreeing with the CloudWatch copy. The CloudWatch
  copy is authoritative: it left the box within seconds and the instance role
  cannot read or delete it.

**What to do, in order:**

1. **Do not SSH in to investigate.** You would be logging into a host you
   believe is attacker-controlled.
2. **Cut the network first, then preserve.** In the console: replace the
   instance's security groups with one that has no rules. This freezes it
   without terminating it, which keeps the EBS volume and memory state.
3. **Snapshot the root volume** if you intend to look at it — from the API,
   not from inside the instance.
4. **Pull the evidence that is already off-box:** CloudWatch Logs and VPC Flow
   Logs. Neither can have been altered from the instance.
5. **Then destroy.** `terraform destroy`. Redeploying is cheap; the instance
   was always disposable.
6. **Check the blast radius.** Review CloudTrail for any API call made with
   the instance role. Its permissions are write-only to one log group and one
   S3 prefix, so the worst case is polluted telemetry — which versioning on the
   bucket preserves the originals against — but confirm rather than assume.
7. **If there is any sign the host attacked a third party**, contact AWS
   proactively rather than waiting for the notification.

The design assumption throughout is that **the instance is expendable and the
account is not**. Every control is sized to that.

---

## 5. Data retention and handling

Cowrie logs contain source IP addresses, which are personal data under GDPR
and comparable regimes, and credential guesses, which are someone's password
dictionary and may include real credentials harvested elsewhere.

| Control | Setting | Where |
| --- | --- | --- |
| CloudWatch Logs retention | 14 days | `cloudwatch.tf` |
| S3 lifecycle to STANDARD_IA | 30 days | `s3.tf` |
| S3 expiration | 180 days | `s3.tf` |
| Non-current version expiration | 30 days | `s3.tf` |
| Encryption at rest | SSE-S3, plus encrypted EBS | `s3.tf`, `ec2.tf` |
| Public access | Blocked, all four flags | `s3.tf` |
| Transport | Non-TLS requests denied by bucket policy | `s3.tf` |

**180 days is a commitment, not a default.** Non-current version expiry is set
alongside it deliberately: with versioning enabled and no non-current rule,
"expiration" deletes nothing and the retention promise is false.

**What must not be published:**

- Raw logs. `findings/raw/` is gitignored.
- Full source IP lists without considering that several will be shared
  infrastructure — NAT, VPN exits, cloud egress — and that a reader may act on
  them.
- Passwords as a standalone list. `parse_cowrie.py` emits the
  `username:password` **pair** as an indicator and never the password alone: a
  password list from a honeypot is a credential-stuffing dictionary with a
  respectable provenance story attached.
- Anything that identifies a private individual.

**What is fine to publish:** aggregate counts, credential pair frequencies,
command patterns, attempted staging URLs, and the analysis itself.

---

## 6. Things this deployment deliberately does not do

- **No proxy mode.** Cowrie can forward sessions to a real backend VM for much
  richer telemetry. That means operating a genuinely compromisable Linux host
  on the public internet — a different risk posture and a different
  conversation with your provider.
- **No telnet listener.** A second protocol, a second port, a second parser,
  for data nobody asked for.
- **No SSM agent.** It would be a useful break-glass path, but
  `AmazonSSMManagedInstanceCore` carries resource wildcards that would widen
  the instance role far beyond write-only telemetry, and an SSM session channel
  is extra attack surface on a box designed to be attacked. The recovery path
  is destroy-and-redeploy.
- **No automatic blocking.** The sensor observes. Feeding these indicators
  into a live blocklist without review would act on shared infrastructure.
- **No outbound anything beyond the allowlist.** Including NTP: the Amazon
  Time Sync Service is reached at the link-local address `169.254.169.123`,
  which is not subject to security group or NACL evaluation.
