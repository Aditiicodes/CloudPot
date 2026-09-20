# Setup

> ## ⚠️ READ THIS FIRST: THE PORT 62222 LOCKOUT
>
> **After deployment, port 22 belongs to the honeypot. The real sshd is on
> port 62222.**
>
> ```bash
> ssh -p 62222 ubuntu@<public-ip>      # the real host
> ssh ubuntu@<public-ip>               # Cowrie. An emulated shell. Not your server.
> ```
>
> Connecting to port 22 will appear to work. You will get a prompt, a
> filesystem and a shell. **It is fake**, your commands do nothing, and every
> keystroke is recorded into the attack dataset as if you were an attacker.
> More than one operator has filed a bug about "my changes not persisting"
> from inside a honeypot.
>
> The bootstrap moves sshd and **verifies it is listening on 62222 before it
> hands port 22 to Cowrie**. If that verification fails it rolls back and
> aborts, leaving the original sshd where it was. That gate is the only thing
> standing between a bad edit to `cowrie/userdata.sh` and an instance with no
> administrative access — this host has no SSM agent and no serial console
> configured, so the recovery path is `terraform destroy && terraform apply`,
> which costs you the run.

---

## Prerequisites

| Requirement | Notes |
| --- | --- |
| AWS account with full IAM control | A personal account. Do not run this in an employer's account without written authorisation. |
| Terraform >= 1.6 | Pinned in `terraform/versions.tf`. |
| AWS CLI v2, authenticated | `aws sts get-caller-identity` must succeed. |
| Python 3.8+ | `parse_cowrie.py` is stdlib-only; `plots.py` needs matplotlib. |
| Your public IP | `curl -s https://checkip.amazonaws.com` |
| An email address for alarms | You must click the SNS confirmation link. |

Read [SAFETY.md](SAFETY.md) before you apply. It covers the AWS Acceptable Use
Policy position, why egress is contained, and what to do if the host is
compromised outside Cowrie's jail. It is not optional reading for something
you are deliberately exposing to the internet.

---

## Deploy

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars
$EDITOR terraform.tfvars          # admin_cidr and owner_contact are required
terraform init
terraform plan                    # read it
terraform apply
```

Or from the repository root: `make deploy`.

`admin_cidr` has no default and Terraform refuses to plan if you set it to
`0.0.0.0/0`. That is deliberate — an open admin port is a second attack
surface that is *not* inside Cowrie's jail.

Confirm the SNS subscription email when it arrives, or the billing alarm has
nowhere to fire.

### What gets built

A dedicated VPC (`10.42.0.0/16`), one public subnet, an internet gateway, a
network ACL, two security groups, one `t3.micro`, an Elastic IP, an
instance role with write-only telemetry permissions, a CloudWatch log group,
two S3 buckets, an SNS topic and two alarms. Nothing touches your default VPC.

---

## Verify the sensor is alive

The bootstrap takes roughly 4–6 minutes after `apply` returns. Work down this
list in order; each step isolates a different failure.

**1. Did the bootstrap finish?**

```bash
ssh -p 62222 ubuntu@$(terraform output -raw honeypot_public_ip) \
  'cat /var/lib/cloudpot/bootstrap-complete'
```

The file exists only on full success. If it is missing, read
`/var/log/cloudpot-bootstrap.log` — it is verbose and says which step failed.

**2. Is Cowrie listening, and is port 22 redirected?**

```bash
ssh -p 62222 ubuntu@<ip> 'systemctl is-active cowrie; sudo ss -lntp | grep 2222'
ssh -p 62222 ubuntu@<ip> 'sudo iptables -t nat -L PREROUTING -n'
```

**3. Does the bait answer from outside?**

```bash
ssh -o StrictHostKeyChecking=no root@<ip>      # password: 123456
```

You should land in an emulated shell on `svr-prod-01`. Type a command, then
disconnect. This is a real test — your own session will appear in the data, so
make a note of the time and exclude it from the analysis.

**4. Is telemetry arriving in CloudWatch?**

```bash
aws logs tail /cloudpot/cowrie --follow --region us-east-1
```

Your test session from step 3 should appear within about 15 seconds. If the
log group exists but has no streams, the agent is not shipping — check
`/opt/aws/amazon-cloudwatch-agent/logs/amazon-cloudwatch-agent.log` on the host
for an `AccessDenied`.

**5. Is it landing in S3?**

The nightly uploader runs at 00:30 UTC. To check the path without waiting:

```bash
ssh -p 62222 ubuntu@<ip> 'sudo /usr/local/bin/cloudpot-ship-logs.sh'
aws s3 ls s3://$(terraform output -raw telemetry_bucket)/cowrie/ --recursive
```

It only ships *rotated* files (`cowrie.json.YYYY-MM-DD`), so on day one there
may be nothing to send yet. That is not a fault.

**6. Is anyone actually attacking it?**

On a public IPv4 address with port 22 open, the first unsolicited connection
typically arrives within minutes. If an hour passes with nothing, the problem
is almost certainly your side — check the security group and the NACL before
concluding the internet has gone quiet.

The `cloudpot-no-log-ingest` alarm fires after two hours of zero ingest. It
exists so that "no activity" is a trustworthy statement rather than a guess: a
dead sensor and a quiet one look identical in the data.

---

## Cost

Roughly **$9 for a 7-day run** in `us-east-1`, outside free tier:

| Item | ~7-day cost | Note |
| --- | --- | --- |
| `t3.micro` on-demand | ~$1.75 | ~$0.0104/hr. Free tier covers this if eligible. |
| 20 GB gp3 root volume | ~$0.37 | |
| Elastic IP | $0.00 | Free while attached to a running instance. |
| CloudWatch Logs ingest | ~$1–4 | $0.50/GB. The dominant variable, and it scales with how hard you get scanned. |
| CloudWatch Logs storage | ~$0.05 | 14-day retention. |
| S3 (storage, requests) | <$0.20 | |
| VPC Flow Logs to S3 | ~$0.50–2 | Parquet, hourly partitions. |
| Athena | ~$0.10 | $5/TB scanned; partition projection keeps scans small. |
| Data transfer out | ~$0.10 | Honeypots receive far more than they send. |

**The number that moves is CloudWatch ingest.** A sustained brute-force
campaign can multiply log volume tenfold overnight. That is the entire reason
for the $20 billing alarm — and for checking Cost Explorer during the run, not
only after it.

Detailed monitoring is off (saves ~$2.10/instance/month) and there is no NAT
gateway (saves ~$32/month) because the honeypot lives in a public subnet by
design.

---

## Analysis

```bash
make fetch                        # aws s3 sync -> findings/raw/
make parse                        # -> findings/iocs.csv, findings/summary.json
make plot                         # -> analysis/figures/*.png
make athena-ddl                   # renders create_table.sql with your bucket name
```

`plots.py` needs matplotlib:

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r analysis/requirements.txt
```

`source_country_bar.png` requires an IP-to-country CSV passed with `--geo`.
The script does no geolocation itself — that would mean either bundling a
licensed database or sending every attacker address to a third party. Build
the mapping from a source you are entitled to use, then:

```bash
python3 analysis/plots.py --input findings/raw/ --geo findings/geo.csv
```

Without it, that one figure is skipped and the other three are still produced.

---

## Common problems

| Symptom | Cause |
| --- | --- |
| `terraform plan` errors on `admin_cidr` | It is `0.0.0.0/0` or malformed. This is the validation doing its job. |
| SSH to 62222 times out | Your public IP changed. Update `admin_cidr` and re-apply. |
| SSH to 62222 refused, 22 works | The bootstrap failed before the sshd move. Read `/var/log/cloudpot-bootstrap.log` via port 22 — but note you are in Cowrie, so you cannot. Destroy and re-apply. |
| No CloudWatch streams | Agent `AccessDenied`, or the log group name in `user_data` does not match `var.log_group_name`. |
| `terraform apply` fails on user_data size | The precondition in `ec2.tf` tripped: the bootstrap plus configs exceeds EC2's 16 KB limit. The error names the byte count. |
| Athena returns zero rows | The `dt=` partitions are not under the table's `LOCATION`, or your `BETWEEN` window is wrong. Check S3 before concluding nobody attacked. |
| Billing alarm never fires | You did not confirm the SNS subscription email. |
