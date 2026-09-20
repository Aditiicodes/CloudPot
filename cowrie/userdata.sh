#!/bin/bash
# ===========================================================================
# CloudPot sensor bootstrap
#
# This file is a Terraform template (terraform/ec2.tf renders it through
# templatefile). Anything of the form dollar-brace is a Terraform
# interpolation and is substituted at plan time; shell variables in this
# script are therefore written WITHOUT braces - $VAR, never dollar-brace-VAR.
# Adding a braced shell variable will break `terraform plan` with a confusing
# "Invalid function argument" error, not a shell error.
#
# ---------------------------------------------------------------------------
# THE ORDERING CONSTRAINT - READ THIS BEFORE EDITING
#
# This host has to do something that sounds trivial and is the single most
# dangerous step in the whole project: give port 22 to the honeypot while
# keeping a way in for the operator.
#
# There is exactly one correct order:
#
#   1. Move the real sshd to the admin port.
#   2. Restart it and PROVE it is listening there.
#   3. Only then redirect port 22 into Cowrie.
#
# Get that backwards - redirect 22 first, or move sshd without verifying -
# and the result is an EC2 instance with no administrative access at all. On
# a normal server you would recover through the serial console or SSM. This
# host has neither: SSM is deliberately not installed, because its managed IAM
# policy carries resource wildcards that would widen the instance role far
# beyond write-only telemetry (see terraform/iam.tf). The recovery path is
# `terraform destroy && terraform apply`, which costs you the run.
#
# The verification gate in step 2 is what makes this safe. If sshd is not
# confirmed listening on the admin port, the script exits non-zero BEFORE
# touching port 22, leaving the original sshd exactly where it was. A failed
# bootstrap that leaves you locked out is a bug; a failed bootstrap that
# leaves you with a working sshd and no honeypot is a Tuesday.
#
# Progress is written to /var/log/cloudpot-bootstrap.log and a marker file
# lands at /var/lib/cloudpot/bootstrap-complete only on full success.
# ===========================================================================

set -euo pipefail
exec > >(tee -a /var/log/cloudpot-bootstrap.log) 2>&1

ADMIN_PORT="${admin_ssh_port}"
BAIT_PORT="${bait_ssh_port}"
HTTP_BAIT_PORT="${http_bait_port}"
COWRIE_PORT=2222
COWRIE_HOME=/opt/cowrie
AWS_REGION="${aws_region}"
LOG_GROUP="${log_group_name}"
S3_BUCKET="${s3_bucket}"
S3_PREFIX="${s3_prefix}"

log() { echo "[cloudpot $(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"; }
fail() { log "FATAL: $*"; exit 1; }

log "bootstrap starting on $(hostname)"

# ---------------------------------------------------------------------------
# 1. Identity
# ---------------------------------------------------------------------------
# The real hostname matters less than Cowrie's emulated one, but a matching
# name keeps kernel log lines consistent with the sensor name in the data.
hostnamectl set-hostname "${sensor_hostname}"
sed -i "s/^127.0.1.1.*/127.0.1.1\t${sensor_hostname}/" /etc/hosts || true

# ---------------------------------------------------------------------------
# 2. Package sources over HTTPS
# ---------------------------------------------------------------------------
# Ubuntu's cloud images point apt at http:// mirrors. The security group
# permits NO outbound port 80 - that is the egress containment decision, and
# it applies to us as much as to an attacker - so apt would hang forever on
# its first fetch and the whole bootstrap would time out with a useless error.
#
# Rewriting the sources to https:// is the fix. It is also the better posture:
# plaintext apt leaks the exact package set of the host to any on-path
# observer, and on a machine whose whole purpose is to be probed, advertising
# "this box just installed python3-venv, libffi-dev and git" is free
# reconnaissance.
log "rewriting apt sources to https"
sed -i 's|http://|https://|g' /etc/apt/sources.list
if [ -d /etc/apt/sources.list.d ]; then
  find /etc/apt/sources.list.d -name '*.list' -exec sed -i 's|http://|https://|g' {} +
fi

export DEBIAN_FRONTEND=noninteractive

log "installing packages"
apt-get update -y
# iptables-persistent prompts for whether to save current rules; preseed the
# answers or the install blocks forever on a headless box.
echo "iptables-persistent iptables-persistent/autoinstall_v4 boolean true" | debconf-set-selections
echo "iptables-persistent iptables-persistent/autoinstall_v6 boolean true" | debconf-set-selections
apt-get install -y --no-install-recommends \
  git \
  python3-venv \
  python3-dev \
  python3-pip \
  libssl-dev \
  libffi-dev \
  build-essential \
  iptables \
  iptables-persistent \
  iproute2 \
  rsyslog \
  unzip \
  awscli

# ---------------------------------------------------------------------------
# 3. RELOCATE THE REAL SSHD  ***  do not reorder anything below this line  ***
# ---------------------------------------------------------------------------
log "relocating real sshd to port $ADMIN_PORT"

# Some Ubuntu/Debian builds socket-activate ssh. If ssh.socket is active it
# owns the listening port and sshd_config's Port directive is ignored
# entirely, so the move would silently do nothing and step 5 would hand 22 to
# Cowrie while the real sshd was still on it.
if systemctl list-unit-files 2>/dev/null | grep -q '^ssh.socket'; then
  log "ssh.socket present - disabling so sshd_config controls the port"
  systemctl disable --now ssh.socket || true
  systemctl enable ssh || true
fi

# Drop-in rather than an edit of the main file. On Ubuntu 22.04 the main
# sshd_config begins with "Include /etc/ssh/sshd_config.d/*.conf", and sshd
# takes the FIRST value it sees for any keyword, so a drop-in beats anything
# later in the main file.
cat > /etc/ssh/sshd_config.d/99-cloudpot.conf <<EOF
# Managed by CloudPot bootstrap. The honeypot owns port $BAIT_PORT.
Port $ADMIN_PORT

# Keys only. The honeypot's entire premise is that password authentication on
# port 22 is being brute-forced around the clock by the same population that
# can reach this port; leaving password auth enabled on the real sshd would
# mean the one service that actually matters shares an attack surface with
# the bait.
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
EOF

# Belt and braces: neutralise any Port line in the main file so a future
# reader grepping for "Port" finds one answer, not two that disagree.
sed -i -E "s/^[[:space:]]*#?[[:space:]]*Port[[:space:]]+[0-9]+/#Port (moved to $ADMIN_PORT by CloudPot)/" /etc/ssh/sshd_config

# Validate the configuration BEFORE restarting. sshd -t catches a syntax error
# while the running daemon is still serving; restarting into a broken config
# is how you lock yourself out without ever seeing an error message.
sshd -t || fail "sshd config invalid - refusing to restart. Original sshd untouched, port $BAIT_PORT not redirected."

systemctl restart ssh

# ---------------------------------------------------------------------------
# 4. THE VERIFICATION GATE
# ---------------------------------------------------------------------------
# Nothing below this point runs unless sshd is provably listening on the admin
# port. This is the check that turns "lock yourself out of a live honeypot"
# into "bootstrap failed, ssh in on 22 and read the log".
log "verifying sshd is listening on $ADMIN_PORT"
SSHD_UP=0
for _ in $(seq 1 30); do
  if ss -lntH "sport = :$ADMIN_PORT" 2>/dev/null | grep -q LISTEN; then
    SSHD_UP=1
    break
  fi
  sleep 1
done

if [ "$SSHD_UP" -ne 1 ]; then
  log "sshd is NOT listening on $ADMIN_PORT. Rolling back to the packaged config."
  rm -f /etc/ssh/sshd_config.d/99-cloudpot.conf
  systemctl restart ssh || true
  fail "could not move sshd to $ADMIN_PORT. Port $BAIT_PORT was NOT redirected, so the original sshd is still reachable. Fix the config and re-apply."
fi
log "sshd confirmed on $ADMIN_PORT - safe to proceed"

# ---------------------------------------------------------------------------
# 5. Cowrie
# ---------------------------------------------------------------------------
log "installing Cowrie (ref ${cowrie_ref})"

# Dedicated unprivileged system account with no login shell of its own worth
# stealing. Cowrie never needs root: it binds 2222, and port 22 reaches it
# through a kernel redirect instead of a privileged bind. If Cowrie itself has
# a remote hole, the attacker lands as this user with no sudo and no
# credentials, not as root.
if ! id cowrie >/dev/null 2>&1; then
  useradd -r -m -d "$COWRIE_HOME" -s /bin/bash cowrie
fi
install -d -o cowrie -g cowrie "$COWRIE_HOME"

sudo -u cowrie git clone --depth 1 --branch "${cowrie_ref}" \
  https://github.com/cowrie/cowrie.git "$COWRIE_HOME/repo"

# The clone lands in repo/ and is then moved into place, so a re-run finds a
# clean tree rather than a half-populated home directory.
sudo -u cowrie bash -c "cp -a $COWRIE_HOME/repo/. $COWRIE_HOME/ && rm -rf $COWRIE_HOME/repo"

# Virtualenv rather than system pip. Cowrie pins specific Twisted and
# cryptography versions; installing those over the distribution's python3
# packages breaks unrelated system tooling, including the CloudWatch agent's
# own python dependencies on some images.
sudo -u cowrie python3 -m venv "$COWRIE_HOME/cowrie-env"
sudo -u cowrie "$COWRIE_HOME/cowrie-env/bin/pip" install --upgrade pip setuptools wheel
sudo -u cowrie "$COWRIE_HOME/cowrie-env/bin/pip" install -r "$COWRIE_HOME/requirements.txt"

install -d -o cowrie -g cowrie "$COWRIE_HOME/var/log/cowrie" "$COWRIE_HOME/var/lib/cowrie/tty" "$COWRIE_HOME/var/lib/cowrie/downloads"

# Configuration is delivered gzip+base64. Two reasons: Cowrie's own config
# uses dollar-brace interpolation (the jsonlog path, for one), which
# Terraform's template parser would try to evaluate as an expression; and
# EC2 caps user_data at 16 KB, which this bootstrap plus its configuration
# would blow through uncompressed. Encoding sidesteps both and guarantees
# the file on the box is byte-identical to the one in the repository.
log "writing cowrie.cfg and userdb.txt"
echo "${cowrie_cfg_b64}" | base64 -d | gunzip > "$COWRIE_HOME/etc/cowrie.cfg"
echo "${cowrie_userdb_b64}" | base64 -d | gunzip > "$COWRIE_HOME/etc/userdb.txt"
chown cowrie:cowrie "$COWRIE_HOME/etc/cowrie.cfg" "$COWRIE_HOME/etc/userdb.txt"
chmod 0640 "$COWRIE_HOME/etc/cowrie.cfg" "$COWRIE_HOME/etc/userdb.txt"

# honeyfs overlay - the file contents an attacker reads after landing. Shipped
# from the repository rather than retyped here so the two cannot drift.
log "writing honeyfs overlay"
%{ for p, b64 in honeyfs_b64 ~}
install -d -o cowrie -g cowrie "$(dirname "$COWRIE_HOME/honeyfs/${p}")"
echo '${b64}' | base64 -d | gunzip > "$COWRIE_HOME/honeyfs/${p}"
chown cowrie:cowrie "$COWRIE_HOME/honeyfs/${p}"
%{ endfor ~}

cat > /etc/systemd/system/cowrie.service <<EOF
[Unit]
Description=Cowrie SSH honeypot (CloudPot sensor)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=cowrie
Group=cowrie
WorkingDirectory=$COWRIE_HOME
Environment=PYTHONPATH=$COWRIE_HOME/src
ExecStart=$COWRIE_HOME/cowrie-env/bin/twistd -n -l - --umask=0022 --pidfile= cowrie
Restart=on-failure
RestartSec=10

# Service hardening. Cowrie is the process that talks to attackers, so it gets
# the tightest sandbox the application tolerates. NoNewPrivileges alone defeats
# every setuid-based escalation from inside the process.
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full
ProtectHome=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
ReadWritePaths=$COWRIE_HOME/var $COWRIE_HOME/etc

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now cowrie

log "verifying Cowrie is listening on $COWRIE_PORT"
COWRIE_UP=0
for _ in $(seq 1 60); do
  if ss -lntH "sport = :$COWRIE_PORT" 2>/dev/null | grep -q LISTEN; then
    COWRIE_UP=1
    break
  fi
  sleep 2
done
[ "$COWRIE_UP" -eq 1 ] || fail "Cowrie did not bind $COWRIE_PORT. Port $BAIT_PORT NOT redirected - check journalctl -u cowrie."

# ---------------------------------------------------------------------------
# 6. Hand port 22 to Cowrie
# ---------------------------------------------------------------------------
# A kernel-level REDIRECT in the nat PREROUTING chain, not a privileged bind
# and not authbind. The attacker connects to 22; the kernel rewrites the
# destination to 2222 before it reaches the socket layer; Cowrie, running
# unprivileged, answers. Nothing with root ever holds the internet-facing
# port.
#
# PREROUTING only sees traffic arriving at the interface, so this rule cannot
# affect the host's own outbound connections or the admin port.
log "redirecting $BAIT_PORT to $COWRIE_PORT"
iptables -t nat -C PREROUTING -p tcp --dport "$BAIT_PORT" -j REDIRECT --to-ports "$COWRIE_PORT" 2>/dev/null \
  || iptables -t nat -A PREROUTING -p tcp --dport "$BAIT_PORT" -j REDIRECT --to-ports "$COWRIE_PORT"

# Port 80 has no listener. Without this rule an HTTP scan produces a TCP RST
# and no record anywhere, so a whole class of opportunistic scanning would be
# invisible in the data. Logging the SYN turns it into a countable event that
# ships to CloudWatch with everything else. The packet is not dropped - the
# kernel still answers with a RST, which is what a genuinely closed port does;
# silently dropping would make the host look filtered and is itself a tell.
iptables -C INPUT -p tcp --dport "$HTTP_BAIT_PORT" --syn -j LOG --log-prefix "CLOUDPOT-HTTP-SCAN " --log-level 4 2>/dev/null \
  || iptables -A INPUT -p tcp --dport "$HTTP_BAIT_PORT" --syn -j LOG --log-prefix "CLOUDPOT-HTTP-SCAN " --log-level 4

netfilter-persistent save

# ---------------------------------------------------------------------------
# 7. Telemetry off the box
# ---------------------------------------------------------------------------
# Cowrie's JSON is written to local disk, which is attacker-controlled the
# moment anyone escapes the emulated shell. The agent tails it and ships each
# line within seconds, so the authoritative copy lives in an account service
# the instance role cannot read back or delete.
log "installing CloudWatch agent"
CWA_DEB=/tmp/amazon-cloudwatch-agent.deb
curl -fsSL -o "$CWA_DEB" https://amazoncloudwatch-agent.s3.amazonaws.com/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb
dpkg -i -E "$CWA_DEB"

cat > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json <<EOF
{
  "agent": {
    "run_as_user": "root",
    "region": "$AWS_REGION"
  },
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [
          {
            "file_path": "$COWRIE_HOME/var/log/cowrie/cowrie.json",
            "log_group_name": "$LOG_GROUP",
            "log_stream_name": "{instance_id}/cowrie-json",
            "timezone": "UTC",
            "retention_in_days": -1
          },
          {
            "file_path": "/var/log/kern.log",
            "log_group_name": "$LOG_GROUP",
            "log_stream_name": "{instance_id}/netfilter",
            "timezone": "UTC",
            "retention_in_days": -1
          },
          {
            "file_path": "/var/log/cloudpot-bootstrap.log",
            "log_group_name": "$LOG_GROUP",
            "log_stream_name": "{instance_id}/bootstrap",
            "timezone": "UTC",
            "retention_in_days": -1
          }
        ]
      }
    },
    "force_flush_interval": 15
  }
}
EOF

# retention_in_days is -1 on purpose: retention is owned by Terraform
# (cloudwatch.tf), and letting the agent set it would mean the instance role
# needed logs:PutRetentionPolicy, which it does not have and should not.
/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
  -a fetch-config -m ec2 -s -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json

# ---------------------------------------------------------------------------
# 8. Nightly archive to S3
# ---------------------------------------------------------------------------
# The second, independent path to durable storage. Cowrie rotates its JSON
# daily to cowrie.json.YYYY-MM-DD; this ships each completed day into the
# Hive-style layout that Athena's partition projection expects, so no
# MSCK REPAIR is ever needed.
#
# Uploads are write-only by IAM: this script can put an object and cannot
# list, read or delete one. A .shipped marker beside each file prevents
# re-upload, and because the bucket is versioned, even a re-upload could not
# destroy the original.
log "installing nightly S3 shipper"
cat > /usr/local/bin/cloudpot-ship-logs.sh <<EOF
#!/bin/bash
set -euo pipefail
BUCKET="$S3_BUCKET"
PREFIX="$S3_PREFIX"
REGION="$AWS_REGION"
LOGDIR="$COWRIE_HOME/var/log/cowrie"
EOF

cat >> /usr/local/bin/cloudpot-ship-logs.sh <<'SHIPEOF'

shopt -s nullglob
for f in "$LOGDIR"/cowrie.json.*; do
  case "$f" in
    *.shipped|*.gz) continue ;;
  esac
  [ -f "$f.shipped" ] && continue

  base=$(basename "$f")
  day=$(printf '%s' "$base" | sed -E 's/^cowrie\.json\.//')

  # Only ship files whose suffix is a real date. Cowrie's rotation is the only
  # thing that should be creating these; anything else is either a partial
  # write or someone on the box getting creative, and neither belongs in the
  # evidence bucket under a fabricated partition.
  case "$day" in
    [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]) ;;
    *) continue ;;
  esac

  gzip -c "$f" > "/tmp/$base.gz"
  if aws s3 cp --region "$REGION" --only-show-errors \
       "/tmp/$base.gz" "s3://$BUCKET/$PREFIX/dt=$day/$base.gz"; then
    touch "$f.shipped"
    logger -t cloudpot-ship "uploaded $base to dt=$day"
  else
    logger -t cloudpot-ship "FAILED to upload $base"
  fi
  rm -f "/tmp/$base.gz"
done
SHIPEOF

chmod 0750 /usr/local/bin/cloudpot-ship-logs.sh

cat > /etc/systemd/system/cloudpot-ship.service <<'EOF'
[Unit]
Description=Ship rotated Cowrie logs to S3
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/cloudpot-ship-logs.sh
EOF

cat > /etc/systemd/system/cloudpot-ship.timer <<'EOF'
[Unit]
Description=Nightly Cowrie log upload

[Timer]
# Half past midnight UTC, after Cowrie's daily rotation has closed the file.
OnCalendar=*-*-* 00:30:00 UTC
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now cloudpot-ship.timer

# ---------------------------------------------------------------------------
# 9. Done
# ---------------------------------------------------------------------------
install -d /var/lib/cloudpot
date -u +%Y-%m-%dT%H:%M:%SZ > /var/lib/cloudpot/bootstrap-complete
log "bootstrap complete"
log "real sshd: port $ADMIN_PORT | cowrie: port $BAIT_PORT -> $COWRIE_PORT"
