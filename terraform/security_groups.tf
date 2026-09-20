# ---------------------------------------------------------------------------
# Security groups - the stateful, per-instance control.
#
# Two groups are attached to one instance. Splitting them is deliberate: the
# bait rules and the operator rules have completely different review criteria.
# The bait group is supposed to be wide open and should never be questioned.
# The admin group is supposed to be a single /32 and should be questioned
# every time it changes. Keeping them in one group makes that distinction
# invisible in a diff.
#
# Both groups are declared with NO inline ingress/egress blocks. That is not
# an omission: declaring an aws_security_group without inline rules causes
# Terraform to revoke the AWS-default "allow all egress" rule, which is
# exactly what we want. Rules are then added one at a time below, each with
# its own description, so `terraform plan` shows a per-rule diff.
# ---------------------------------------------------------------------------

# The S3 service prefix list, so the S3 egress rule targets S3's published
# address ranges instead of the whole internet.
data "aws_ec2_managed_prefix_list" "s3" {
  name = "com.amazonaws.${data.aws_region.current.name}.s3"
}

# The bait group. Declared with no inline rules so Terraform revokes the
# AWS-default allow-all egress; every rule it ends up with is added
# explicitly below and shows as its own line in a plan diff.
resource "aws_security_group" "honeypot" {
  name_prefix = "${var.project}-honeypot-"
  description = "Internet-facing bait ports and the enumerated egress allowlist"
  vpc_id      = aws_vpc.honeypot.id

  # Recreate before destroy so a rule change never leaves the instance
  # momentarily without a security group.
  lifecycle {
    create_before_destroy = true
  }

  tags = { Name = "${var.project}-honeypot-sg" }
}

# The operator group. Same no-inline-rules reasoning, and it deliberately
# ends up with exactly one rule and no egress at all.
resource "aws_security_group" "admin" {
  name_prefix = "${var.project}-admin-"
  description = "Operator access to the real sshd on the relocated admin port"
  vpc_id      = aws_vpc.honeypot.id

  lifecycle {
    create_before_destroy = true
  }

  tags = { Name = "${var.project}-admin-sg" }
}

# --- Honeypot ingress ----------------------------------------------------

# Open to the internet by design. This is the sensor aperture: every packet
# that arrives here is unsolicited and therefore interesting. Cowrie is bound
# to 2222 and receives this traffic through a netfilter REDIRECT, so nothing
# privileged is listening on 22.
resource "aws_vpc_security_group_ingress_rule" "honeypot_ssh_bait" {
  security_group_id = aws_security_group.honeypot.id
  description       = "SSH bait - unsolicited internet traffic, redirected to Cowrie on 2222"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = var.ssh_bait_port
  to_port           = var.ssh_bait_port
}

# No listener on 80. Inbound SYNs are logged by a netfilter LOG rule and
# shipped alongside the Cowrie stream, which turns an otherwise silent
# "connection refused" into countable scan telemetry.
resource "aws_vpc_security_group_ingress_rule" "honeypot_http_bait" {
  security_group_id = aws_security_group.honeypot.id
  description       = "HTTP bait - no listener, SYNs logged by netfilter for scan telemetry"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = var.http_bait_port
  to_port           = var.http_bait_port
}

# --- Admin ingress -------------------------------------------------------

# The only route to the real operating system, and it is restricted at two
# layers: here, and by NACL rules 120/130 in vpc.tf. Read the comment on those
# rules before changing either - the subnet-level restriction depends on an
# explicit deny ordered ahead of the ephemeral-return allow, and removing it
# silently reduces this to a single layer.
#
# A variable validation in variables.tf refuses to plan if this is 0.0.0.0/0.
# The port is non-standard not because obscurity is security, but because
# leaving the real sshd on 22 would mean the operator and the attackers share
# a listener - and Cowrie needs 22 for the bait.
resource "aws_vpc_security_group_ingress_rule" "admin_ssh" {
  security_group_id = aws_security_group.admin.id
  description       = "Real sshd, operator CIDR only"
  cidr_ipv4         = var.admin_cidr
  ip_protocol       = "tcp"
  from_port         = var.admin_ssh_port
  to_port           = var.admin_ssh_port
}

# --- Egress: the enumerated allowlist ------------------------------------
#
# Security groups are stateful, so replies to the inbound rules above are
# permitted automatically and do NOT need an egress rule. Everything below is
# therefore the complete list of connections this host may *initiate*. There
# is no 0.0.0.0/0-on-all-ports rule anywhere in this file, and the admin
# security group has no egress rules at all.

# S3, scoped to the service's published prefix list rather than the internet.
# Carries the daily Cowrie JSON upload and VPC flow log delivery.
resource "aws_vpc_security_group_egress_rule" "honeypot_s3" {
  security_group_id = aws_security_group.honeypot.id
  description       = "HTTPS to S3 service ranges only - telemetry upload"
  prefix_list_id    = data.aws_ec2_managed_prefix_list.s3.id
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

# CloudWatch Logs has no public managed prefix list, so this rule is 443 to
# 0.0.0.0/0. That is the widest rule in the project and it is a conscious
# trade-off, not an oversight:
#   - The alternative is an interface VPC endpoint for logs (and one for
#     ssm/ec2messages if SSM were used), each ~$7.30/month plus data
#     processing, against a target run cost of ~$9/week. It roughly doubles
#     the cost of the project to close one path.
#   - The residual risk is that an attacker who fully escapes Cowrie could
#     use 443 for C2 or exfiltration to an arbitrary host.
#   - It is accepted because the host holds nothing worth exfiltrating, the
#     VPC is isolated, VPC Flow Logs record every connection from outside the
#     instance, and the recovery path is `terraform destroy`.
# This rule is also what the bootstrap depends on for the https apt mirror,
# PyPI and GitHub.
resource "aws_vpc_security_group_egress_rule" "honeypot_https" {
  security_group_id = aws_security_group.honeypot.id
  description       = "HTTPS egress - CloudWatch Logs, apt over https, PyPI, GitHub. See comment for the endpoint cost trade-off."
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

# DNS to the VPC resolver only. The resolver lives at the VPC base + 2, so
# this is a single address, not the internet. An attacker cannot use an
# arbitrary external resolver, which closes the most common DNS-tunnelling
# and DNS-based-C2 path.
resource "aws_vpc_security_group_egress_rule" "honeypot_dns_udp" {
  security_group_id = aws_security_group.honeypot.id
  description       = "DNS/UDP to the VPC resolver only - blocks external resolvers and DNS tunnelling"
  cidr_ipv4         = "${cidrhost(var.vpc_cidr, 2)}/32"
  ip_protocol       = "udp"
  from_port         = 53
  to_port           = 53
}

# DNS over TCP to the same single resolver address, for responses too large
# for UDP. Same containment reasoning as the rule above.
resource "aws_vpc_security_group_egress_rule" "honeypot_dns_tcp" {
  security_group_id = aws_security_group.honeypot.id
  description       = "DNS/TCP to the VPC resolver only - large responses"
  cidr_ipv4         = "${cidrhost(var.vpc_cidr, 2)}/32"
  ip_protocol       = "tcp"
  from_port         = 53
  to_port           = 53
}

# Not present, on purpose: any egress rule on the admin security group. The
# honeypot group already carries the host's outbound allowlist; duplicating it
# here would just create a second place to get it wrong. Time sync is not
# listed either because the Amazon Time Sync Service is reached at the
# link-local address 169.254.169.123, which is not subject to security group
# or NACL evaluation.
