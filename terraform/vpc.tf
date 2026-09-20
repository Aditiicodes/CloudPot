# ---------------------------------------------------------------------------
# Dedicated network for the honeypot.
#
# Security rationale for a dedicated VPC: the honeypot must share nothing with
# anything the operator cares about. No default VPC, no shared subnets, no
# peering, no security-group references to other workloads. If this host is
# fully compromised outside Cowrie's jail, the blast radius is this VPC and
# nothing else in the account.
# ---------------------------------------------------------------------------

resource "aws_vpc" "honeypot" {
  cidr_block = var.vpc_cidr

  # DNS is required: the CloudWatch agent and the S3 uploader resolve public
  # AWS endpoints. DNS hostnames are enabled for the same reason.
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "${var.project}-vpc" }
}

# Flow logs are the independent record of what left this VPC. Cowrie's own
# logs cannot be trusted if the attacker escapes the emulated shell; VPC Flow
# Logs are written by the hypervisor, outside the instance, so an attacker on
# the box cannot edit them. This is the primary evidence source for the
# "did anything actually get out?" question in docs/SAFETY.md.
resource "aws_flow_log" "vpc" {
  vpc_id               = aws_vpc.honeypot.id
  traffic_type         = "ALL"
  log_destination_type = "s3"
  log_destination      = "${aws_s3_bucket.telemetry.arn}/vpc-flow-logs/"

  # Hourly partitions in Hive format so the same Athena workflow can read them.
  destination_options {
    file_format                = "parquet"
    per_hour_partition         = true
    hive_compatible_partitions = true
  }

  # The bucket policy granting delivery.logs.amazonaws.com write access must
  # exist first, or flow log delivery silently fails and the independent
  # egress record - the one an attacker on the box cannot tamper with - is
  # never written.
  depends_on = [aws_s3_bucket_policy.telemetry]

  tags = { Name = "${var.project}-vpc-flow-logs" }
}

# The honeypot must be directly reachable to receive unsolicited traffic, so
# an IGW is required. It is attached to this VPC alone - there is no shared
# gateway and no second attachment.
resource "aws_internet_gateway" "honeypot" {
  vpc_id = aws_vpc.honeypot.id

  tags = { Name = "${var.project}-igw" }
}

# Single public subnet. The honeypot must be directly reachable from the
# internet to receive unsolicited traffic - that is the entire point - so
# there is no private subnet or NAT gateway here. NAT would also add ~$32/mo
# for no benefit.
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.honeypot.id
  cidr_block              = var.public_subnet_cidr
  availability_zone       = var.availability_zone
  map_public_ip_on_launch = false # The instance gets an explicit EIP instead.

  tags = { Name = "${var.project}-public" }
}

# One route table, one default route. Keeping routing this small is a
# security property: there is no route anywhere except the internet, so a
# compromised host has no path toward another network the operator owns.
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.honeypot.id

  # The only route off-VPC is the IGW. There is no transit gateway, no
  # peering, and no VPN, so there is no path from this subnet into any other
  # network the operator owns.
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.honeypot.id
  }

  tags = { Name = "${var.project}-public-rt" }
}

# Binds the subnet to the table above rather than leaving it on the VPC main
# route table, whose contents this configuration does not control.
resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# ---------------------------------------------------------------------------
# Network ACL - the egress containment layer.
#
# THIS IS THE CORE SECURITY DECISION OF THE PROJECT. Read this block before
# changing anything in it.
#
# A honeypot is a machine you are inviting strangers to break into. The threat
# model is not "someone might get in" - someone WILL get in, that is the
# design. The question is what they can do with the host afterwards. The
# failure mode that matters is the host being used to attack a third party:
# outbound scanning, spam, DDoS participation, or C2 check-in. That is an AWS
# Acceptable Use Policy violation and it is the operator's account on the line.
#
# Two layers enforce containment, and they work differently:
#
#   Security groups are STATEFUL. Return traffic for an allowed connection is
#   permitted automatically. So the SG egress list can be exactly the set of
#   destinations the host is allowed to *initiate* to: 443 and 53. Nothing
#   else. An attacker who breaks out of Cowrie's emulated shell and runs a
#   real process cannot open a socket to a C2 listener on port 4444, because
#   the SG has no egress rule that matches.
#
#   Network ACLs are STATELESS. Every packet is evaluated independently, in
#   both directions, with no connection tracking. That means the NACL MUST
#   allow the ephemeral port range outbound, otherwise the SYN-ACK replies to
#   legitimate inbound SSH connections are dropped and the honeypot never
#   completes a handshake with anyone.
#
# The consequence is important and is stated here rather than hidden: NACL
# egress rule 200 below allows TCP 1024-65535 to anywhere. On its own that
# would be a hole. It is not a hole in practice because NACL and SG are
# evaluated in series for instance-originated traffic - the SG is evaluated
# first, and the SG has no egress rule permitting a new outbound connection to
# a high port. The NACL's ephemeral allowance can therefore only ever carry
# replies to connections that arrived from outside.
#
# Put plainly: the NACL is the coarse blast-radius limit for the subnet, the
# security group is the precise per-instance control, and neither one alone is
# sufficient. See docs/SAFETY.md.
# ---------------------------------------------------------------------------

resource "aws_network_acl" "honeypot" {
  vpc_id = aws_vpc.honeypot.id

  tags = { Name = "${var.project}-nacl" }
}

# Binds the subnet to the custom ACL. Without this the subnet keeps the
# default NACL, which allows all traffic in both directions and would silently
# void the entire egress containment design below.
resource "aws_network_acl_association" "public" {
  network_acl_id = aws_network_acl.honeypot.id
  subnet_id      = aws_subnet.public.id
}

# --- Inbound -------------------------------------------------------------

# The bait, and the sensor's entire aperture. Open to the whole internet on
# purpose: unsolicited scanning of port 22 is the data we came here to
# collect, and narrowing this would bias the sample toward whoever we chose to
# let in - which is no sample at all. Scanners flag this rule; it is correct.
# tfsec:ignore:aws-vpc-no-public-ingress-acl
resource "aws_network_acl_rule" "in_ssh_bait" {
  network_acl_id = aws_network_acl.honeypot.id
  rule_number    = 100
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = var.ssh_bait_port
  to_port        = var.ssh_bait_port
}

# Secondary bait, same reasoning as the rule above. No process listens on 80;
# inbound SYNs are counted by a netfilter LOG rule on the host, so
# opportunistic HTTP scanning shows up as telemetry instead of being invisible.
# tfsec:ignore:aws-vpc-no-public-ingress-acl
resource "aws_network_acl_rule" "in_http_bait" {
  network_acl_id = aws_network_acl.honeypot.id
  rule_number    = 110
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = var.http_bait_port
  to_port        = var.http_bait_port
}

# The operator's only way in. Restricted to a single CIDR at the subnet
# boundary as well as at the security group, so a security-group misedit
# cannot by itself expose the real sshd.
resource "aws_network_acl_rule" "in_admin_ssh" {
  network_acl_id = aws_network_acl.honeypot.id
  rule_number    = 120
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = var.admin_cidr
  from_port      = var.admin_ssh_port
  to_port        = var.admin_ssh_port
}

# --- Inbound denies, evaluated before the ephemeral allow ------------------
#
# These two rules exist because of an ordering trap that is easy to miss and
# quietly undoes the rule above.
#
# NACL rules are evaluated in ascending order and the first match wins. Rule
# 200 below has to allow inbound TCP 1024-65535 so that replies to the host's
# own outbound connections get back in (stateless NACLs, see the section
# header). But 62222 and 2222 are both inside 1024-65535 - so without these
# denies, rule 200 would match a connection to the admin port from ANY source
# address and the admin_cidr restriction in rule 120 would apply to nothing.
# The operator would believe the real sshd was restricted at two layers when
# it was restricted at one.
#
# Placing the denies between 120 and 200 fixes it: the operator's address
# matches the allow at 120, everyone else matches a deny, and genuine
# ephemeral return traffic still matches 200.
#
# This is safe for return traffic because Linux's default ephemeral source
# port range is 32768-60999. Neither denied port falls inside it, so the
# kernel will never choose one as the source port of an outbound connection
# and have the reply blocked.

resource "aws_network_acl_rule" "in_deny_admin_from_internet" {
  network_acl_id = aws_network_acl.honeypot.id
  rule_number    = 130
  egress         = false
  protocol       = "tcp"
  rule_action    = "deny"
  cidr_block     = "0.0.0.0/0"
  from_port      = var.admin_ssh_port
  to_port        = var.admin_ssh_port
}

# Cowrie is reachable only through the netfilter REDIRECT from port 22. That
# rewrite happens on the host, after the NACL has already seen the packet with
# destination port 22, so denying 2222 at the subnet boundary costs nothing and
# closes the direct path. The literal must match listen_endpoints in
# cowrie/cowrie.cfg; the two change together or not at all.
resource "aws_network_acl_rule" "in_deny_cowrie_direct" {
  network_acl_id = aws_network_acl.honeypot.id
  rule_number    = 140
  egress         = false
  protocol       = "tcp"
  rule_action    = "deny"
  cidr_block     = "0.0.0.0/0"
  from_port      = 2222
  to_port        = 2222
}

# --- Inbound ephemeral returns ---------------------------------------------

# Return traffic for the host's own outbound 443/53 connections. Unavoidable
# at this layer: NACLs are stateless, so without it the CloudWatch agent's TLS
# handshakes never complete and no telemetry is ever delivered. The stateful
# security group is what actually constrains where the instance may connect.
# tfsec:ignore:aws-vpc-no-public-ingress-acl
resource "aws_network_acl_rule" "in_ephemeral_tcp" {
  network_acl_id = aws_network_acl.honeypot.id
  rule_number    = 200
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 1024
  to_port        = 65535
}

# DNS responses, which arrive on an ephemeral source port. Same
# stateless-NACL reasoning as the TCP rule above.
# tfsec:ignore:aws-vpc-no-public-ingress-acl
resource "aws_network_acl_rule" "in_ephemeral_udp" {
  network_acl_id = aws_network_acl.honeypot.id
  rule_number    = 210
  egress         = false
  protocol       = "udp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 1024
  to_port        = 65535
}

# There is no catch-all allow. Anything not matched above hits the implicit
# deny at rule 32767 and is dropped.

# --- Outbound ------------------------------------------------------------

# HTTPS is the only application egress the host needs: CloudWatch Logs, S3,
# the Ubuntu archive (rewritten to https during bootstrap for exactly this
# reason), PyPI and GitHub for the Cowrie install. Note what is NOT here:
# port 80 outbound is absent, which is why the bootstrap must not rely on
# plain-HTTP apt mirrors.
resource "aws_network_acl_rule" "out_https" {
  network_acl_id = aws_network_acl.honeypot.id
  rule_number    = 100
  egress         = true
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 443
  to_port        = 443
}

# DNS over TCP - used for responses too large for UDP.
resource "aws_network_acl_rule" "out_dns_tcp" {
  network_acl_id = aws_network_acl.honeypot.id
  rule_number    = 110
  egress         = true
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 53
  to_port        = 53
}

# DNS over UDP - the normal path. Resolution goes to the VPC resolver at
# .2 inside the VPC, but is allowed broadly because the resolver reply path
# and any systemd-resolved fallback both need it.
resource "aws_network_acl_rule" "out_dns_udp" {
  network_acl_id = aws_network_acl.honeypot.id
  rule_number    = 120
  egress         = true
  protocol       = "udp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 53
  to_port        = 53
}

# Replies to inbound connections on 22/80/62222. Stateless NACLs cannot tell
# a reply from a new connection, so this range is unavoidable at this layer.
# It is not an egress path for an attacker: the stateful security group is
# evaluated first for instance-originated traffic and permits no new outbound
# connection to a high port. See the long comment at the top of this section.
resource "aws_network_acl_rule" "out_ephemeral_tcp" {
  network_acl_id = aws_network_acl.honeypot.id
  rule_number    = 200
  egress         = true
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 1024
  to_port        = 65535
}

# Deliberately absent from egress: ICMP (no outbound ping sweeps), UDP
# ephemeral (no UDP reflection/amplification participation), 25 (no spam),
# 6667 (no IRC C2), and every other port. Anything not listed is denied.
