# ---------------------------------------------------------------------------
# The sensor itself.
#
# Design posture: this instance is disposable and is expected to be attacked.
# Nothing valuable lives on it, no SSH key of any consequence is placed on it,
# and the recovery procedure for any suspicious behaviour is `terraform
# destroy` followed by `terraform apply`, not incident response on the host.
# Every hardening control below exists to protect the *account*, not the box.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Bootstrap payload.
#
# Two constraints shape this, and both bite before the instance ever boots:
#
# 1. Cowrie's own configuration uses ${...} interpolation (the jsonlog path,
#    for one). Terraform's template parser would evaluate those as Terraform
#    expressions and fail the plan, so the configuration files are passed in
#    as opaque gzip+base64 blobs rather than inlined into the script.
#
# 2. EC2 caps user_data at 16 KB of raw bytes. The bootstrap plus its
#    configuration is roughly 39 KB uncompressed - well over the limit, and
#    AWS rejects it at RunInstances with an error that does not mention the
#    number. Compressing the blobs individually and then gzipping the whole
#    payload brings it to 14832 bytes as of this commit. cloud-init recognises
#    the gzip magic bytes and inflates before executing, so nothing on the
#    instance needs to know any of this happened.
#
# That leaves roughly 1.5 KB of headroom, which is real but not generous -
# hence the precondition on the instance below. If someone adds a few hundred
# lines of comments to cowrie.cfg, they get a named byte count and a
# suggested fix instead of an opaque RunInstances rejection. If you do hit it,
# the answer is to move the configuration into S3 and fetch it at boot,
# accepting the s3:GetObject grant on the instance role that implies.
# ---------------------------------------------------------------------------
locals {
  user_data_rendered = templatefile("${path.module}/../cowrie/userdata.sh", {
    aws_region      = data.aws_region.current.name
    log_group_name  = aws_cloudwatch_log_group.cowrie.name
    s3_bucket       = aws_s3_bucket.telemetry.id
    s3_prefix       = var.s3_log_prefix
    admin_ssh_port  = var.admin_ssh_port
    bait_ssh_port   = var.ssh_bait_port
    http_bait_port  = var.http_bait_port
    sensor_hostname = var.sensor_hostname
    cowrie_ref      = var.cowrie_ref

    cowrie_cfg_b64    = base64gzip(file("${path.module}/../cowrie/cowrie.cfg"))
    cowrie_userdb_b64 = base64gzip(file("${path.module}/../cowrie/userdb.example"))

    # The honeyfs overlay is shipped file-by-file straight from the repo so the
    # emulated /etc on the sensor cannot drift from what is reviewed here.
    # README.md is excluded - it documents the overlay, it is not part of it,
    # and a stray README in the fake /etc is a honeypot tell.
    honeyfs_b64 = {
      for f in fileset("${path.module}/../cowrie/honeyfs", "**") : f => base64gzip(file("${path.module}/../cowrie/honeyfs/${f}"))
      if f != "README.md"
    }
  })

  user_data_payload = base64gzip(local.user_data_rendered)

  # base64 encodes 3 bytes as 4 characters, so the decoded size AWS measures
  # is three quarters of the string length.
  user_data_raw_bytes = floor(length(local.user_data_payload) * 3 / 4)
}

# Canonical's official Ubuntu 22.04 LTS image. The owner filter is the control
# that matters: AMI names are not namespaced, so anyone can publish an image
# called "ubuntu-jammy-22.04-amd64-server-whatever". Pinning owner 099720109477
# (Canonical) is what stops this from being an AMI-confusion supply chain hole.
data "aws_ami" "ubuntu_2204" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

# A stable address for the run. Attack telemetry is only comparable across
# days if the sensor keeps the same IP - a changed IP resets every scanner's
# view of the host and makes "attempts per day" meaningless. An EIP attached
# to a running instance is free; an unattached one is not, which is why
# docs/TEARDOWN.md calls out releasing it.
resource "aws_eip" "honeypot" {
  domain = "vpc"

  tags = { Name = "${var.project}-eip" }
}

# Separate from the allocation so the address survives instance replacement:
# a user_data change replaces the instance, and a sensor that changes IP
# mid-run resets every scanner's view of it and breaks day-over-day
# comparison.
resource "aws_eip_association" "honeypot" {
  instance_id   = aws_instance.honeypot.id
  allocation_id = aws_eip.honeypot.id
}

# The sensor. Every argument below is load-bearing; the comments say which
# threat each one addresses.
resource "aws_instance" "honeypot" {
  ami           = data.aws_ami.ubuntu_2204.id
  instance_type = var.instance_type
  subnet_id     = aws_subnet.public.id

  # Both groups attach to one ENI. Security group rules are a union, so the
  # instance ends up with the bait ports, the admin port, and exactly one
  # egress allowlist. See security_groups.tf for why they are split.
  vpc_security_group_ids = [
    aws_security_group.honeypot.id,
    aws_security_group.admin.id,
  ]

  iam_instance_profile = aws_iam_instance_profile.honeypot.name

  # The public address comes from the EIP association above, not from the
  # subnet's auto-assign behaviour, so the address is a managed resource with
  # its own lifecycle rather than something that changes on every stop/start.
  associate_public_ip_address = false

  # No key pair is attached on purpose. Access to the real sshd is by the key
  # the operator bakes in below through cloud-init's default user, and a
  # honeypot should not have an AWS-managed key pair whose public half is
  # visible in the account's EC2 console next to an internet-facing host.
  # If you prefer a key pair, add key_name here and accept that trade-off
  # knowingly.

  # Detailed monitoring is 1-minute metrics for ~$2.10/instance/month. The
  # alarms in cloudwatch.tf evaluate on hourly and 6-hourly periods, so the
  # extra resolution buys nothing and would be a quarter of the weekly budget.
  monitoring = false

  # IMDSv2 required. This is the single most important instance-level control
  # in the project. IMDSv1 answers an unauthenticated HTTP GET, so any SSRF or
  # any attacker process on the box can read the instance role's temporary
  # credentials with one curl. Requiring the PUT-token handshake defeats the
  # whole class of SSRF-to-credential-theft attacks, and a hop limit of 1 stops
  # a container or a forwarding proxy on the host from relaying to IMDS.
  # Instance tags are kept out of metadata because the tags name the project
  # and the operator's contact, and an attacker should not be able to read
  # "this is a honeypot" from inside the box.
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "disabled"
  }

  root_block_device {
    volume_type = "gp3"
    volume_size = 20

    # Encrypted at rest with the AWS-managed EBS key. Cheap, and it means a
    # snapshot accidentally shared later is not readable without the key
    # grant.
    encrypted = true

    # The volume dies with the instance. Telemetry has already been shipped to
    # CloudWatch and S3, so nothing of value is lost, and it guarantees a
    # destroy does not leave an orphaned volume holding attacker payload
    # fragments and an unnoticed monthly charge.
    delete_on_termination = true

    tags = { Name = "${var.project}-root" }
  }

  # Source/destination checking stays at its default of enabled. Disabling it
  # would let a compromised host forward traffic for other addresses, i.e.
  # act as a router for an attacker.

  # The bootstrap. Order inside this script is security-critical: the real
  # sshd is relocated and verified BEFORE port 22 is handed to Cowrie. See the
  # long comment block at the top of cowrie/userdata.sh.
  #
  # The rendered, compressed bootstrap. See the locals block below for why it
  # is compressed and what guards the size limit.
  user_data_base64 = local.user_data_payload

  # A change to the bootstrap means a new sensor, not a mutated one. Editing a
  # running honeypot in place leaves you unsure which configuration produced
  # which day of data; replacing it keeps the run reproducible.
  user_data_replace_on_change = true

  # Fail with a legible message, not an opaque API error, if the bootstrap
  # has outgrown what EC2 will accept.
  lifecycle {
    precondition {
      condition     = local.user_data_raw_bytes < 16384
      error_message = "Compressed user_data is ${local.user_data_raw_bytes} bytes; EC2 allows 16384. Trim cowrie/userdata.sh or move the config files to S3 and fetch them at boot."
    }
  }

  # The log group and bucket policy must exist before first boot, otherwise
  # the agent's first PutLogEvents and the first upload fail and the operator
  # spends an hour debugging IAM that is actually a race.
  depends_on = [
    aws_cloudwatch_log_group.cowrie,
    aws_iam_role_policy.telemetry_write,
    aws_s3_bucket_policy.telemetry,
  ]

  tags = {
    Name = "${var.project}-sensor"
    Role = "cowrie-ssh-honeypot"
  }
}
