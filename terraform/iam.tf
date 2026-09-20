# ---------------------------------------------------------------------------
# Instance role.
#
# Security rationale: this role is attached to a machine we expect to be
# compromised. Anything it can do, an attacker who escapes Cowrie can do, by
# reading the credentials from IMDS. So the design question is not "what does
# the agent need?" but "what is the worst an attacker can do with exactly
# this?" The answer here is: append log events to one log group, and write
# objects under one S3 prefix. They cannot read the telemetry back, cannot
# delete it, cannot enumerate the bucket, cannot describe any EC2 resource,
# and cannot reach any other service.
#
# There are no AWS managed policies attached anywhere in this file. Managed
# policies such as CloudWatchAgentServerPolicy and AmazonSSMManagedInstanceCore
# contain "Resource": "*" statements; attaching one would hand the attacker
# account-wide log and SSM reach, which is the opposite of the intent.
# ---------------------------------------------------------------------------

# ARNs are constructed explicitly rather than taken from resource attributes,
# because aws_cloudwatch_log_group.arn already carries a trailing ":*" and
# mixing that with an explicit ":log-stream:*" suffix produces a policy that
# silently matches nothing.
locals {
  log_group_arn  = "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:${var.log_group_name}"
  log_stream_arn = "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:${var.log_group_name}:log-stream:*"
  s3_object_arn  = "${aws_s3_bucket.telemetry.arn}/${var.s3_log_prefix}/*"
}

# Trust policy: only the EC2 service may assume this role, and only through
# the instance profile below. No cross-account trust, no external ID, no human
# principals.
data "aws_iam_policy_document" "assume_ec2" {
  statement {
    sid     = "AllowEC2InstanceAssumeRole"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

# The role an attacker inherits if they escape Cowrie and read IMDS. Its only
# permissions are the single inline policy below.
resource "aws_iam_role" "honeypot" {
  name               = "${var.project}-instance-role"
  description        = "Write-only telemetry role for the CloudPot honeypot instance"
  assume_role_policy = data.aws_iam_policy_document.assume_ec2.json

  # No aws_iam_role_policy_attachment resources exist for this role anywhere
  # in the configuration. The only permissions it has are the inline policy
  # below. If a future operator attaches a managed policy in the console to
  # "just get it working", that is a drift finding, not a fix.

  tags = { Name = "${var.project}-instance-role" }
}

# The complete permission set for the instance. Written as a policy document
# data source rather than a JSON heredoc so Terraform validates the structure
# at plan time - a typo in a JSON action string is otherwise only discovered
# when the agent starts failing in production.
data "aws_iam_policy_document" "telemetry_write" {
  # --- CloudWatch Logs -----------------------------------------------------

  # Scoped to the single log group created in cloudwatch.tf. The wildcard is
  # on the log-stream segment only, which is unavoidable: the CloudWatch agent
  # names streams after the instance ID and we do not know it until after the
  # instance exists. It is a wildcard within one log group, not across log
  # groups, so an attacker cannot write into or discover any other group.
  statement {
    sid    = "AppendToCowrieLogGroupOnly"
    effect = "Allow"

    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      # Required by the CloudWatch agent to resume a stream after a restart
      # (it reads the stream's last state). This is a documented deviation
      # from a pure CreateLogStream+PutLogEvents policy: without it the agent
      # logs an AccessDenied on startup and stops shipping. Read-only, and
      # scoped to this group.
      "logs:DescribeLogStreams",
    ]

    resources = [
      local.log_group_arn,
      local.log_stream_arn,
    ]
  }

  # Deliberately NOT granted: logs:CreateLogGroup. The group is created by
  # Terraform with a retention policy already set. If the instance could
  # create groups, an attacker could create one without retention and bill the
  # account indefinitely, and the agent could silently ship to the wrong place
  # if the group name were ever mistyped - instead it fails loudly.

  # --- S3 ------------------------------------------------------------------

  # Write-only, single prefix. PutObject covers both simple puts and the parts
  # of a multipart upload; AbortMultipartUpload lets the CLI clean up after a
  # network failure instead of leaving billable orphaned parts.
  #
  # Not granted, on purpose: s3:GetObject (an attacker cannot read back what
  # earlier attackers did), s3:ListBucket (they cannot enumerate the evidence),
  # s3:DeleteObject and s3:DeleteObjectVersion (they cannot destroy it).
  # Accepted: the wildcard is on the object KEY, not on the bucket and not on
  # the action. S3 has no way to express "any object under this prefix"
  # without it, and the alternative - naming every future daily object - is
  # not expressible before those objects exist. The grant is still
  # write-only: no Get, no List, no Delete. See the note below.
  # tfsec:ignore:aws-iam-no-policy-wildcards
  statement {
    sid    = "WriteOnlyToCowriePrefix"
    effect = "Allow"

    actions = [
      "s3:PutObject",
      "s3:AbortMultipartUpload",
    ]

    resources = [local.s3_object_arn]
  }
}

# Inline rather than a managed policy, deliberately: an inline policy cannot
# be attached to another principal by accident, and it is deleted with the
# role instead of lingering in the account after teardown.
resource "aws_iam_role_policy" "telemetry_write" {
  name   = "${var.project}-telemetry-write"
  role   = aws_iam_role.honeypot.id
  policy = data.aws_iam_policy_document.telemetry_write.json
}

# The only way the role reaches the instance. Nothing else in the account is
# permitted to assume it - see the trust policy above.
resource "aws_iam_instance_profile" "honeypot" {
  name = "${var.project}-instance-profile"
  role = aws_iam_role.honeypot.name
}
