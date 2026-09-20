# ---------------------------------------------------------------------------
# Telemetry bucket - the system of record.
#
# Security rationale: CloudWatch Logs is the live view and expires in 14 days.
# S3 is where the evidence actually lives, so it gets the durability and
# integrity controls: versioning (an overwrite does not destroy the original),
# encryption at rest, a hard public-access block, and a bucket policy that
# refuses plaintext transport. The honeypot instance can write here and can do
# nothing else here - no list, no get, no delete.
# ---------------------------------------------------------------------------

# Accepted: server access logging would need a third bucket (self-logging
# creates a delivery loop AWS explicitly warns against), which is another
# public-access surface and another lifecycle policy to keep honest. This
# bucket has exactly two writers, both enumerated in iam.tf and s3.tf, and
# CloudTrail S3 data events are the right tool if per-object auditing is ever
# needed - at a cost this project does not carry.
# tfsec:ignore:aws-s3-enable-bucket-logging
resource "aws_s3_bucket" "telemetry" {
  # Account ID suffix because S3 bucket names are globally unique. Using the
  # account ID rather than a random suffix keeps the name stable across
  # destroy/apply cycles, which matters because the Athena table LOCATION is
  # written by hand.
  bucket = "${var.project}-telemetry-${data.aws_caller_identity.current.account_id}"

  # NOT force_destroy. Deleting a bucket full of attack telemetry should
  # require a deliberate `make empty-bucket` step, not a stray destroy. See
  # docs/TEARDOWN.md.
  tags = { Name = "${var.project}-telemetry" }
}

# Block public access at the bucket level, all four flags. This is belt and
# braces against the policy below being edited badly later: even a policy that
# grants Principal "*" cannot make an object public while these are set.
resource "aws_s3_bucket_public_access_block" "telemetry" {
  bucket                  = aws_s3_bucket.telemetry.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ACLs disabled. Object ownership is unconditional, so there is no way for a
# writer to hand ownership of evidence to another account.
resource "aws_s3_bucket_ownership_controls" "telemetry" {
  bucket = aws_s3_bucket.telemetry.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# Versioning is an integrity control here, not a convenience one. If the
# instance is compromised and the attacker uses the instance credentials to
# overwrite a day of logs with garbage, the original object version survives
# and the PutObject-only policy gives them no way to delete it.
resource "aws_s3_bucket_versioning" "telemetry" {
  bucket = aws_s3_bucket.telemetry.id

  versioning_configuration {
    status = "Enabled"
  }
}

# SSE-S3 rather than SSE-KMS: the data is attacker-generated public-internet
# noise, not secrets, and KMS would add per-request cost and a key policy to
# maintain for no meaningful gain. Encryption at rest is still mandatory so
# that a future bucket-level mistake does not expose plaintext.
# Accepted: SSE-S3 rather than a customer-managed KMS key. The contents are
# attacker-generated public-internet noise, not secrets. A CMK would add
# ~$1/month, per-request KMS charges on every log object, and a key policy to
# maintain, in exchange for key-level access auditing nobody will read.
# tfsec:ignore:aws-s3-encryption-customer-key
resource "aws_s3_bucket_server_side_encryption_configuration" "telemetry" {
  bucket = aws_s3_bucket.telemetry.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

# Cost and data-retention policy in one place. 180-day expiry is the stated
# retention commitment in docs/SAFETY.md - attacker source IPs are arguably
# personal data in some jurisdictions, so "keep it forever" is not a neutral
# default.
resource "aws_s3_bucket_lifecycle_configuration" "telemetry" {
  bucket     = aws_s3_bucket.telemetry.id
  depends_on = [aws_s3_bucket_versioning.telemetry]

  rule {
    id     = "cowrie-telemetry-tiering"
    status = "Enabled"

    filter {}

    # Analysis happens in the first few weeks; after that the data is archive.
    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    expiration {
      days = 180
    }

    # Versioning is on, so non-current versions need their own expiry or the
    # bucket grows forever and the 180-day retention promise is false.
    noncurrent_version_expiration {
      noncurrent_days = 30
    }

    # A failed multipart upload from the instance would otherwise bill
    # indefinitely for invisible storage.
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# Resource-based controls that apply to every principal, including the
# operator: mandatory TLS, and narrowly-scoped write grants for the two AWS
# services that deliver logs here. Each service statement is conditioned on
# this account, which is what prevents the confused-deputy pattern where a
# log-delivery service is pointed at your bucket from somewhere else.
resource "aws_s3_bucket_policy" "telemetry" {
  bucket = aws_s3_bucket.telemetry.id

  # The public access block must exist first, otherwise applying a policy with
  # a service principal can trip the "public policy" heuristic.
  depends_on = [aws_s3_bucket_public_access_block.telemetry]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # Refuse any request that did not arrive over TLS. The instance role is
      # already scoped tightly, but this makes plaintext transport impossible
      # for every principal, including the operator's own CLI.
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.telemetry.arn,
          "${aws_s3_bucket.telemetry.arn}/*",
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      },

      # VPC Flow Logs delivery. Scoped to the flow-log prefix and conditioned
      # on this account, so the log delivery service cannot be tricked into
      # writing another account's logs into this bucket (the confused-deputy
      # pattern AWS documents for cross-service writes).
      {
        Sid       = "AWSLogDeliveryAclCheck"
        Effect    = "Allow"
        Principal = { Service = "delivery.logs.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.telemetry.arn
        Condition = {
          StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
        }
      },
      {
        Sid       = "AWSLogDeliveryWrite"
        Effect    = "Allow"
        Principal = { Service = "delivery.logs.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.telemetry.arn}/vpc-flow-logs/*"
        Condition = {
          StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
        }
      },

      # CloudWatch Logs export tasks (the archival path documented in the
      # Makefile). Same source-account condition, same prefix scoping.
      {
        Sid       = "CloudWatchLogsExportAclCheck"
        Effect    = "Allow"
        Principal = { Service = "logs.${data.aws_region.current.name}.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.telemetry.arn
        Condition = {
          StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
        }
      },
      {
        Sid       = "CloudWatchLogsExportWrite"
        Effect    = "Allow"
        Principal = { Service = "logs.${data.aws_region.current.name}.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.telemetry.arn}/${var.s3_log_prefix}/*"
        Condition = {
          StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
        }
      },
    ]
  })
}

# Athena needs somewhere to write query results. Separate bucket so that query
# output - which is operator-generated and disposable - never lands in the
# evidence bucket and confuses the Athena table's partition scan.
# Accepted on both counts: Athena query results are derived data. Every object
# here can be regenerated by re-running a query against the telemetry bucket,
# so there is nothing for versioning to protect and nothing whose access
# history matters. It is also why this bucket expires its contents in 30 days.
# tfsec:ignore:aws-s3-enable-bucket-logging
# tfsec:ignore:aws-s3-enable-versioning
resource "aws_s3_bucket" "athena_results" {
  bucket = "${var.project}-athena-results-${data.aws_caller_identity.current.account_id}"
  tags   = { Name = "${var.project}-athena-results" }
}

# Same four flags as the telemetry bucket. Query results are derived from
# attack telemetry and a "temporary" bucket is exactly the kind that gets
# left public.
resource "aws_s3_bucket_public_access_block" "athena_results" {
  bucket                  = aws_s3_bucket.athena_results.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Accepted: same reasoning as the telemetry bucket, and these objects are
# derived from it.
# tfsec:ignore:aws-s3-encryption-customer-key
resource "aws_s3_bucket_server_side_encryption_configuration" "athena_results" {
  bucket = aws_s3_bucket.athena_results.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Query results are regenerable; 30 days is plenty and keeps the bill flat.
resource "aws_s3_bucket_lifecycle_configuration" "athena_results" {
  bucket = aws_s3_bucket.athena_results.id

  rule {
    id     = "expire-query-results"
    status = "Enabled"

    filter {}

    expiration {
      days = 30
    }
  }
}
