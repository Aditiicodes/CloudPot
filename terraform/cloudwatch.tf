# ---------------------------------------------------------------------------
# CloudWatch: live telemetry and the cost circuit breaker.
#
# Security rationale for shipping logs off-box at all: Cowrie writes its JSON
# to local disk. If an attacker escapes the emulated shell, local logs are
# attacker-controlled - they can be truncated or rewritten. Streaming each
# line to CloudWatch within seconds means the evidence is out of the
# attacker's reach almost as soon as it is generated. The local copy is a
# convenience; the CloudWatch and S3 copies are the record.
# ---------------------------------------------------------------------------

# Accepted: CMK encryption on the log group would add a KMS key, a key policy
# the CloudWatch Logs service principal must appear in, and per-request
# charges on a high-volume ingest path. The contents are attacker traffic
# against a disposable host, and the group is already account-private with a
# 14-day retention.
# tfsec:ignore:aws-cloudwatch-log-group-customer-key
resource "aws_cloudwatch_log_group" "cowrie" {
  name = var.log_group_name

  # 14 days, deliberately short. CloudWatch Logs is the expensive tier
  # ($0.50/GB ingest, $0.03/GB-month stored) and is used here as a live tail
  # and alarm source, not as an archive. S3 holds the long-lived copy at a
  # fraction of the storage price. A honeypot on an open port can produce a
  # surprising volume of log lines, so leaving retention at "never expire" is
  # a real cost risk.
  retention_in_days = var.log_retention_days

  tags = { Name = "${var.project}-cowrie-logs" }
}

# ---------------------------------------------------------------------------
# Archive to S3.
#
# Terraform has no resource for a recurring CloudWatch Logs export - the API
# call (logs:CreateExportTask) is a one-shot job, not a piece of persistent
# infrastructure, so there is nothing for Terraform to own. What Terraform
# provides here is the permission surface that makes the export possible: the
# bucket policy statements in s3.tf, and the log group itself.
#
# The export is invoked from the operator side, one day per task, into a
# Hive-style prefix so Athena's partition projection can read it directly:
#
#   make export DAY=2026-03-14
#
# In parallel, the instance uploads its own rotated cowrie.json to the same
# layout each night (see cowrie/userdata.sh). Two independent paths to S3 is
# intentional: if the CloudWatch agent breaks, the nightly upload still lands
# the data, and if the instance is destroyed mid-run the CloudWatch copy is
# already off-box. Neither path can delete what the other wrote.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Alarms.
# ---------------------------------------------------------------------------

# Accepted, and worth reading before "fixing" it. Encrypting an SNS topic that
# CloudWatch alarms publish to is not a one-line change: the AWS-managed key
# alias/aws/sns does not grant kms:GenerateDataKey to cloudwatch.amazonaws.com,
# so alarms silently fail to publish and you discover it the month the bill
# arrives. Doing it properly needs a customer-managed key with a key policy
# naming the CloudWatch service principal. The messages carried here are
# "estimated charges exceeded $20" and "log ingest stopped" - no attacker
# data, no secrets - so that machinery is not worth a silently-broken alarm.
# tfsec:ignore:aws-sns-enable-topic-encryption
resource "aws_sns_topic" "alerts" {
  name = "${var.project}-alerts"

  tags = { Name = "${var.project}-alerts" }
}

# Only the account's own CloudWatch alarms may publish. Pinning the service
# principal and the source account closes the confused-deputy path where
# another account's alarm is pointed at this topic.
data "aws_iam_policy_document" "alerts_topic" {
  statement {
    sid     = "AllowCloudWatchAlarmsToPublish"
    effect  = "Allow"
    actions = ["SNS:Publish"]

    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }

    resources = [aws_sns_topic.alerts.arn]

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

# Replaces the permissive default topic policy with the single statement
# above, so only this account's CloudWatch alarms can publish here.
resource "aws_sns_topic_policy" "alerts" {
  arn    = aws_sns_topic.alerts.arn
  policy = data.aws_iam_policy_document.alerts_topic.json
}

# Email subscription requires a click-through confirmation from the operator;
# Terraform shows the subscription as pending until then. Created only if an
# address was supplied, so the configuration still applies cleanly without.
resource "aws_sns_topic_subscription" "alerts_email" {
  count = var.alert_email == "" ? 0 : 1

  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# The cost circuit breaker. A honeypot is an uncapped-ingress machine: a
# single aggressive scanner can multiply log volume by an order of magnitude
# overnight, and CloudWatch ingest scales directly with it. This alarm exists
# so the first sign of that is an email, not a monthly invoice.
#
# Note the region: AWS/Billing EstimatedCharges is only published in us-east-1,
# which this deployment already uses. Running the honeypot elsewhere would
# require a second provider alias pinned to us-east-1 for this alarm alone.
resource "aws_cloudwatch_metric_alarm" "billing" {
  alarm_name          = "${var.project}-estimated-charges-over-${var.billing_alarm_threshold_usd}-usd"
  alarm_description   = "Account estimated charges exceeded the CloudPot budget. Check Cost Explorer, then consider make destroy."
  namespace           = "AWS/Billing"
  metric_name         = "EstimatedCharges"
  dimensions          = { Currency = "USD" }
  statistic           = "Maximum"
  period              = 21600 # Billing metrics update roughly every 6 hours.
  evaluation_periods  = 1
  threshold           = var.billing_alarm_threshold_usd
  comparison_operator = "GreaterThanThreshold"

  # Missing data is normal early in a billing cycle and must not page.
  treat_missing_data = "notBreaching"

  alarm_actions = [aws_sns_topic.alerts.arn]

  tags = { Name = "${var.project}-billing-alarm" }
}

# Pipeline health. A honeypot that has silently stopped shipping logs looks
# exactly like a honeypot nobody attacked, and the two are indistinguishable
# from the analysis side. Alarming on zero ingest for two consecutive hours
# catches a dead agent, a crashed Cowrie, or an instance that failed to boot,
# and makes "no activity in this window" a trustworthy statement rather than
# a guess.
resource "aws_cloudwatch_metric_alarm" "no_telemetry" {
  alarm_name          = "${var.project}-no-log-ingest"
  alarm_description   = "No Cowrie log events ingested for 2 hours. The sensor is probably down, not idle."
  namespace           = "AWS/Logs"
  metric_name         = "IncomingLogEvents"
  dimensions          = { LogGroupName = aws_cloudwatch_log_group.cowrie.name }
  statistic           = "Sum"
  period              = 3600
  evaluation_periods  = 2
  threshold           = 0
  comparison_operator = "LessThanOrEqualToThreshold"

  # The metric is simply absent when nothing is ingested, so absence is the
  # very condition being alarmed on.
  treat_missing_data = "breaching"

  alarm_actions = [aws_sns_topic.alerts.arn]

  tags = { Name = "${var.project}-telemetry-health-alarm" }
}
