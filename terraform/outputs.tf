# ---------------------------------------------------------------------------
# Outputs.
#
# Nothing here is marked sensitive because nothing here is a secret - these
# are public addresses and resource names. The admin SSH command is surfaced
# because the single most likely operator error in this project is forgetting
# that the real sshd is no longer on 22.
# ---------------------------------------------------------------------------

output "honeypot_public_ip" {
  description = "Public address of the sensor. This is the IP that appears in attacker-side logs."
  value       = aws_eip.honeypot.public_ip
}

output "admin_ssh_command" {
  description = "How to reach the REAL sshd. Port 22 on this host is Cowrie; connecting there logs you into an emulated shell."
  value       = "ssh -p ${var.admin_ssh_port} ubuntu@${aws_eip.honeypot.public_ip}"
}

output "instance_id" {
  description = "EC2 instance ID, used as the CloudWatch log stream prefix."
  value       = aws_instance.honeypot.id
}

output "log_group_name" {
  description = "CloudWatch Logs group carrying the live Cowrie JSON stream."
  value       = aws_cloudwatch_log_group.cowrie.name
}

output "telemetry_bucket" {
  description = "S3 bucket holding the durable copy of the telemetry."
  value       = aws_s3_bucket.telemetry.id
}

output "telemetry_s3_uri" {
  description = "Base S3 URI for the Cowrie partitions. Paste this into analysis/athena/create_table.sql."
  value       = "s3://${aws_s3_bucket.telemetry.id}/${var.s3_log_prefix}/"
}

output "athena_results_s3_uri" {
  description = "Athena query result location to set in the workgroup or console."
  value       = "s3://${aws_s3_bucket.athena_results.id}/"
}

output "alerts_topic_arn" {
  description = "SNS topic for the billing and telemetry-health alarms. Confirm the email subscription before relying on it."
  value       = aws_sns_topic.alerts.arn
}
