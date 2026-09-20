# ---------------------------------------------------------------------------
# Input variables.
#
# Two variables deliberately have NO default: admin_cidr and owner_contact.
# Defaulting an administrative source range is how honeypots end up with
# 0.0.0.0/0 on the real SSH port. Terraform will refuse to plan until the
# operator states them explicitly.
# ---------------------------------------------------------------------------

variable "aws_region" {
  description = "AWS region for the deployment. Billing metrics only exist in us-east-1, so the billing alarm assumes this region."
  type        = string
  default     = "us-east-1"
}

variable "project" {
  description = "Short name used as a prefix for resource names and tags."
  type        = string
  default     = "cloudpot"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,20}$", var.project))
    error_message = "project must be 3-21 chars, lowercase alphanumeric or hyphen, starting with a letter (S3 bucket naming)."
  }
}

variable "admin_cidr" {
  description = "Source CIDR allowed to reach the real sshd on the admin port. Must be a single operator address, never 0.0.0.0/0."
  type        = string

  # Security rationale: the whole design depends on exactly one path to the
  # real sshd. A wide-open admin CIDR turns the management port into a second
  # attack surface that is NOT inside Cowrie's jail. Refuse to build it.
  validation {
    condition     = var.admin_cidr != "0.0.0.0/0" && can(cidrhost(var.admin_cidr, 0))
    error_message = "admin_cidr must be a valid CIDR and must not be 0.0.0.0/0. Use your own /32."
  }
}

variable "owner_contact" {
  description = "Email or handle tagged on every resource, so the operator of an internet-exposed host is identifiable from the account."
  type        = string
}

variable "alert_email" {
  description = "Email subscribed to the SNS alarm topic. Leave empty to create the topic without a subscription."
  type        = string
  default     = ""
}

variable "vpc_cidr" {
  description = "CIDR for the dedicated honeypot VPC. Deliberately an unusual range so it never overlaps a real network during a future peering mistake."
  type        = string
  default     = "10.42.0.0/16"
}

variable "public_subnet_cidr" {
  description = "CIDR for the single public subnet holding the honeypot."
  type        = string
  default     = "10.42.1.0/24"
}

variable "availability_zone" {
  description = "AZ for the public subnet. Single-AZ is intentional: a honeypot has no availability requirement."
  type        = string
  default     = "us-east-1a"
}

variable "instance_type" {
  description = "Instance type. t3.micro is sufficient for Cowrie's shell emulation and keeps the weekly cost near the free-tier boundary."
  type        = string
  default     = "t3.micro"
}

variable "admin_ssh_port" {
  description = "Port the REAL sshd is moved to during bootstrap, freeing 22 for Cowrie. Changing this without changing the security group locks you out."
  type        = number
  default     = 62222

  validation {
    condition     = var.admin_ssh_port > 1024 && var.admin_ssh_port < 65536 && var.admin_ssh_port != 2222
    error_message = "admin_ssh_port must be a high port and must not be 2222 (that is Cowrie's listener)."
  }
}

variable "sensor_hostname" {
  description = "Hostname presented to the attacker by Cowrie. A boring production-looking name gets better engagement than 'honeypot'."
  type        = string
  default     = "svr-prod-01"
}

variable "cowrie_ref" {
  description = "Git ref of Cowrie to install. Pin this to a release tag you have reviewed before a real run; 'master' is convenient but not reproducible."
  type        = string
  default     = "master"
}

variable "log_group_name" {
  description = "CloudWatch Logs group receiving Cowrie JSON. IAM is scoped to exactly this group."
  type        = string
  default     = "/cloudpot/cowrie"
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention. Short by design: S3 is the system of record, CloudWatch is the live tail."
  type        = number
  default     = 14
}

variable "s3_log_prefix" {
  description = "Key prefix inside the telemetry bucket for Cowrie JSON. IAM s3:PutObject is scoped to this prefix only."
  type        = string
  default     = "cowrie"
}

variable "billing_alarm_threshold_usd" {
  description = "Estimated-charges threshold that trips the billing alarm."
  type        = number
  default     = 20
}

variable "ssh_bait_port" {
  description = "Port presented to the internet as the SSH bait and redirected to Cowrie."
  type        = number
  default     = 22
}

variable "http_bait_port" {
  description = "Secondary bait port. Nothing listens on it; inbound SYNs are logged by netfilter for scan telemetry."
  type        = number
  default     = 80
}
