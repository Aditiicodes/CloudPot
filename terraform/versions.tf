# ---------------------------------------------------------------------------
# Provider and version pinning.
#
# Security rationale: an unpinned provider is a supply-chain risk. A minor
# provider bump can silently change a default (for example, the default egress
# rule behaviour of aws_security_group), and on a host that is deliberately
# exposed to the internet a silent default change is a real incident. We pin
# the major version and let the lockfile (.terraform.lock.hcl) pin the exact
# build and its hashes.
# ---------------------------------------------------------------------------

terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  # Every resource is tagged. This is not cosmetic:
  #   - Purpose/Contact make the intent of an internet-exposed host obvious to
  #     anyone auditing the account, including AWS Trust & Safety if they ever
  #     ask about traffic originating from this VPC (see docs/SAFETY.md).
  #   - ManagedBy=Terraform tells a future operator not to click-fix this in
  #     the console; the teardown path is `terraform destroy`.
  default_tags {
    tags = {
      Project   = "CloudPot"
      Purpose   = "SecurityResearch-SSHHoneypot"
      ManagedBy = "Terraform"
      Contact   = var.owner_contact
    }
  }
}

# Account/region/partition are resolved rather than hardcoded so that IAM
# policy ARNs below can be built explicitly instead of reaching for wildcards.
data "aws_caller_identity" "current" {}
# Region is read rather than taken from var.aws_region so that the IAM and
# bucket-policy ARNs below always match the region the provider actually
# resolved to, even if it came from an environment variable.
data "aws_region" "current" {}
# Partition, so the hand-built ARNs are correct in GovCloud and China as well
# as aws. Hardcoding "aws" is the most common way a policy silently matches
# nothing in another partition.
data "aws_partition" "current" {}
