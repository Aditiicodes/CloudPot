# Teardown

Destroy in this order. Skipping steps leaves either your data or your bill
behind.

---

## 1. Get the data off first

`terraform destroy` terminates the instance, and the root volume is set to
delete on termination. Anything not already shipped is gone.

```bash
# Flush whatever has rotated but not yet uploaded.
ssh -p 62222 ubuntu@$(terraform -chdir=terraform output -raw honeypot_public_ip) \
  'sudo /usr/local/bin/cloudpot-ship-logs.sh'
```

The shipper only handles *rotated* files (`cowrie.json.YYYY-MM-DD`). The
current day's `cowrie.json` is still open and will not be sent. If the last
day matters, copy it down directly:

```bash
scp -P 62222 ubuntu@<ip>:/opt/cowrie/var/log/cowrie/cowrie.json \
  findings/raw/cowrie.json.$(date -u +%F)
```

Then sync everything from S3 and confirm you have it:

```bash
make fetch
ls findings/raw/
```

The live CloudWatch stream is a third copy, and it survives the instance —
but it expires after 14 days, so it is a safety net, not the archive.

**Optional: archive the CloudWatch copy to S3** before retention expires.

```bash
make export DAY=2026-03-14      # repeat per day
```

---

## 2. Destroy the infrastructure

```bash
make destroy          # or: terraform -chdir=terraform destroy
```

Terraform tears down in dependency order. Expect it to take 2–4 minutes; the
Elastic IP disassociation and the ENI detach are the slow parts.

**The S3 buckets are not destroyed.** `force_destroy` is deliberately not set
on the telemetry bucket: deleting a bucket full of attack telemetry should be
a decision, not a side effect of a command you ran to stop paying for an
instance. Terraform will report an error if the bucket is not empty, which is
the intended behaviour.

---

## 3. Empty the buckets — only when you are sure

**This is irreversible.** Confirm `findings/raw/` holds what you need first.

Versioning is enabled, so deleting objects is not enough — every version and
every delete marker has to go, or the bucket will not delete and you will keep
paying for storage you cannot see in the console's default view.

```bash
BUCKET=$(terraform -chdir=terraform output -raw telemetry_bucket)

# Current objects.
aws s3 rm "s3://$BUCKET" --recursive

# Versions and delete markers.
aws s3api list-object-versions --bucket "$BUCKET" \
  --query '{Objects: Versions[].{Key:Key,VersionId:VersionId}}' --output json \
  > /tmp/versions.json
aws s3api delete-objects --bucket "$BUCKET" --delete file:///tmp/versions.json

aws s3api list-object-versions --bucket "$BUCKET" \
  --query '{Objects: DeleteMarkers[].{Key:Key,VersionId:VersionId}}' --output json \
  > /tmp/markers.json
aws s3api delete-objects --bucket "$BUCKET" --delete file:///tmp/markers.json

aws s3api delete-bucket --bucket "$BUCKET"
```

Repeat for the Athena results bucket (`terraform output -raw
athena_results_s3_uri`), which is unversioned and needs only the first command.

If you would rather leave the data in place, do nothing — the lifecycle rule
expires it at 180 days. Storage for a week of telemetry is cents per month.

---

## 4. Verify nothing is still running

Terraform only knows about what it created. Check for orphans:

```bash
REGION=us-east-1

# An unattached Elastic IP bills ~$3.60/month for existing.
aws ec2 describe-addresses --region $REGION \
  --query 'Addresses[?AssociationId==`null`].[PublicIp,AllocationId]' --output table

# Volumes that outlived their instance.
aws ec2 describe-volumes --region $REGION \
  --filters Name=status,Values=available --query 'Volumes[].[VolumeId,Size]' --output table

# Snapshots, if you took one during an incident.
aws ec2 describe-snapshots --owner-ids self --region $REGION \
  --query 'Snapshots[].[SnapshotId,VolumeSize,StartTime]' --output table

# Log groups (Terraform removes /cloudpot/cowrie; a stray one means the agent
# created it, which the instance role should not have permitted).
aws logs describe-log-groups --region $REGION \
  --log-group-name-prefix /cloudpot --query 'logGroups[].logGroupName'

# The alarms and topic.
aws cloudwatch describe-alarms --region $REGION \
  --alarm-name-prefix cloudpot --query 'MetricAlarms[].AlarmName'
```

The unattached Elastic IP is the one that catches people out: it is free while
attached to a running instance and billed once it is not.

---

## 5. Confirm the spend

Billing data lags by up to 24 hours, so check the day after.

1. **Cost Explorer** → filter `Tag: Project = CloudPot` → group by service.
   Every resource carries that tag via `default_tags`, so the total is exact
   rather than estimated.
2. Compare against the ~$9/week estimate in [SETUP.md](SETUP.md). The line
   that most often overruns is CloudWatch Logs ingest, which scales with how
   hard you were scanned.
3. Check that the daily cost has actually gone to zero. A cost that persists
   after teardown means an orphan from step 4.
4. **Delete the billing alarm and SNS topic** if you are not redeploying —
   `terraform destroy` handles both, but confirm the email subscription is
   gone so a future unrelated spend does not page you about CloudPot.

---

## 6. Repository hygiene

```bash
git status --short
```

Nothing in this list should be committed — `.gitignore` covers all of it, but
check rather than trust:

- `terraform/terraform.tfvars` — contains your home IP address.
- `terraform/*.tfstate*` — contains every resource attribute.
- `findings/raw/` — a week of unreviewed raw telemetry.
- `analysis/figures/*.png` — regenerable from the data.
- Any `.pem` or key material.

Before publishing the report, re-read the "what must not be published" section
of [SAFETY.md](SAFETY.md).
