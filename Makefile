# CloudPot - deploy, collect, analyse, destroy.
#
# Every target that touches AWS reads the bucket and log group names from the
# Terraform outputs rather than from a hardcoded string, so there is one source
# of truth and no way for the analysis to point at last week's bucket.

TF        := terraform -chdir=terraform
PYTHON    := python3
RAW_DIR   := findings/raw
FIG_DIR   := analysis/figures
OUT_DIR   := findings

# Lazy assignment on purpose: these shell out to Terraform, and an eager `:=`
# would run them on every make invocation including `make help`.
BUCKET     = $(shell $(TF) output -raw telemetry_bucket 2>/dev/null)
LOG_GROUP  = $(shell $(TF) output -raw log_group_name 2>/dev/null)
PUBLIC_IP  = $(shell $(TF) output -raw honeypot_public_ip 2>/dev/null)

.DEFAULT_GOAL := help
.PHONY: help init plan deploy destroy fetch parse plot export athena-ddl lint fmt validate clean ssh watch

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

# --- infrastructure -------------------------------------------------------

init: ## terraform init
	$(TF) init

plan: ## terraform plan (read it before applying)
	$(TF) plan

deploy: ## Build the sensor. Requires terraform/terraform.tfvars.
	@test -f terraform/terraform.tfvars || { \
		echo "terraform/terraform.tfvars is missing."; \
		echo "  cp terraform/terraform.tfvars.example terraform/terraform.tfvars"; \
		exit 1; }
	$(TF) init -input=false
	$(TF) apply
	@echo ""
	@echo "Sensor is up. The REAL sshd is on port 62222:"
	@echo "  $$($(TF) output -raw admin_ssh_command)"
	@echo "Port 22 is Cowrie. Connecting there logs you into the dataset."

destroy: ## Tear everything down. Fetch your data FIRST - see docs/TEARDOWN.md.
	@echo "This terminates the sensor. Unshipped logs on the root volume are lost."
	@echo "Run 'make fetch' first if you have not. Buckets are NOT deleted."
	$(TF) destroy

ssh: ## SSH to the real host on the admin port
	ssh -p 62222 ubuntu@$(PUBLIC_IP)

watch: ## Tail the live Cowrie stream from CloudWatch
	aws logs tail $(LOG_GROUP) --follow

# --- collection -----------------------------------------------------------

fetch: ## Sync telemetry from S3 into findings/raw/
	@test -n "$(BUCKET)" || { echo "No telemetry_bucket output. Is the stack deployed?"; exit 1; }
	mkdir -p $(RAW_DIR)
	aws s3 sync s3://$(BUCKET)/cowrie/ $(RAW_DIR)/
	@echo "Synced to $(RAW_DIR)/"

# Archive one day from CloudWatch Logs into the same dt= layout Athena reads.
# Terraform cannot own this: CreateExportTask is a one-shot job, not a resource.
export: ## Export one day of CloudWatch Logs to S3. Usage: make export DAY=2026-03-14
	@test -n "$(DAY)" || { echo "Usage: make export DAY=YYYY-MM-DD"; exit 1; }
	@test -n "$(BUCKET)" || { echo "No telemetry_bucket output. Is the stack deployed?"; exit 1; }
	aws logs create-export-task \
		--log-group-name $(LOG_GROUP) \
		--from $$(( $$(date -u -j -f "%Y-%m-%d" "$(DAY)" +%s 2>/dev/null || date -u -d "$(DAY)" +%s) * 1000 )) \
		--to $$(( ($$(date -u -j -f "%Y-%m-%d" "$(DAY)" +%s 2>/dev/null || date -u -d "$(DAY)" +%s) + 86400) * 1000 )) \
		--destination $(BUCKET) \
		--destination-prefix "cowrie/dt=$(DAY)"

# --- analysis -------------------------------------------------------------

parse: ## Extract indicators -> findings/iocs.csv + findings/summary.json
	$(PYTHON) analysis/parse_cowrie.py --input $(RAW_DIR) --out-dir $(OUT_DIR)

plot: ## Render figures -> analysis/figures/*.png  (needs matplotlib)
	$(PYTHON) analysis/plots.py --input $(RAW_DIR) --out-dir $(FIG_DIR) $(if $(GEO),--geo $(GEO),)

athena-ddl: ## Print create_table.sql with your real bucket name substituted
	@test -n "$(BUCKET)" || { echo "No telemetry_bucket output. Is the stack deployed?"; exit 1; }
	@sed 's|<TELEMETRY_BUCKET>|$(BUCKET)|g' analysis/athena/create_table.sql

# --- quality --------------------------------------------------------------

fmt: ## Rewrite Terraform files to canonical format
	$(TF) fmt -recursive

validate: ## terraform validate (no credentials needed)
	$(TF) init -backend=false -input=false >/dev/null
	$(TF) validate

lint: ## fmt check, validate, tflint, tfsec, python syntax
	$(TF) fmt -check -recursive -diff
	$(TF) init -backend=false -input=false >/dev/null
	$(TF) validate
	@command -v tflint >/dev/null 2>&1 && (cd terraform && tflint --recursive) || echo "tflint not installed - skipped (CI runs it)"
	@command -v tfsec  >/dev/null 2>&1 && tfsec terraform/ || echo "tfsec not installed - skipped (CI runs it)"
	$(PYTHON) -m py_compile analysis/parse_cowrie.py analysis/plots.py
	@echo "lint OK"

clean: ## Remove generated figures and __pycache__ (never touches findings/raw)
	rm -rf $(FIG_DIR) analysis/__pycache__ __pycache__
	@echo "Removed generated artefacts. $(RAW_DIR)/ left alone."
