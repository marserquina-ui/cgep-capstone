#!/usr/bin/env bash
# policy-gate.sh — Conftest gate for the HIPAA Rego suite.
# Runs all policies against a Terraform plan JSON, writes JSON evidence,
# and fails closed (non-zero exit) if any policy denies.
#
# Usage: ./policy-gate.sh <plan.json> [evidence-output.json]
set -euo pipefail

PLAN="${1:-terraform/plan.json}"
EVIDENCE="${2:-policy-results.json}"
POLICY_DIR="$(dirname "$0")"

echo "Running HIPAA policy gate against: $PLAN"

# Capture JSON evidence. Conftest exits non-zero on any failure, which would
# abort this script before we save the file — so suppress that exit with
# '|| true' and decide pass/fail from the captured results afterward.
conftest test "$PLAN" \
	--policy "$POLICY_DIR" \
	--all-namespaces \
	--output json > "$EVIDENCE" || true

echo "Evidence written to: $EVIDENCE"

# Decide exit code from the evidence: sum failures across all results.
FAILURES=$(python3 -c "import json,sys; d=json.load(open('$EVIDENCE')); print(sum(len(r.get('failures',[])) for r in d))")

if [ "$FAILURES" -gt 0 ]; then
	echo "POLICY GATE FAILED: $FAILURES violation(s). See $EVIDENCE."
	exit 1
fi

echo "POLICY GATE PASSED: 0 violations."
exit 0
