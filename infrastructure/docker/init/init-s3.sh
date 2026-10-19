#!/bin/sh
set -e

echo "=== Initializing LocalStack S3 Resources ==="

for bucket in sug-quarantine-local sug-clean-local sug-audit-local; do
  awslocal s3 mb "s3://$bucket" 2>/dev/null || true
  awslocal s3api put-bucket-versioning \
    --bucket "$bucket" \
    --versioning-configuration Status=Enabled || true
done

echo "=== S3 Initialization Complete: sug-quarantine-local, sug-clean-local, sug-audit-local (Versioning: Enabled) ==="
