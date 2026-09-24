#!/bin/sh
set -e

echo "=== Initializing LocalStack S3 Resources ==="

# Create Quarantine Storage bucket
awslocal s3 mb s3://sug-quarantine-local

# Enable versioning on Quarantine Storage bucket (mandatory for artifact binding)
awslocal s3api put-bucket-versioning \
  --bucket sug-quarantine-local \
  --versioning-configuration Status=Enabled

echo "=== S3 Initialization Complete: sug-quarantine-local (Versioning: Enabled) ==="
