#!/bin/sh
# seaweedfs-init.sh
# Wait for SeaweedFS S3 to be ready, create the bucket, enable versioning, apply lifecycle.

set -e

BUCKET="${S3_BUCKET:-kutup-files}"
ENDPOINT="http://seaweedfs-s3:8333"

echo "Waiting for SeaweedFS S3..."
until aws --endpoint-url "$ENDPOINT" s3 ls 2>/dev/null; do
  echo "Retrying in 3s..."
  sleep 3
done

echo "Creating bucket $BUCKET (idempotent)..."
aws --endpoint-url "$ENDPOINT" s3 mb "s3://$BUCKET" --region us-east-1 2>/dev/null || true

echo "Enabling versioning on $BUCKET..."
aws --endpoint-url "$ENDPOINT" s3api put-bucket-versioning \
  --bucket "$BUCKET" \
  --versioning-configuration Status=Enabled

echo "Applying lifecycle configuration..."
aws --endpoint-url "$ENDPOINT" s3api put-bucket-lifecycle-configuration \
  --bucket "$BUCKET" \
  --lifecycle-configuration file:///etc/kutup/lifecycle.json

echo "Bucket ready: $BUCKET, versioning enabled, lifecycle applied."
