#!/bin/sh
# seaweedfs-init.sh
# Wait for SeaweedFS S3 to be ready, create the bucket, apply lifecycle.
# Kutup needs no bucket versioning: every file version is an object of its
# own, and deletes are final either way (docs/self-hosting.md).

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

echo "Applying lifecycle configuration..."
aws --endpoint-url "$ENDPOINT" s3api put-bucket-lifecycle-configuration \
  --bucket "$BUCKET" \
  --lifecycle-configuration file:///etc/kutup/lifecycle.json

echo "Bucket ready: $BUCKET, lifecycle applied."
