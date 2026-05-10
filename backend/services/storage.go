package services

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

type StorageService struct {
	client *s3.Client
	bucket string
}

func NewStorage(endpoint, accessKey, secretKey, bucket, region string) (*StorageService, error) {
	cfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithRegion(region),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")),
	)
	if err != nil {
		return nil, fmt.Errorf("aws config: %w", err)
	}

	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(endpoint)
		o.UsePathStyle = true // SeaweedFS requires path-style
	})

	return &StorageService{client: client, bucket: bucket}, nil
}

// Upload streams data directly to SeaweedFS — no disk buffering.
func (s *StorageService) Upload(ctx context.Context, path string, body io.Reader, size int64) error {
	_, err := s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(s.bucket),
		Key:           aws.String(path),
		Body:          body,
		ContentLength: aws.Int64(size),
	})
	if err != nil {
		return fmt.Errorf("s3 put: %w", err)
	}
	return nil
}

// PutObjectVersioned puts an object and returns the SeaweedFS version id.
// Bucket must have versioning enabled (see seaweedfs-init.sh / lifecycle.json).
func (s *StorageService) PutObjectVersioned(ctx context.Context, key string, body io.Reader, size int64) (string, error) {
	out, err := s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(s.bucket),
		Key:           aws.String(key),
		Body:          body,
		ContentLength: aws.Int64(size),
	})
	if err != nil {
		return "", err
	}
	if out.VersionId == nil {
		return "", nil // bucket might not have versioning enabled
	}
	return *out.VersionId, nil
}

// PresignedDownload generates a presigned URL valid for 15 minutes.
func (s *StorageService) PresignedDownload(ctx context.Context, path string) (string, error) {
	presigner := s3.NewPresignClient(s.client)
	req, err := presigner.PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(path),
	}, s3.WithPresignExpires(15*time.Minute))
	if err != nil {
		return "", fmt.Errorf("presign: %w", err)
	}
	return req.URL, nil
}

// GetObject fetches an object from SeaweedFS and returns its body and size.
func (s *StorageService) GetObject(ctx context.Context, path string) (io.ReadCloser, int64, error) {
	result, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(path),
	})
	if err != nil {
		return nil, 0, fmt.Errorf("s3 get: %w", err)
	}
	size := int64(0)
	if result.ContentLength != nil {
		size = *result.ContentLength
	}
	return result.Body, size, nil
}

// GetObjectVersion fetches a specific S3 (SeaweedFS) noncurrent version of an object.
// Returns the body stream + content-length.
func (s *StorageService) GetObjectVersion(ctx context.Context, path, versionID string) (io.ReadCloser, int64, error) {
	result, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket:    aws.String(s.bucket),
		Key:       aws.String(path),
		VersionId: aws.String(versionID),
	})
	if err != nil {
		return nil, 0, fmt.Errorf("s3 get version: %w", err)
	}
	size := int64(0)
	if result.ContentLength != nil {
		size = *result.ContentLength
	}
	return result.Body, size, nil
}

// Delete removes an object from SeaweedFS.
func (s *StorageService) Delete(ctx context.Context, path string) error {
	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(path),
	})
	return err
}

// DeleteObjectVersion deletes a specific S3 (SeaweedFS) noncurrent version of an object.
func (s *StorageService) DeleteObjectVersion(ctx context.Context, key, versionID string) error {
	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket:    aws.String(s.bucket),
		Key:       aws.String(key),
		VersionId: aws.String(versionID),
	})
	return err
}

// DeletePrefix wipes every object whose key begins with the given prefix.
// Used to GC all per-file children (snapshot blob + asset blobs + …) when
// the parent file is deleted from Drive. Paginated ListObjectsV2 + batched
// DeleteObjects (S3 caps a delete batch at 1000 keys).
//
// Returns the first error encountered. Callers treat this as best-effort —
// the parent file row is already gone from the DB, so a partial failure
// only leaks orphan blobs (recoverable later by an admin sweep).
func (s *StorageService) DeletePrefix(ctx context.Context, prefix string) error {
	var continuationToken *string
	for {
		out, err := s.client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:            aws.String(s.bucket),
			Prefix:            aws.String(prefix),
			ContinuationToken: continuationToken,
		})
		if err != nil {
			return fmt.Errorf("s3 list: %w", err)
		}
		if len(out.Contents) > 0 {
			ids := make([]s3types.ObjectIdentifier, 0, len(out.Contents))
			for _, obj := range out.Contents {
				if obj.Key == nil {
					continue
				}
				ids = append(ids, s3types.ObjectIdentifier{Key: obj.Key})
			}
			if len(ids) > 0 {
				_, err := s.client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
					Bucket: aws.String(s.bucket),
					Delete: &s3types.Delete{Objects: ids, Quiet: aws.Bool(true)},
				})
				if err != nil {
					return fmt.Errorf("s3 delete batch: %w", err)
				}
			}
		}
		if out.IsTruncated == nil || !*out.IsTruncated {
			return nil
		}
		continuationToken = out.NextContinuationToken
	}
}
