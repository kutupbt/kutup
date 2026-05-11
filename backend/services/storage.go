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

// ObjectInfo is a slim projection of S3 ListObjectsV2 entries used by paged
// walkers. Carrying Size + LastModified inline avoids a per-key HEAD round
// trip in the orphan-sweep age check.
type ObjectInfo struct {
	Key          string
	Size         int64
	LastModified time.Time
}

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

// ListObjectsPaged iterates ListObjectsV2 results in pages of up to 1000
// keys, invoking page() once per non-empty page. Stops + returns the
// error if page() returns one. Used by both DeletePrefix and the orphan
// sweep — extracting it lets both share one tested LIST loop.
func (s *StorageService) ListObjectsPaged(
	ctx context.Context,
	prefix string,
	page func(objs []ObjectInfo) error,
) error {
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
			objs := make([]ObjectInfo, 0, len(out.Contents))
			for _, obj := range out.Contents {
				if obj.Key == nil {
					continue
				}
				size := int64(0)
				if obj.Size != nil {
					size = *obj.Size
				}
				lm := time.Time{}
				if obj.LastModified != nil {
					lm = *obj.LastModified
				}
				objs = append(objs, ObjectInfo{Key: *obj.Key, Size: size, LastModified: lm})
			}
			if err := page(objs); err != nil {
				return err
			}
		}
		if out.IsTruncated == nil || !*out.IsTruncated {
			return nil
		}
		continuationToken = out.NextContinuationToken
	}
}

// DeleteObjectsBatch removes up to 1000 keys in a single DeleteObjects S3 call.
// S3 caps a delete batch at exactly 1000 keys; callers should chunk if larger.
func (s *StorageService) DeleteObjectsBatch(ctx context.Context, keys []string) error {
	if len(keys) == 0 {
		return nil
	}
	ids := make([]s3types.ObjectIdentifier, len(keys))
	for i := range keys {
		k := keys[i]
		ids[i] = s3types.ObjectIdentifier{Key: &k}
	}
	_, err := s.client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
		Bucket: aws.String(s.bucket),
		Delete: &s3types.Delete{Objects: ids, Quiet: aws.Bool(true)},
	})
	if err != nil {
		return fmt.Errorf("s3 delete batch: %w", err)
	}
	return nil
}

// DeletePrefix wipes every object whose key begins with the given prefix.
// Used to GC all per-file children (snapshot blob + asset blobs + …) when
// the parent file is deleted from Drive.
//
// Returns the first error encountered. Callers treat this as best-effort —
// the parent file row is already gone from the DB, so a partial failure
// only leaks orphan blobs (recoverable later by the admin orphan sweep).
func (s *StorageService) DeletePrefix(ctx context.Context, prefix string) error {
	return s.ListObjectsPaged(ctx, prefix, func(objs []ObjectInfo) error {
		keys := make([]string, len(objs))
		for i, o := range objs {
			keys[i] = o.Key
		}
		return s.DeleteObjectsBatch(ctx, keys)
	})
}

// CompletedPart is the {PartNumber, ETag} pair S3 needs at finalize time.
// We model it ourselves so the tus DB row can serialise it as JSONB
// without dragging the SDK type into the schema.
type CompletedPart struct {
	PartNumber int32  `json:"part_number"`
	ETag       string `json:"etag"`
}

// CreateMultipart opens a new S3 multipart upload at `key`. Returns the
// opaque UploadId that subsequent UploadPart / CompleteMultipart calls
// must thread through. The lifetime of the multipart on SeaweedFS is
// bounded by the stale-upload sweeper — if the user abandons mid-stream
// we Abort it explicitly.
func (s *StorageService) CreateMultipart(ctx context.Context, key string) (string, error) {
	out, err := s.client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return "", fmt.Errorf("s3 create multipart: %w", err)
	}
	if out.UploadId == nil {
		return "", fmt.Errorf("s3 create multipart: empty upload id")
	}
	return *out.UploadId, nil
}

// UploadPart streams one part of a multipart upload. partNumber is 1-based
// per S3. Returns the ETag the caller must remember for CompleteMultipart.
// Note: S3 requires every part except the last to be ≥ 5 MiB. The tus
// handler enforces that — clients sending sub-5MiB PATCHes before the
// final one will get a 4xx from S3 surfaced as 500 here.
func (s *StorageService) UploadPart(
	ctx context.Context,
	key, uploadID string,
	partNumber int32,
	body io.Reader,
	size int64,
) (string, error) {
	out, err := s.client.UploadPart(ctx, &s3.UploadPartInput{
		Bucket:        aws.String(s.bucket),
		Key:           aws.String(key),
		UploadId:      aws.String(uploadID),
		PartNumber:    aws.Int32(partNumber),
		Body:          body,
		ContentLength: aws.Int64(size),
	})
	if err != nil {
		return "", fmt.Errorf("s3 upload part %d: %w", partNumber, err)
	}
	if out.ETag == nil {
		return "", fmt.Errorf("s3 upload part %d: empty etag", partNumber)
	}
	return *out.ETag, nil
}

// CompleteMultipart finalises the multipart upload, producing one object
// at `key`. Parts must be passed in PartNumber order.
func (s *StorageService) CompleteMultipart(
	ctx context.Context,
	key, uploadID string,
	parts []CompletedPart,
) error {
	sdkParts := make([]s3types.CompletedPart, len(parts))
	for i, p := range parts {
		etag := p.ETag
		pn := p.PartNumber
		sdkParts[i] = s3types.CompletedPart{
			PartNumber: aws.Int32(pn),
			ETag:       aws.String(etag),
		}
	}
	_, err := s.client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket:          aws.String(s.bucket),
		Key:             aws.String(key),
		UploadId:        aws.String(uploadID),
		MultipartUpload: &s3types.CompletedMultipartUpload{Parts: sdkParts},
	})
	if err != nil {
		return fmt.Errorf("s3 complete multipart: %w", err)
	}
	return nil
}

// AbortMultipart discards a multipart upload — used when the user cancels
// or when the stale-upload sweeper reaps an abandoned session. Idempotent
// per the S3 spec: aborting an already-aborted upload returns success.
func (s *StorageService) AbortMultipart(ctx context.Context, key, uploadID string) error {
	_, err := s.client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
		Bucket:   aws.String(s.bucket),
		Key:      aws.String(key),
		UploadId: aws.String(uploadID),
	})
	if err != nil {
		return fmt.Errorf("s3 abort multipart: %w", err)
	}
	return nil
}

// CopyObject moves an object within the bucket from src to dst. Used by
// the tus finaliser to rename the temp multipart-assembled object to its
// canonical {userId}/{collectionId}/{fileId} path, then DeleteObject the
// temp. (Naïve "rename" doesn't exist in S3 — CopyObject + Delete is the
// convention.)
func (s *StorageService) CopyObject(ctx context.Context, src, dst string) error {
	_, err := s.client.CopyObject(ctx, &s3.CopyObjectInput{
		Bucket:     aws.String(s.bucket),
		Key:        aws.String(dst),
		CopySource: aws.String(s.bucket + "/" + src),
	})
	if err != nil {
		return fmt.Errorf("s3 copy %s -> %s: %w", src, dst, err)
	}
	return nil
}
