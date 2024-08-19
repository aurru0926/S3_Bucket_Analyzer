package s3client

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
)

// S3Client wraps an S3 service client.
type S3Client struct {
	Client *s3.S3
}

// NewS3Client creates a new S3 client.
func NewS3Client() *S3Client {
	sess := session.Must(session.NewSession(&aws.Config{
		Region: aws.String("us-east-1"), // Change to your specific region.
	}))
	return &S3Client{
		Client: s3.New(sess),
	}
}

// ListBuckets lists all buckets.
func (c *S3Client) ListBuckets() ([]*s3.Bucket, error) {
	resp, err := c.Client.ListBuckets(nil)
	if err != nil {
		return nil, err
	}
	return resp.Buckets, nil
}
