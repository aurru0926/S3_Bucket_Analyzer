package main

import (
	"fmt"
	"s3-bucket-access-analyzer/errorhandler"
	"s3-bucket-access-analyzer/policy"
	"s3-bucket-access-analyzer/publicaccess"
	"s3-bucket-access-analyzer/report"
	"s3-bucket-access-analyzer/s3client"

	"github.com/aws/aws-sdk-go/service/s3"
)

func main() {
	fmt.Println("Starting S3 Bucket Access Analyzer...")

	// Initialize the S3 client.
	s3Client := s3client.NewS3Client()

	// Retrieve a list of all S3 buckets in the account.
	var buckets []*s3.Bucket
	err := errorhandler.RetryOnError(3, func() error {
		var err error
		buckets, err = s3Client.ListBuckets()
		return err
	})
	if err != nil {
		errorhandler.HandleError(err, "listing S3 buckets", 0)
		return
	}

	// Iterate through each bucket and perform access analysis.
	for _, bucket := range buckets {
		// Checks if the bucket has public access.
		publicAccess := publicaccess.CheckPublicAccess(s3Client, bucket)
		// Analyzes the bucket's policy for security issues.
		policyIssues := policy.AnalyzeBucketPolicy(s3Client, bucket)
		// Generates a report based on the findings.
		report.GenerateReport(bucket, publicAccess, policyIssues)
	}

	fmt.Println("S3 Bucket Access Analyzer completed.")
}
