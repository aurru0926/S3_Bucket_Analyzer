package publicaccess

import (
	"fmt"
	"s3-bucket-access-analyzer/s3client"

	"github.com/aws/aws-sdk-go/service/s3"
)

// CheckPublicAccess checks if the given bucket has public access enabled.
func CheckPublicAccess(client *s3client.S3Client, bucket *s3.Bucket) bool {
	input := &s3.GetBucketPolicyStatusInput{
		Bucket: bucket.Name,
	}

	result, err := client.Client.GetBucketPolicyStatus(input)
	if err != nil {
		fmt.Printf("Error checking policy status for bucket %s: %v\n", *bucket.Name, err)
		return false
	}

	if result.PolicyStatus.IsPublic != nil && *result.PolicyStatus.IsPublic {
		return true
	}

	// Checks ACL.
	aclInput := &s3.GetBucketAclInput{
		Bucket: bucket.Name,
	}

	aclResult, err := client.Client.GetBucketAcl(aclInput)
	if err != nil {
		fmt.Printf("Error checking ACL for bucket %s: %v\n", *bucket.Name, err)
		return false
	}

	for _, grant := range aclResult.Grants {
		if grant.Grantee.URI != nil && *grant.Grantee.URI == "http://acs.amazonaws.com/groups/global/AllUsers" {
			return true
		}
	}

	return false
}
