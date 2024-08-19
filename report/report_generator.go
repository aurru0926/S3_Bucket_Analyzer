package report

import (
	"fmt"
	"s3-bucket-access-analyzer/policy"

	"github.com/aws/aws-sdk-go/service/s3"
)

// GenerateReport generates a report based on the bucket's access and policy analysis.
func GenerateReport(bucket *s3.Bucket, publicAccess bool, policyIssues []policy.PolicyIssue) error {
	fmt.Printf("Bucket Name: %s\n", *bucket.Name)
	fmt.Printf("Public Access: %v\n", publicAccess)
	fmt.Println("Policy Issues:")
	if len(policyIssues) == 0 {
		fmt.Println("  No issues detected")
	} else {
		for _, issue := range policyIssues {
			fmt.Printf("  - %s: %s\n", issue.Type, issue.Description)
		}
	}
	fmt.Println()

	return nil
}
