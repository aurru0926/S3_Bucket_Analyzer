package policy

import (
	"encoding/json"
	"fmt"
	"s3-bucket-access-analyzer/s3client"
	"strings"

	"github.com/aws/aws-sdk-go/service/s3"
)

// PolicyIssue represents a detected policy issue
type PolicyIssue struct {
	Type        string
	Description string
}

// AnalyzeBucketPolicy analyzes the given bucket's policy for security issues.
func AnalyzeBucketPolicy(client *s3client.S3Client, bucket *s3.Bucket) []PolicyIssue {
	input := &s3.GetBucketPolicyInput{
		Bucket: bucket.Name,
	}

	result, err := client.Client.GetBucketPolicy(input)
	if err != nil {
		if strings.Contains(err.Error(), "NoSuchBucketPolicy") {
			return []PolicyIssue{{Type: "Info", Description: "No bucket policy found"}}
		}
		return []PolicyIssue{{Type: "Error", Description: fmt.Sprintf("Unable to retrieve bucket policy: %v", err)}}
	}

	if result.Policy == nil {
		return []PolicyIssue{{Type: "Info", Description: "No bucket policy found"}}
	}

	var policy map[string]interface{}
	err = json.Unmarshal([]byte(*result.Policy), &policy)
	if err != nil {
		return []PolicyIssue{{Type: "Error", Description: fmt.Sprintf("Unable to parse bucket policy: %v", err)}}
	}

	return analyzePolicy(policy, *bucket.Name)
}

func analyzePolicy(policy map[string]interface{}, bucketName string) []PolicyIssue {
	var issues []PolicyIssue

	statements, ok := policy["Statement"].([]interface{})
	if !ok {
		return append(issues, PolicyIssue{Type: "Error", Description: "Invalid policy structure"})
	}

	for _, stmt := range statements {
		statement, ok := stmt.(map[string]interface{})
		if !ok {
			continue
		}

		effect, _ := statement["Effect"].(string)
		principal := statement["Principal"]
		action := statement["Action"]
		resource := statement["Resource"]

		// Checks for overly permissive policies.
		if effect == "Allow" {
			if isWildcardPrincipal(principal) {
				issues = append(issues, PolicyIssue{Type: "High", Description: "Policy allows access to all AWS users"})
			}

			if isWildcardAction(action) {
				issues = append(issues, PolicyIssue{Type: "High", Description: "Policy allows all actions"})
			}

			if !isResourceLimitedToBucket(resource, bucketName) {
				issues = append(issues, PolicyIssue{Type: "Medium", Description: "Policy applies to resources outside this bucket"})
			}
		}

		// Checks for potentially under-permissive policies.
		if effect == "Deny" {
			if isWildcardAction(action) {
				issues = append(issues, PolicyIssue{Type: "Medium", Description: "Policy denies all actions, which may be overly restrictive"})
			}
		}

		// Checks for use of NotPrincipal.
		if _, exists := statement["NotPrincipal"]; exists {
			issues = append(issues, PolicyIssue{Type: "Low", Description: "Policy uses NotPrincipal, which can be complex and error-prone"})
		}
	}

	if len(issues) == 0 {
		issues = append(issues, PolicyIssue{Type: "Info", Description: "No significant policy issues detected"})
	}

	return issues
}

// Helper functions to check policy elements.

func isWildcardPrincipal(principal interface{}) bool {
	switch p := principal.(type) {
	case string:
		return p == "*"
	case map[string]interface{}:
		for _, v := range p {
			if v == "*" {
				return true
			}
		}
	}
	return false
}

func isWildcardAction(action interface{}) bool {
	switch a := action.(type) {
	case string:
		return a == "*" || a == "s3:*"
	case []interface{}:
		for _, act := range a {
			if s, ok := act.(string); ok && (s == "*" || s == "s3:*") {
				return true
			}
		}
	}
	return false
}

func isResourceLimitedToBucket(resource interface{}, bucketName string) bool {
	bucketARN := fmt.Sprintf("arn:aws:s3:::%s", bucketName)
	switch r := resource.(type) {
	case string:
		return strings.HasPrefix(r, bucketARN)
	case []interface{}:
		for _, res := range r {
			if s, ok := res.(string); ok && !strings.HasPrefix(s, bucketARN) {
				return false
			}
		}
	}
	return true
}
