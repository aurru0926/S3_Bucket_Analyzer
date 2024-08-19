package errorhandler

import (
	"fmt"
	"time"
)

// RetryOnError retries the given function a specified number of times on error
func RetryOnError(retries int, fn func() error) error {
	var err error
	for i := 0; i < retries; i++ {
		err = fn()
		if err == nil {
			return nil
		}
		fmt.Printf("Retrying after error: %v\n", err)
		time.Sleep(time.Second * time.Duration(i+1))
	}
	return err
}

// HandleError handles errors and optionally retries the operation
func HandleError(err error, message string, retries int) {
	if err != nil {
		fmt.Printf("Error %s: %v\n", message, err)
		if retries > 0 {
			RetryOnError(retries, func() error {
				fmt.Printf("Retrying %s...\n", message)
				// Here you would typically re-run the operation that failed
				// For demonstration, we're just returning nil
				return nil
			})
		}
	}
}
