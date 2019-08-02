package recaptcha

import (
	"fmt"
	"strings"
)

type InvalidHostnameError struct {
	Expected string
	Actual   string
}

func (e *InvalidHostnameError) Error() string {
	return fmt.Sprintf("invalid hostname: %s, expected: %s", e.Actual, e.Expected)
}

type InvalidActionError struct {
	Expected string
	Actual   string
}

func (e *InvalidActionError) Error() string {
	return fmt.Sprintf("invalid action: %s, expected: %s", e.Actual, e.Expected)
}

type InvalidScoreError struct {
	Threshold float64
	Actual    float64
}

func (e *InvalidScoreError) Error() string {
	return fmt.Sprintf("invalid score: %f, minimum threshold: %f", e.Actual, e.Threshold)
}

type VerificationError struct {
	ErrorCodes []string
}

func (e *VerificationError) Error() string {
	if len(e.ErrorCodes) > 0 {
		return fmt.Sprintf("failed verification: %s", strings.Join(e.ErrorCodes, ","))
	}
	return "failed verification"
}
