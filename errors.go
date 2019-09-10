package recaptcha

import (
	"fmt"
	"strings"
	"time"
)

// VerificationError is returned from Verify when the response's "success"
// field is false or the "error-codes" field is non-empty. This is the only
// error the can be returned from Verify if no additional verification criteria
// are provided.
type VerificationError struct {
	ErrorCodes []string
}

func (e *VerificationError) Error() string {
	if len(e.ErrorCodes) > 0 {
		return fmt.Sprintf("invalid reCAPTCHA: %s", strings.Join(e.ErrorCodes, ","))
	}
	return "invalid reCAPTCHA (success: false)"
}

// InvalidHostnameError is returned from Verify if the Hostname criterion is
// provided and the response's "hostname" field does not correspond to the
// expected hostname.
type InvalidHostnameError struct {
	Hostname string
}

func (e *InvalidHostnameError) Error() string {
	return fmt.Sprintf("invalid reCAPTCHA: invalid hostname: %s", e.Hostname)
}

// InvalidActionError is returned from Verify if the Action criterion is
// provided and the response's "action" field does not correspond to the
// expected action.
type InvalidActionError struct {
	Action string
}

func (e *InvalidActionError) Error() string {
	return fmt.Sprintf("invalid reCAPTCHA: invalid action: %s", e.Action)
}

// InvalidScoreError is returned from Verify if the Score criterion is provided
// and the response's "score" field is below the minimum threshold.
type InvalidScoreError struct {
	Score float64
}

func (e *InvalidScoreError) Error() string {
	return fmt.Sprintf("invalid reCAPTCHA: invalid score: %f", e.Score)
}

// InvalidChallengeTsError is returned from Verify if the ChallengeTs criterion
// is provided and the response's "challenge_ts" field falls outside the valid
// window.
type InvalidChallengeTsError struct {
	ChallengeTs time.Time
	Diff        time.Duration
}

func (e *InvalidChallengeTsError) Error() string {
	return fmt.Sprintf("invalid reCAPTCHA: invalid challenge timestamp: %s (%s old)", e.ChallengeTs, e.Diff)
}
