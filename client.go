// Package recaptcha provides functionality for hitting the reCAPTCHA v3
// verification endpoint and verifying the response. By default, it simply
// verifies that the response's "success" field is true, and that the
// "error-codes" field is empty. Additional optional verification criteria can
// be provided when calling Verify to ensure, for example, that the correct
// hostname and action were returned. See the package-level example for a
// demonstration of how to use the package.
//
// More information about reCAPTCHA v3 can be found here:
// https://developers.google.com/recaptcha/docs/v3
package recaptcha

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/xerrors"
)

// DefaultURL is the default reCAPTCHA verification endpoint URL. This can be
// overridden via the SetURL option.
const DefaultURL = "https://www.google.com/recaptcha/api/siteverify"

// HTTPClient is a basic interface for an HTTP client, as required by the
// SetHTTPClient function. The standard *http.Client satisfies this interface.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Client for making requests to the reCAPTCHA verification endpoint and
// receiving token verification responses. Created with NewClient.
type Client interface {
	Fetch(ctx context.Context, token, userIP string) (Response, error)
}

// Concrete implementation of the Client interface. Created with NewClient.
type client struct {
	secret     string
	url        string
	httpClient HTTPClient
}

// Option represents a configuration option that can be applied when creating a
// Client via the NewClient method. See SetHTTPClient and SetURL functions.
type Option func(c *client)

// SetHTTPClient is an option for creating a Client with a custom *http.Client.
// If not provided, the Client will use http.DefaultClient.
func SetHTTPClient(httpClient HTTPClient) Option {
	return func(c *client) {
		c.httpClient = httpClient
	}
}

// SetURL is an option for creating a Client that hits a custom verification
// URL. If not provided, the Client will use DefaultURL.
func SetURL(url string) Option {
	return func(c *client) {
		c.url = url
	}
}

// NewClient creates an instance of Client, which is thread-safe and should be
// reused instead of created as needed. You must provided your website's secret
// key, which is shared between your site and reCAPTCHA. Additional
// configuration options may also be provided (e.g. SetHTTPClient, SetURL).
func NewClient(secret string, opts ...Option) Client {
	c := &client{
		secret:     secret,
		url:        DefaultURL,
		httpClient: http.DefaultClient,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Fetch makes a request to the reCAPTCHA verification endpoint using the
// provided token and optional userIP (which can be omitted from the request by
// providing an empty string), and returns the response. To check whether the
// token was actually valid, use the response's Verify method.
func (c *client) Fetch(ctx context.Context, token, userIP string) (Response, error) {
	values := url.Values{
		"secret":   {c.secret},
		"response": {token},
	}
	if userIP != "" {
		values["remoteip"] = []string{userIP}
	}

	request, err := http.NewRequest(http.MethodPost, c.url, strings.NewReader(values.Encode()))
	if err != nil {
		return Response{}, xerrors.Errorf("error creating POST request: %w", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request = request.WithContext(ctx)

	res, err := c.httpClient.Do(request)
	if err != nil {
		return Response{}, xerrors.Errorf("error making POST request: %w", err)
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return Response{}, xerrors.Errorf("error reading response body: %w", err)
	}

	var response Response
	if err := json.Unmarshal(body, &response); err != nil {
		return Response{}, xerrors.Errorf("error unmarshalling response body: %w", err)
	}

	return response, nil
}

// Response represents a response from the reCAPTCHA token verification
// endpoint. The validity of the token can be verified via the Verify method.
type Response struct {
	Success     bool      `json:"success"`
	Score       float64   `json:"score"`
	Action      string    `json:"action"`
	ChallengeTs time.Time `json:"challenge_ts"`
	Hostname    string    `json:"hostname"`
	ErrorCodes  []string  `json:"error-codes"`
}

// Verify checks whether the response represents a valid token. It returns an
// error if the token is invalid (i.e. if Success is false or ErrorCodes is
// non-empty). Typically, the error will be of type *VerificationError.
// However, if additional optional verification criteria are provided, their
// respective error types may be returned as well.
func (r *Response) Verify(criteria ...Criterion) error {
	if !r.Success || len(r.ErrorCodes) > 0 {
		return &VerificationError{
			ErrorCodes: r.ErrorCodes,
		}
	}

	for _, criterion := range criteria {
		if err := criterion(r); err != nil {
			return err
		}
	}

	return nil
}

// Criterion is an optional token verification criterion that can be applied
// when a token is verified via the Verify method.
type Criterion func(r *Response) error

// Hostname is an optional verification criterion which ensures that the
// hostname of the website where the reCAPTCHA was presented matches one of the
// provided hostnames. Returns *InvalidHostnameError if the hostname is not
// correct.
func Hostname(hostnames ...string) Criterion {
	return func(r *Response) error {
		for _, hostname := range hostnames {
			if hostname == r.Hostname {
				return nil
			}
		}
		return &InvalidHostnameError{
			Hostname: r.Hostname,
		}
	}
}

// Action is an optional verification criterion which ensures that the website
// action associated with the reCAPTCHA matches one of the provided actions.
// Returns *InvalidActionError if the action is not correct.
func Action(actions ...string) Criterion {
	return func(r *Response) error {
		for _, action := range actions {
			if action == r.Action {
				return nil
			}
		}
		return &InvalidActionError{
			Action: r.Action,
		}
	}
}

// Score is an optional verification criterion which ensures that the score
// associated with the reCAPTCHA meets the minimum threshold. Returns
// *InvalidScoreError if the score is below the threshold.
func Score(threshold float64) Criterion {
	return func(r *Response) error {
		if r.Score < threshold {
			return &InvalidScoreError{
				Score: r.Score,
			}
		}
		return nil
	}
}

// Makes it possible to mock time.Now() calls
var now = time.Now

// ChallengeTs is an optional verification criterion which ensures that the
// response token is being used within the specified window of time from when
// the reCAPTCHA was presented. By default, the reCAPTCHA verification endpoint
// only considers a token valid for 2 minutes, so this method is only necessary
// if you want to enforce an narrower window than that. Returns
// *InvalidChallengeTsError if the challenge timestamp is outside the valid
// window.
func ChallengeTs(window time.Duration) Criterion {
	return func(r *Response) error {
		if diff := now().Sub(r.ChallengeTs); diff > window {
			return &InvalidChallengeTsError{
				ChallengeTs: r.ChallengeTs,
				Diff:        diff,
			}
		}
		return nil
	}
}
