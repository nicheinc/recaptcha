package recaptcha

import (
	"context"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/xerrors"
)

type httpClientMock struct {
	doStub func(req *http.Request) (*http.Response, error)
}

func (m *httpClientMock) Do(req *http.Request) (*http.Response, error) {
	return m.doStub(req)
}

type readCloserMock struct {
	readStub  func(p []byte) (n int, err error)
	closeStub func() error
}

func (m *readCloserMock) Read(p []byte) (n int, err error) {
	return m.readStub(p)
}

func (m *readCloserMock) Close() error {
	return m.closeStub()
}

func TestNewClient(t *testing.T) {
	testCases := []struct {
		name     string
		secret   string
		options  []Option
		expected *Client
	}{
		{
			name:   "NoOptions",
			secret: "secret",
			expected: &Client{
				secret: "secret",
				url:    DefaultURL,
				client: http.DefaultClient,
			},
		},
		{
			name:   "SetHTTPClient",
			secret: "secret",
			options: []Option{
				SetHTTPClient(&http.Client{
					Transport: &http.Transport{
						MaxIdleConnsPerHost: 1,
					},
				}),
			},
			expected: &Client{
				secret: "secret",
				url:    DefaultURL,
				client: &http.Client{
					Transport: &http.Transport{
						MaxIdleConnsPerHost: 1,
					},
				},
			},
		},
		{
			name:   "SetURL",
			secret: "secret",
			options: []Option{
				SetURL("url"),
			},
			expected: &Client{
				secret: "secret",
				url:    "url",
				client: http.DefaultClient,
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			actual := NewClient(testCase.secret, testCase.options...)
			if !reflect.DeepEqual(testCase.expected, actual) {
				t.Errorf("Expected:\n%#v\nActual:\n%v\n", testCase.expected, actual)
			}
		})
	}
}

func TestFetch(t *testing.T) {
	testCases := []struct {
		name     string
		client   *Client
		token    string
		userIP   string
		expected Response
		err      error
	}{
		{
			name: "NewRequest/Error",
			client: NewClient("secret",
				SetURL("\x7f"),
			),
			token:  "token",
			userIP: "192.169.0.1",
			err: &url.Error{
				Op:  "parse",
				URL: "\x7f",
				Err: errors.New("net/url: invalid control character in URL"),
			},
		},
		{
			name: "Do/Error",
			client: NewClient("secret",
				SetHTTPClient(&httpClientMock{
					doStub: func(req *http.Request) (*http.Response, error) {
						return nil, errors.New("AAHHH")
					},
				}),
			),
			token:  "token",
			userIP: "192.169.0.1",
			err:    errors.New("AAHHH"),
		},
		{
			name: "ReadAll/Error",
			client: NewClient("secret",
				SetHTTPClient(&httpClientMock{
					doStub: func(req *http.Request) (*http.Response, error) {
						return &http.Response{
							Body: &readCloserMock{
								readStub: func(p []byte) (n int, err error) {
									return 0, errors.New("AAHHH")
								},
								closeStub: func() error {
									return nil
								},
							},
						}, nil
					},
				}),
			),
			token:  "token",
			userIP: "192.169.0.1",
			err:    errors.New("AAHHH"),
		},
		{
			name: "Unmarshal/Error",
			client: NewClient("secret",
				SetHTTPClient(&httpClientMock{
					doStub: func(req *http.Request) (*http.Response, error) {
						body := `{"score":"invalid"}`
						return &http.Response{
							Body: ioutil.NopCloser(strings.NewReader(body)),
						}, nil
					},
				}),
			),
			token:  "token",
			userIP: "192.169.0.1",
			err: &json.UnmarshalTypeError{
				Value:  "string",
				Type:   reflect.TypeOf(float64(1)),
				Offset: 18,
				Struct: "Response",
				Field:  "score",
			},
		},
		{
			name: "Success",
			client: NewClient("secret",
				SetHTTPClient(&httpClientMock{
					doStub: func(req *http.Request) (*http.Response, error) {
						body := `{
							"success": true,
							"score": 0.5,
							"action": "login",
							"challenge_ts" : "2019-08-25T16:20:00Z",
							"hostname": "niche.com",
							"error-codes": []
						}`
						return &http.Response{
							Body: ioutil.NopCloser(strings.NewReader(body)),
						}, nil
					},
				}),
			),
			token:  "token",
			userIP: "192.169.0.1",
			expected: Response{
				Success:            true,
				Score:              .5,
				Action:             "login",
				ChallengeTimestamp: time.Date(2019, 8, 25, 16, 20, 0, 0, time.UTC),
				Hostname:           "niche.com",
				ErrorCodes:         []string{},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			actual, err := testCase.client.Fetch(context.Background(), testCase.token, testCase.userIP)
			err = xerrors.Unwrap(err)
			if !reflect.DeepEqual(testCase.expected, actual) {
				t.Errorf("Expected:\n%#v\nActual:\n%#v\n", testCase.expected, actual)
			} else if !reflect.DeepEqual(testCase.err, err) {
				t.Errorf("Expected error:\n%#v\nActual:\n%#v\n", testCase.err, err)
			}
		})
	}
}

func TestVerify(t *testing.T) {
	testCases := []struct {
		name     string
		response Response
		criteria []Criterion
		expected error
	}{
		{
			name: "VerificationError/SuccessFalse",
			response: Response{
				Success:            false,
				Score:              .5,
				Action:             "login",
				ChallengeTimestamp: time.Date(2019, 8, 25, 16, 20, 0, 0, time.UTC),
				Hostname:           "niche.com",
				ErrorCodes:         nil,
			},
			expected: &VerificationError{},
		},
		{
			name: "VerificationError/ErrorCodes",
			response: Response{
				Success:            true,
				Score:              .5,
				Action:             "login",
				ChallengeTimestamp: time.Date(2019, 8, 25, 16, 20, 0, 0, time.UTC),
				Hostname:           "niche.com",
				ErrorCodes:         []string{"invalid-input-secret"},
			},
			expected: &VerificationError{
				ErrorCodes: []string{"invalid-input-secret"},
			},
		},
		{
			name: "InvalidHostnameError",
			response: Response{
				Success:            true,
				Score:              .5,
				Action:             "login",
				ChallengeTimestamp: time.Date(2019, 8, 25, 16, 20, 0, 0, time.UTC),
				Hostname:           "nathanjcochran.com",
				ErrorCodes:         []string{},
			},
			criteria: []Criterion{
				Hostname("niche.com"),
			},
			expected: &InvalidHostnameError{
				Expected: "niche.com",
				Actual:   "nathanjcochran.com",
			},
		},
		{
			name: "InvalidActionError",
			response: Response{
				Success:            true,
				Score:              .5,
				Action:             "register",
				ChallengeTimestamp: time.Date(2019, 8, 25, 16, 20, 0, 0, time.UTC),
				Hostname:           "niche.com",
				ErrorCodes:         []string{},
			},
			criteria: []Criterion{
				Action("login"),
			},
			expected: &InvalidActionError{
				Expected: "login",
				Actual:   "register",
			},
		},
		{
			name: "InvalidScoreError",
			response: Response{
				Success:            true,
				Score:              .4,
				Action:             "login",
				ChallengeTimestamp: time.Date(2019, 8, 25, 16, 20, 0, 0, time.UTC),
				Hostname:           "niche.com",
				ErrorCodes:         []string{},
			},
			criteria: []Criterion{
				Score(.5),
			},
			expected: &InvalidScoreError{
				Threshold: .5,
				Actual:    .4,
			},
		},
		{
			name: "Success",
			response: Response{
				Success:            true,
				Score:              .5,
				Action:             "login",
				ChallengeTimestamp: time.Date(2019, 8, 25, 16, 20, 0, 0, time.UTC),
				Hostname:           "niche.com",
				ErrorCodes:         []string{},
			},
			expected: nil,
		},
		{
			name: "Success/Hostname",
			response: Response{
				Success:            true,
				Score:              .5,
				Action:             "login",
				ChallengeTimestamp: time.Date(2019, 8, 25, 16, 20, 0, 0, time.UTC),
				Hostname:           "niche.com",
				ErrorCodes:         []string{},
			},
			criteria: []Criterion{
				Hostname("niche.com"),
			},
			expected: nil,
		},
		{
			name: "Success/Action",
			response: Response{
				Success:            true,
				Score:              .5,
				Action:             "login",
				ChallengeTimestamp: time.Date(2019, 8, 25, 16, 20, 0, 0, time.UTC),
				Hostname:           "niche.com",
				ErrorCodes:         []string{},
			},
			criteria: []Criterion{
				Action("login"),
			},
			expected: nil,
		},
		{
			name: "Success/Score",
			response: Response{
				Success:            true,
				Score:              .5,
				Action:             "login",
				ChallengeTimestamp: time.Date(2019, 8, 25, 16, 20, 0, 0, time.UTC),
				Hostname:           "niche.com",
				ErrorCodes:         []string{},
			},
			criteria: []Criterion{
				Score(.5),
			},
			expected: nil,
		},
		{
			name: "Success/AllOptions",
			response: Response{
				Success:            true,
				Score:              .5,
				Action:             "login",
				ChallengeTimestamp: time.Date(2019, 8, 25, 16, 20, 0, 0, time.UTC),
				Hostname:           "niche.com",
				ErrorCodes:         []string{},
			},
			criteria: []Criterion{
				Hostname("niche.com"),
				Action("login"),
				Score(.5),
			},
			expected: nil,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			actual := testCase.response.Verify(testCase.criteria...)
			if !reflect.DeepEqual(testCase.expected, actual) {
				t.Errorf("Expected:\n%#v\nActual:\n%#v\n", testCase.expected, actual)
			}
		})
	}
}
