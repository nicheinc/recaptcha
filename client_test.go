package recaptcha

import (
	"net/http"
	"reflect"
	"testing"
)

func TestNewClient(t *testing.T) {
	testCases := []struct {
		name     string
		secret   string
		options  []ClientOption
		expected *Client
	}{
		{
			name:   "NoOptions",
			secret: "secret",
			expected: &Client{
				secret: "secret",
				client: http.DefaultClient,
			},
		},
		{
			name:   "SetHTTPClient",
			secret: "secret",
			options: []ClientOption{
				SetHTTPClient(&http.Client{
					Transport: &http.Transport{
						MaxIdleConnsPerHost: 1,
					},
				}),
			},
			expected: &Client{
				secret: "secret",
				client: &http.Client{
					Transport: &http.Transport{
						MaxIdleConnsPerHost: 1,
					},
				},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			actual := NewClient(testCase.secret, testCase.options...)
			if !reflect.DeepEqual(testCase.expected, actual) {
				t.Errorf("expected: %v, actual: %v", testCase.expected, actual)
			}
		})
	}
}
