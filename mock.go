package recaptcha

import (
	"context"
	"sync/atomic"
)

// Mock implements the Client interface, with a stubbed Fetch method for use in
// testing.
type Mock struct {
	FetchStub   func(ctx context.Context, token string, userIP string) (Response, error)
	FetchCalled int32
}

var _ Client = &Mock{}

// Fetch calls FetchStub with the provided parameters and returns the result.
func (m *Mock) Fetch(ctx context.Context, token string, userIP string) (Response, error) {
	atomic.AddInt32(&m.FetchCalled, 1)
	return m.FetchStub(ctx, token, userIP)
}
