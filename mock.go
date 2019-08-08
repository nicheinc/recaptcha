package recaptcha

import (
	"context"
	"sync/atomic"
)

type Mock struct {
	FetchStub   func(ctx context.Context, token string, userIP string) (Response, error)
	FetchCalled int32
}

var _ Client = &Mock{}

func (m *Mock) Fetch(ctx context.Context, token string, userIP string) (Response, error) {
	atomic.AddInt32(&m.FetchCalled, 1)
	return m.FetchStub(ctx, token, userIP)
}
