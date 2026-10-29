// Package network provides bounded, context-aware GETs without redirects.
package network

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

const MaxResponse = 8 << 20

func Client(c *http.Client) *http.Client {
	if c == nil {
		c = &http.Client{Timeout: 20 * time.Second}
	}
	clone := *c
	clone.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	if clone.Timeout == 0 {
		clone.Timeout = 20 * time.Second
	}
	return &clone
}

func Get(ctx context.Context, c *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	res, err := Client(c).Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", res.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, MaxResponse+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxResponse {
		return nil, fmt.Errorf("response exceeds %d bytes", MaxResponse)
	}
	return b, nil
}
