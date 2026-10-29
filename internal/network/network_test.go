package network

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBoundedNetwork(t *testing.T) {
	targetCalls := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { targetCalls++; _, _ = io.WriteString(w, "unexpected") }))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			_, _ = io.WriteString(w, "ok")
		case "/empty":
			w.WriteHeader(http.StatusOK)
		case "/redirect":
			http.Redirect(w, r, target.URL, http.StatusFound)
		default:
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer source.Close()
	for _, tc := range []struct {
		path, want string
		fail       bool
	}{{"/ok", "ok", false}, {"/empty", "", false}, {"/redirect", "", true}, {"/error", "", true}} {
		data, e := Get(t.Context(), nil, source.URL+tc.path)
		if (e != nil) != tc.fail || string(data) != tc.want {
			t.Fatalf("%s: %s %v", tc.path, data, e)
		}
	}
	if targetCalls != 0 {
		t.Fatal("followed a redirect")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, e := Get(ctx, nil, source.URL+"/ok"); e == nil {
		t.Fatal("ignored cancellation")
	}
}
