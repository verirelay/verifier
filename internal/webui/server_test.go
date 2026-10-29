package webui

import (
	"bytes"
	"mime/multipart"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/verirelay/verifier/pkg/verifier"
)

func TestSecurity(t *testing.T) {
	handler := Handler("secret", "127.0.0.1:1234", verifier.Options{Offline: true})
	for _, tc := range []struct {
		path, host, origin string
		status             int
	}{{"/secret/", "127.0.0.1:1234", "", 200}, {"/", "127.0.0.1:1234", "", 403}, {"/other/api/verify", "127.0.0.1:1234", "", 403}, {"/secret/", "evil.test", "", 403}, {"/secret/", "127.0.0.1:1234", "https://evil.test", 403}, {"/secret/", "127.0.0.1:1234", "null", 403}, {"/secret/", "127.0.0.1:1234", "http://127.0.0.1:1234", 200}} {
		r := httptest.NewRequestWithContext(t.Context(), "GET", tc.path, nil)
		r.Host = tc.host
		r.Header.Set("Origin", tc.origin)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Errorf("%+v got %d", tc, w.Code)
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Error("missing no-store")
		}
	}
}

func TestAPIs(t *testing.T) {
	handler := Handler("secret", "127.0.0.1:1234", verifier.Options{Offline: true})
	data := []byte(`{"version":"avr/1","receipt":{},"attestation":null}`)
	for _, endpoint := range []string{"identify", "verify"} {
		var body bytes.Buffer
		writer := multipart.NewWriter(&body)
		file, e := writer.CreateFormFile("evidence", "evidence.json")
		if e != nil {
			t.Fatal(e)
		}
		if _, e := file.Write(data); e != nil {
			t.Fatal(e)
		}
		if e := writer.Close(); e != nil {
			t.Fatal(e)
		}
		r := httptest.NewRequestWithContext(t.Context(), "POST", "/secret/api/"+endpoint, &body)
		r.Host = "127.0.0.1:1234"
		r.Header.Set("Content-Type", writer.FormDataContentType())
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != 200 || !strings.Contains(w.Body.String(), map[string]string{"identify": `"kind":"evidence"`, "verify": `"version":"verifier-report/1"`}[endpoint]) {
			t.Fatalf("%s: %d %s", endpoint, w.Code, w.Body.String())
		}
	}
	r := httptest.NewRequestWithContext(t.Context(), "POST", "/secret/api/verify", strings.NewReader("invalid"))
	r.Host = "127.0.0.1:1234"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatal(w.Code)
	}
}
