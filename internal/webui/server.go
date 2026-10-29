// Package webui serves the embedded local interface behind a per-run capability.
package webui

import (
	"bytes"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/verirelay/verifier/pkg/verifier"
)

//go:embed index.html
var assets embed.FS

const MaxUpload = 160 << 20

func Token() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func Handler(token, host string, options verifier.Options) http.Handler {
	mux := http.NewServeMux()
	prefix := "/" + token + "/"
	mux.HandleFunc("GET "+prefix, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != prefix {
			http.NotFound(w, r)
			return
		}
		data, err := assets.ReadFile("index.html")
		if err != nil {
			http.Error(w, "UI unavailable", 500)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(bytes.ReplaceAll(data, []byte("<script>"), []byte(`<script nonce="`+token+`">`)))
	})
	mux.HandleFunc("POST "+prefix+"api/identify", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, MaxUpload)
		if err := r.ParseMultipartForm(8 << 20); err != nil { // #nosec G120 -- MaxBytesReader caps the entire request above; spill files are removed below.
			http.Error(w, "Invalid multipart input", 400)
			return
		}
		defer func() { _ = r.MultipartForm.RemoveAll() }()
		var result []map[string]string
		for _, headers := range r.MultipartForm.File {
			for _, h := range headers {
				f, err := h.Open()
				if err != nil {
					http.Error(w, "Cannot read file", 400)
					return
				}
				data, err := io.ReadAll(f)
				_ = f.Close()
				if err != nil {
					http.Error(w, "Cannot read file", 400)
					return
				}
				result = append(result, map[string]string{"name": h.Filename, "kind": string(verifier.Identify(h.Filename, data))})
			}
		}
		writeJSON(w, result)
	})
	mux.HandleFunc("POST "+prefix+"api/verify", func(w http.ResponseWriter, r *http.Request) {
		in, err := readInputs(w, r)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		result := verifier.Verify(r.Context(), in, options)
		// Decrypted bodies are returned only to the capability-owning local page, never exported in reports.
		request, response, bodyErr := bodies(in)
		writeJSON(w, struct {
			Report    verifier.Report `json:"report"`
			Request   []byte          `json:"request_body"`
			Response  []byte          `json:"response_body"`
			BodyError string          `json:"body_error,omitempty"`
		}{result, request, response, bodyErr})
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'nonce-"+token+"'; style-src 'unsafe-inline'; connect-src 'self'; img-src data:; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
		if r.Host != host || !strings.HasPrefix(r.URL.Path, prefix) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" && origin != "http://"+host {
			http.Error(w, "Forbidden origin", http.StatusForbidden)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func readInputs(w http.ResponseWriter, r *http.Request) (verifier.Inputs, error) {
	r.Body = http.MaxBytesReader(w, r.Body, MaxUpload)
	var in verifier.Inputs
	if err := r.ParseMultipartForm(8 << 20); err != nil { // #nosec G120 -- MaxBytesReader caps the entire request above; spill files are removed below.
		return in, errors.New("invalid multipart input or upload too large")
	}
	defer func() { _ = r.MultipartForm.RemoveAll() }()
	in.StoreID = r.FormValue("store_id")
	in.StoreKey = r.FormValue("store_key")
	destinations := map[string]*[]byte{"evidence": &in.Evidence, "capture": &in.Capture, "request": &in.RequestBody, "response": &in.ResponseBody}
	for kind, headers := range r.MultipartForm.File {
		dst, ok := destinations[kind]
		if !ok || len(headers) != 1 {
			return in, errors.New("choose one file per recognized type")
		}
		f, err := headers[0].Open()
		if err != nil {
			return in, err
		}
		data, err := io.ReadAll(f)
		_ = f.Close()
		if err != nil {
			return in, err
		}
		*dst = data
	}
	if in.Evidence == nil {
		return in, errors.New("evidence JSON is required")
	}
	return in, nil
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func Server(handler http.Handler) *http.Server {
	return &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 2 * time.Minute, WriteTimeout: 2 * time.Minute, IdleTimeout: time.Minute}
}
