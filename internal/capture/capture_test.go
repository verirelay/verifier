package capture

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"

	"github.com/verirelay/protocol/avr1"
)

func TestServerCapture(t *testing.T) {
	read := func(n string) []byte {
		t.Helper()
		b, e := os.ReadFile("../testdata/" + n)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	id, key := Headers("", string(read("store-headers.txt")))
	request, response, err := Open(read("capture.json"), id, key)
	if err != nil || !bytes.Equal(request, read("request.txt")) || !bytes.Equal(response, read("response.txt")) {
		t.Fatalf("server capture mismatch: %v", err)
	}
}

func TestOpen(t *testing.T) {
	raw, id := bytes.Repeat([]byte{2}, avr1.RawCaptureKeySize), "store"
	key := base64.RawURLEncoding.EncodeToString(raw)
	sealed, err := avr1.SealRawCapture(raw, id, []byte("request"), []byte{})
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(sealed)
	if err != nil {
		t.Fatal(err)
	}
	headers := "X-VeriRelay-Store-Id: " + id + "\r\nX-VeriRelay-Store-Key: " + key + "\r\n"
	request, response, err := Open(data, "", headers)
	if err != nil || string(request) != "request" || response == nil || len(response) != 0 {
		t.Fatalf("open: %q %q %v", request, response, err)
	}
	wrong := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, avr1.RawCaptureKeySize))
	for _, tc := range []struct {
		data    []byte
		id, key string
	}{
		{nil, id, key},
		{[]byte(`{}`), id, key},
		{data, id, wrong},
		{data, "other", key},
		{data, id, key + "="},
		{data, id, ""},
	} {
		if _, _, err := Open(tc.data, tc.id, tc.key); err == nil {
			t.Fatalf("accepted %s with %q %q", tc.data, tc.id, tc.key)
		}
	}
}
