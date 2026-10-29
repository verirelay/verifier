package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"testing"

	"github.com/verirelay/verifier/pkg/verifier"
)

const key = "v3i-paaE4tA24JpjAjfphAIl5Nu3ekFO6UOjnKzqYRY"

func TestCheck(t *testing.T) {
	for _, tc := range []struct {
		args []string
		code int
	}{
		{[]string{"--release-key", "bad", "../testdata/evidence.json"}, 2},
		{nil, 2},
		{[]string{"--relay", "https://example.com"}, 2},
		{[]string{"../testdata/request.txt"}, 2},
		{[]string{"../testdata/request.txt", "--store-id"}, 2},
		{[]string{"--bootstrap", "../testdata/missing.json", "../testdata/evidence-null.json"}, 2},
		{[]string{"-h"}, 0},
	} {
		var out, stderr bytes.Buffer
		got := Check(context.Background(), tc.args, &out, &stderr, verifier.Options{})
		if got != tc.code {
			t.Fatalf("%v: %d %s", tc.args, got, stderr.String())
		}
	}
}

func TestCheckGolden(t *testing.T) {
	var out, stderr bytes.Buffer
	if got := Check(context.Background(), []string{"--offline", "../testdata/evidence-null.json", "../testdata/request.txt", "../testdata/response.txt"}, &out, &stderr, verifier.Options{}); got != 2 {
		t.Fatalf("%d %s", got, stderr.String())
	}
	path := "../testdata/cli.golden.txt"
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if e := os.WriteFile(path, out.Bytes(), 0o600); e != nil {
			t.Fatal(e)
		}
	}
	want, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(want, out.Bytes()) {
		t.Fatalf("CLI golden mismatch: %s", out.String())
	}
	out.Reset()
	if got := Check(context.Background(), []string{"../testdata/evidence-null.json", "--offline", "--json"}, &out, &stderr, verifier.Options{}); got != 2 {
		t.Fatalf("%d %s", got, stderr.String())
	}
	var report verifier.Report
	if err := json.Unmarshal(out.Bytes(), &report); err != nil || report.Version != "verifier-report/1" || report.Content.Code != "bodies_missing" {
		t.Fatalf("JSON report: %v %s", err, out.String())
	}
}

func TestWeb(t *testing.T) {
	options, err := Web([]string{"--registry", "https://registry.test", "--release-key", key, "--release-key=" + key, "--offline", "--no-crl"}, io.Discard, verifier.Options{})
	if err != nil || options.RegistryURL != "https://registry.test" || len(options.ReleaseKeys) != 2 || !options.Offline || options.CheckRevocations == nil || *options.CheckRevocations {
		t.Fatalf("%+v %v", options, err)
	}
	options, err = Web(nil, io.Discard, verifier.Options{})
	if err != nil || options.RegistryURL != verifier.DefaultRegistryURL || options.ReleaseKeys != nil || options.Offline || !*options.CheckRevocations {
		t.Fatalf("%+v %v", options, err)
	}
	if _, err := Web([]string{"--offline", "-h"}, io.Discard, verifier.Options{}); !errors.Is(err, flag.ErrHelp) {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"--release-key", "bad"}, {"--json"}, {"--offline", "evidence.json"}} {
		if _, err := Web(args, io.Discard, verifier.Options{}); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}

func TestPassOutputGolden(t *testing.T) {
	raw, err := os.ReadFile("../testdata/report.golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var report verifier.Report
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := Print(&out, report); err != nil {
		t.Fatal(err)
	}
	path := "../testdata/cli-pass.golden.txt"
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(path, out.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, out.Bytes()) {
		t.Fatalf("CLI pass golden mismatch: %s", out.String())
	}
}

func TestPrintBootstrap(t *testing.T) {
	var out bytes.Buffer
	if err := Print(&out, verifier.Report{Bootstrap: &verifier.Bootstrap{URL: "https://veriprov.example.com", Profile: "eu", IdentityPublicKey: key}}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out.Bytes(), []byte("Bootstrap: https://veriprov.example.com, profile eu, identity key "+key+"\n")) {
		t.Fatal(out.String())
	}
}
