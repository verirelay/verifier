// Package cli implements the artifact-only command interface.
package cli

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/verirelay/verifier/internal/registry"
	"github.com/verirelay/verifier/pkg/verifier"
)

const Help = `Verifier verifies artifacts you already hold. It never sends proxy requests.

Usage:
  verifier [options]                Open the local web interface
  verifier check FILE... [options]  Verify evidence and body files
  verifier version                  Print the version
  verifier -h                       Show this help

Options:
  --registry URL       Registry (default https://registry.verirelay.com)
  --release-key KEY    Trust this Release Key (unpadded base64url Ed25519 public key)
                       instead of the pinned one; repeat to trust several
  --offline            No network; Registry and CRL checks unavailable
  --no-crl             Skip AMD CRL checks; hardware verdict is unable

Check options (may appear before or after files):
  --store-id VALUE     Store-Id, or pasted response header lines
  --store-key VALUE    Store-Key, or pasted response header lines
  --bootstrap FILE     Require HOST_DATA to be the SHA-256 of this Bootstrap file
  --json               Emit verifier-report/1 JSON

Evidence JSON is required. Body filenames must contain request or response.
For encrypted bodies, supply a Raw Capture envelope and Store-Id/Store-Key.
Exits: 0 all pass, 1 any fail, 2 any unable, usage or operational error.
`

// common holds the options shared by the web interface and check.
type common struct {
	registry string
	keys     []ed25519.PublicKey
	offline  bool
	noCRL    bool
}

func newFlagSet(name string, stderr io.Writer, c *common) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {}
	fs.StringVar(&c.registry, "registry", verifier.DefaultRegistryURL, "Registry URL")
	fs.Func("release-key", "Trusted Release Key; repeatable", func(value string) error {
		key, err := registry.DecodeKey(value)
		if err == nil {
			c.keys = append(c.keys, key)
		}
		return err
	})
	fs.BoolVar(&c.offline, "offline", false, "Skip network")
	fs.BoolVar(&c.noCRL, "no-crl", false, "Skip CRL")
	return fs
}

func (c common) apply(o *verifier.Options) {
	o.RegistryURL = c.registry
	o.ReleaseKeys = c.keys
	o.Offline = c.offline
	crl := !c.noCRL
	o.CheckRevocations = &crl
}

// Web parses the options of the web interface into options. It returns flag.ErrHelp when help is requested.
func Web(args []string, stderr io.Writer, options verifier.Options) (verifier.Options, error) {
	var c common
	fs := newFlagSet("verifier", stderr, &c)
	if err := fs.Parse(args); err != nil {
		return options, err
	}
	if fs.NArg() > 0 {
		err := fmt.Errorf("unexpected argument %q; use verifier -h", fs.Arg(0))
		_, _ = fmt.Fprintln(stderr, err)
		return options, err
	}
	c.apply(&options)
	return options, nil
}

func Check(ctx context.Context, args []string, out, stderr io.Writer, options verifier.Options) int {
	var c common
	fs := newFlagSet("check", stderr, &c)
	var in verifier.Inputs
	var bootstrap string
	var asJSON bool
	fs.StringVar(&in.StoreID, "store-id", "", "Store-Id or header lines")
	fs.StringVar(&in.StoreKey, "store-key", "", "Store-Key or header lines")
	fs.StringVar(&bootstrap, "bootstrap", "", "Expected Bootstrap file")
	fs.BoolVar(&asJSON, "json", false, "JSON report")
	flags, files, err := split(fs, args)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 2
	}
	if err := fs.Parse(flags); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = io.WriteString(out, Help)
			return 0
		}
		return 2
	}
	if len(files) == 0 {
		_, _ = io.WriteString(stderr, Help)
		return 2
	}
	if bootstrap != "" {
		if options.Bootstrap, err = os.ReadFile(bootstrap); err != nil {
			_, _ = fmt.Fprintln(stderr, err)
			return 2
		}
	}
	if err := load(&in, files); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 2
	}
	if in.Evidence == nil {
		_, _ = fmt.Fprintln(stderr, "Evidence JSON is required.")
		return 2
	}
	c.apply(&options)
	result := verifier.Verify(ctx, in, options)
	if asJSON {
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(result); err != nil {
			return 2
		}
	} else if err := Print(out, result); err != nil {
		return 2
	}
	return result.ExitCode()
}

// split separates flags and their values from files, so flags may follow files.
func split(fs *flag.FlagSet, args []string) ([]string, []string, error) {
	var flags, files []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			files = append(files, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(a, "-") {
			files = append(files, a)
			continue
		}
		flags = append(flags, a)
		if f := fs.Lookup(strings.TrimLeft(a, "-")); f != nil && !isBool(f) {
			i++
			if i >= len(args) {
				return nil, nil, fmt.Errorf("%s needs a value", a)
			}
			flags = append(flags, args[i])
		}
	}
	return flags, files, nil
}

func isBool(f *flag.Flag) bool {
	b, ok := f.Value.(interface{ IsBoolFlag() bool })
	return ok && b.IsBoolFlag()
}

func load(in *verifier.Inputs, files []string) error {
	for _, name := range files {
		data, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		var dst *[]byte
		switch verifier.Identify(name, data) {
		case verifier.Evidence:
			dst = &in.Evidence
		case verifier.Capture:
			dst = &in.Capture
		case verifier.RequestBody:
			dst = &in.RequestBody
		case verifier.ResponseBody:
			dst = &in.ResponseBody
		case verifier.StoreHeaders:
			in.StoreKey = string(data)
			continue
		default:
			return fmt.Errorf("cannot identify %q; name body files request or response", name)
		}
		if *dst != nil {
			return fmt.Errorf("duplicate input type: %s", name)
		}
		*dst = data
	}
	return nil
}

func Print(out io.Writer, r verifier.Report) error {
	_, err := fmt.Fprintln(out, "Verifier")
	if err != nil {
		return err
	}
	for _, v := range []struct {
		name  string
		value verifier.Verdict
	}{{"Content", r.Content}, {"Code", r.Code}, {"Hardware", r.Hardware}} {
		if _, err := fmt.Fprintf(out, "%s: %s [%s]\n  %s\n", v.name, strings.ToUpper(v.value.Status), v.value.Code, v.value.Reason); err != nil {
			return err
		}
	}
	if r.Receipt != nil {
		if _, err := fmt.Fprintf(out, "Receipt: %s %s%s, HTTP %d\n", r.Receipt.Method, r.Receipt.UpstreamHost, r.Receipt.Path, r.Receipt.Status); err != nil {
			return err
		}
	}
	if b := r.Bootstrap; b != nil {
		profile := ""
		if b.Profile != "" {
			profile = ", profile " + b.Profile
		}
		if _, err := fmt.Fprintf(out, "Bootstrap: %s%s, identity key %s\n", b.URL, profile, b.IdentityPublicKey); err != nil {
			return err
		}
	}
	for _, l := range r.Limitations {
		if _, err := fmt.Fprintf(out, "Scope: %s\n", l.Message); err != nil {
			return err
		}
	}
	return nil
}
