// Package report defines the portable verification result.
package report

// Version identifies the report format.
const Version = "verifier-report/1"

type Detail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Verdict struct {
	Status  string   `json:"status"`
	Code    string   `json:"code"`
	Reason  string   `json:"reason"`
	Details []Detail `json:"details"`
}

func Result(status, code, reason string, details ...Detail) Verdict {
	if details == nil {
		details = []Detail{}
	}
	return Verdict{Status: status, Code: code, Reason: reason, Details: details}
}

type ReceiptFacts struct {
	RequestID       string `json:"request_id"`
	Method          string `json:"method"`
	UpstreamHost    string `json:"upstream_host"`
	Path            string `json:"path"`
	Status          int    `json:"status"`
	Time            string `json:"time"`
	UpstreamTLSSPKI string `json:"upstream_tls_spki"`
}

type Release struct {
	Repository string `json:"repository"`
	Tag        string `json:"tag"`
	Commit     string `json:"commit"`
}

// Bootstrap holds the facts of the Bootstrap whose SHA-256 is the verified HOST_DATA.
type Bootstrap struct {
	URL               string `json:"url"`
	Profile           string `json:"profile"`
	IdentityPublicKey string `json:"identity_public_key"`
}

type Report struct {
	Version     string        `json:"version"`
	GeneratedAt string        `json:"generated_at"`
	Content     Verdict       `json:"content"`
	Code        Verdict       `json:"code"`
	Hardware    Verdict       `json:"hardware"`
	Receipt     *ReceiptFacts `json:"receipt,omitempty"`
	Release     *Release      `json:"release,omitempty"`
	Bootstrap   *Bootstrap    `json:"bootstrap,omitempty"`
	Limitations []Detail      `json:"limitations"`
}

func (r Report) ExitCode() int {
	unable := false
	for _, v := range []Verdict{r.Content, r.Code, r.Hardware} {
		if v.Status == "fail" {
			return 1
		}
		if v.Status != "pass" {
			unable = true
		}
	}
	if unable {
		return 2
	}
	return 0
}
