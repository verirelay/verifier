package verifier

import (
	"encoding/json"
	"strings"

	"github.com/verirelay/protocol/avr1"
)

type Kind string

const (
	Unknown      Kind = "unknown"
	Evidence     Kind = "evidence"
	Capture      Kind = "capture"
	RequestBody  Kind = "request"
	ResponseBody Kind = "response"
	StoreHeaders Kind = "store_headers"
)

func Identify(name string, data []byte) Kind {
	var object struct {
		Version string          `json:"version"`
		Receipt json.RawMessage `json:"receipt"`
	}
	if json.Unmarshal(data, &object) == nil {
		switch {
		case object.Version == avr1.AVRVersion && object.Receipt != nil:
			return Evidence
		case object.Version == avr1.RawCaptureVersion:
			return Capture
		}
	}
	lower := strings.ToLower(name)
	switch {
	case strings.Contains(lower, "request") || strings.Contains(lower, "请求"):
		return RequestBody
	case strings.Contains(lower, "response") || strings.Contains(lower, "响应"):
		return ResponseBody
	case strings.Contains(strings.ToLower(string(data)), "store-key:"):
		return StoreHeaders
	default:
		return Unknown
	}
}
