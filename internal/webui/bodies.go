package webui

import (
	"github.com/verirelay/verifier/internal/capture"
	"github.com/verirelay/verifier/pkg/verifier"
)

func bodies(in verifier.Inputs) ([]byte, []byte, string) {
	if in.RequestBody != nil || in.ResponseBody != nil {
		return in.RequestBody, in.ResponseBody, ""
	}
	if in.Capture == nil {
		return nil, nil, "Body files are missing."
	}
	request, response, err := capture.Open(in.Capture, in.StoreID, in.StoreKey)
	if err != nil {
		return nil, nil, err.Error()
	}
	return request, response, ""
}
