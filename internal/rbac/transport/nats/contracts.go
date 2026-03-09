package nats

import "encoding/json"

type Code string

const (
	CodeOK            Code = "ok"
	CodeUnauthorized  Code = "unauthorized"
	CodeForbidden     Code = "forbidden"
	CodeBadRequest    Code = "bad_request"
	CodeInternalError Code = "internal_error"
)

type RequestEnvelope struct {
	RequestID string          `json:"request_id"`
	Token     string          `json:"token"`
	Data      json.RawMessage `json:"data"`
}

type ResponseMeta struct {
	LatencyMS int64 `json:"latency_ms"`
}

type ResponseEnvelope struct {
	RequestID string       `json:"request_id"`
	Code      Code         `json:"code"`
	Message   string       `json:"message"`
	Data      any          `json:"data,omitempty"`
	Meta      ResponseMeta `json:"meta"`
}

func DecodeRequestEnvelope(payload []byte) (RequestEnvelope, error) {
	var envelope RequestEnvelope
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return RequestEnvelope{}, err
	}
	return envelope, nil
}

func EncodeResponseEnvelope(envelope ResponseEnvelope) ([]byte, error) {
	return json.Marshal(envelope)
}
