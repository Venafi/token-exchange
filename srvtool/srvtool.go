package srvtool

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-logr/logr"
)

type EndpointFn func(*http.Request) Response

type Response interface {
	HTTPCode() int
	Body() any
}

type jsonResponse struct {
	code int
	body any
}

func (r *jsonResponse) HTTPCode() int {
	return r.code
}

func (r *jsonResponse) Body() any {
	return r.body
}

func Ok(body any) Response {
	return NewResponse(http.StatusOK, body)
}

func NewResponse(code int, body any) Response {
	return &jsonResponse{
		code: code,
		body: body,
	}
}

type errMsg struct {
	Error string `json:"error"`
}

func Error(code int, message string) Response {
	return NewResponse(code, errMsg{Error: message})
}

func Errorf(code int, fmtStr string, args ...any) Response {
	return Error(code, fmt.Sprintf(fmtStr, args...))
}

func JSONHandler(fn EndpointFn) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		response := fn(r)

		if response == nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		statusCode := response.HTTPCode()
		body := response.Body()

		writeBody(r.Context(), w, statusCode, body)
	}
}

func writeBody(ctx context.Context, w http.ResponseWriter, statusCode int, body any) {
	out, err := json.Marshal(body)
	if err != nil {
		logr.
			FromContextAsSlogLogger(ctx).
			Error("failed to marshal response as JSON", "err", err)

		statusCode = 500
		out = []byte(`{"error":"internal server error"}`)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if _, err := w.Write(out); err != nil {
		logr.
			FromContextAsSlogLogger(ctx).
			Error("failed to write response body", "err", err)
	}
}
