package srvtool

import (
	"context"
	"encoding/json"
	"net/http"
	"token-exchange/logging"
)

type EndpointFn func(http.ResponseWriter, *http.Request) (*Response, *HTTPError)

type Response struct {
	HTTPCode int
	Body     any
}

func (resp *Response) WriteJSON(w http.ResponseWriter, r *http.Request) {
	statusCode := resp.HTTPCode

	if statusCode == 0 {
		statusCode = http.StatusOK
	}

	var out []byte
	var err error

	out, err = json.Marshal(resp.Body)
	if err != nil {
		logger := logging.LoggerFromContext(r.Context())
		logger.Error("failed to marshal response as JSON", "err", err)

		statusCode = 500
		out = []byte(`{"error":"internal server error"}`)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	writeBody(r.Context(), w, out)
}

func JSON(fn EndpointFn) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var response *Response
		var err *HTTPError

		response, err = fn(w, r)
		if err != nil {
			response = err.Response()
		}

		response.WriteJSON(w, r)
	}
}

func writeBody(ctx context.Context, w http.ResponseWriter, body []byte) {
	_, err := w.Write(body)
	if err != nil {
		logging.LoggerFromContext(ctx).Error("failed to write http response", "err", err)
	}
}
