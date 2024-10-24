package srvtool

import (
	"net/http"

	"github.com/go-logr/logr"
	"github.com/google/uuid"
)

func ServeHTTPWithLogs(underlying http.Handler, w http.ResponseWriter, r *http.Request) {
	uuid, err := uuid.NewRandom()
	if err != nil {
		http.Error(w, "couldn't generate UUID", http.StatusInternalServerError)
		return
	}

	logger := logr.FromContextAsSlogLogger(r.Context()).With("request_id", uuid.String())

	r = r.WithContext(logr.NewContextWithSlogLogger(r.Context(), logger))

	sniffer := NewResponseSniffer(w)

	underlying.ServeHTTP(sniffer, r)

	logger.Info("completed request", "user_agent", r.UserAgent(), "status", sniffer.StatusCode, "total_bytes", sniffer.TotalBytes, "path", r.URL.String())
}

type ResponseSniffer struct {
	StatusCode int

	TotalBytes int

	underlying http.ResponseWriter
}

var _ http.ResponseWriter = &ResponseSniffer{}

func NewResponseSniffer(underlying http.ResponseWriter) *ResponseSniffer {
	return &ResponseSniffer{
		StatusCode: http.StatusTeapot,

		TotalBytes: 0,

		underlying: underlying,
	}
}

func (rs *ResponseSniffer) Header() http.Header {
	return rs.underlying.Header()
}

func (rs *ResponseSniffer) Write(b []byte) (int, error) {
	written, err := rs.underlying.Write(b)
	if err == nil {
		rs.TotalBytes += written
	}

	return written, err
}

func (rs *ResponseSniffer) WriteHeader(statusCode int) {
	rs.StatusCode = statusCode

	rs.underlying.WriteHeader(statusCode)
}
