package srvtool

import (
	"fmt"
	"net/http"
)

func Error(code int, message string) *HTTPError {
	return &HTTPError{
		HTTPCode: code,
		Message:  message,
	}
}

func Errorf(code int, fmtStr string, args ...any) *HTTPError {
	return &HTTPError{
		HTTPCode: code,
		Message:  fmt.Sprintf(fmtStr, args...),
	}
}

type HTTPError struct {
	HTTPCode int    `json:"-"`
	Message  string `json:"message"`
}

func (he HTTPError) Error() string {
	return he.Message
}

func (he HTTPError) Response() *Response {
	code := he.HTTPCode
	if code == 0 {
		code = http.StatusInternalServerError
	}

	return &Response{
		HTTPCode: code,
		Body:     errMsg{Error: he.Message},
	}
}

type errMsg struct {
	Error string `json:"error"`
}
