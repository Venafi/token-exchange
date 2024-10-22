package testserver

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"
	"token-exchange/srvtool"
)

type Config struct {
	Greeting string
}

func Create(ctx context.Context, config *Config) (*http.Server, error) {
	srv := &http.Server{
		BaseContext: func(_ net.Listener) context.Context { return ctx },

		Addr: "127.0.0.1:9939",

		ReadTimeout:    5 * time.Second,
		WriteTimeout:   5 * time.Second,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 10 * 1024,

		Handler: newServer(config.Greeting),
	}

	return srv, nil
}

type server struct {
	Greeting string

	mux *http.ServeMux
}

func newServer(greeting string) *server {
	mux := http.NewServeMux()

	srv := &server{
		Greeting: greeting,

		mux: mux,
	}

	mux.HandleFunc("GET /test/{name}", srvtool.JSON(srv.handleTestRequest))

	return srv
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

type respMsg struct {
	Name     string `json:"name"`
	Greeting string `json:"greeting"`
}

func (s *server) handleTestRequest(w http.ResponseWriter, r *http.Request) (*srvtool.Response, *srvtool.HTTPError) {
	name := r.PathValue("name")

	switch strings.ToLower(name) {
	case "error":
		return nil, &srvtool.HTTPError{
			HTTPCode: 400,
			Message:  "bad idea to call yourself 'error'",
		}

	default:
		return &srvtool.Response{
			Body: respMsg{
				Name:     name,
				Greeting: "greeting",
			},
		}, nil
	}

}
