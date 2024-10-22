package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"time"
	"token-exchange/testserver"
)

func main() {
	runCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer stop()

	srv, err := testserver.Create(runCtx, &testserver.Config{Greeting: "hello, world"})
	if err != nil {
		panic(err)
	}

	go func() {
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			panic(err)
		}
	}()

	<-runCtx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		panic(err)
	}

	if err := srv.Shutdown(shutdownCtx); err != nil {
		panic(err)
	}
}
