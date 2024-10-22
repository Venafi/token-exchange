package logging

import (
	"context"
	"log/slog"
)

type ctxKey int

const (
	loggerCtxKey ctxKey = 0
)

func ContextWithLogger(ctx context.Context, logger *slog.Logger) context.Context {
	return context.WithValue(ctx, loggerCtxKey, logger)
}

func LoggerFromContext(ctx context.Context) *slog.Logger {
	val, ok := ctx.Value(loggerCtxKey).(*slog.Logger)
	if !ok {
		return slog.Default()
	}

	return val
}
