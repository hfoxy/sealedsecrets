package logging

import (
	"context"
	"github.com/hfoxy/cobra-starter/flags"
	"github.com/hfoxy/cobra-starter/version"
	slogmulti "github.com/samber/slog-multi"
	"gopkg.in/natefinch/lumberjack.v2"
	"io"
	"log/slog"
	"os"
	"strings"
)

var LogFormat = "text"
var LogOutputs = "stdout"

var rootLogger *slog.Logger
var AddSource = false

func Init() {
	level := slog.LevelInfo
	if flags.DebugEnabled {
		level = slog.LevelDebug
	}

	rootLogger = slog.New(slogmulti.Fanout(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})))

	outputs := strings.Split(LogOutputs, ",")
	if len(outputs) == 0 {
		outputs = []string{"stdout"}
	}

	if flags.DebugEnabled {
		rootLogger.Info("Debug logging enabled")
	}

	handlers := make([]slog.Handler, 0, len(outputs))
	for _, output := range outputs {
		format := LogFormat

		o := strings.Split(output, ":")
		if len(o) == 2 {
			output = o[0]
			format = o[1]
		}

		var handler slog.Handler
		var writer io.Writer
		switch output {
		case "stdout":
			writer = os.Stdout
		case "file":
			logger := &lumberjack.Logger{
				Filename:   "app.log",
				MaxSize:    10, // megabytes
				MaxBackups: 3,
				MaxAge:     28,   //days
				Compress:   true, // disabled by default
			}

			writer = logger
		}

		if handler == nil {
			switch format {
			case "text":
				handler = slog.NewTextHandler(writer, &slog.HandlerOptions{Level: level, AddSource: AddSource})
			case "json":
				handler = slog.NewJSONHandler(writer, &slog.HandlerOptions{Level: level, AddSource: AddSource})
			}
		}

		handlers = append(handlers, handler)
	}

	rootLogger = slog.New(slogmulti.Fanout(handlers...)).With("version", version.Version).With("environment", version.Environment)
}

func Logger() *slog.Logger {
	return rootLogger
}

type stackTraceHandler struct {
	handler slog.Handler
}

func (s *stackTraceHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return s.handler.Enabled(ctx, level)
}

func (s *stackTraceHandler) Handle(ctx context.Context, record slog.Record) error {
	/*trace := sentry.NewStacktrace()
	  if len(trace.Frames) > 6 {
	  	trace.Frames = trace.Frames[:len(trace.Frames)-6]
	  }

	  record.Add("stacktrace", trace.Frames)*/
	return s.handler.Handle(ctx, record)
}

func (s *stackTraceHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &stackTraceHandler{handler: s.handler.WithAttrs(attrs)}
}

func (s *stackTraceHandler) WithGroup(name string) slog.Handler {
	return &stackTraceHandler{handler: s.handler.WithGroup(name)}
}
