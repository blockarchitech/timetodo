/*
 *    Copyright 2025 blockarchitech
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

package timetodo

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.20.0"
	oteltrace "go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
	"go.uber.org/fx"
	"go.uber.org/zap"

	"blockarchitech.com/timetodo/internal/config"
	"blockarchitech.com/timetodo/internal/handler"
	"blockarchitech.com/timetodo/internal/service"
	"blockarchitech.com/timetodo/internal/storage"
)

// newLogger creates a new Zap logger.
func newLogger() (*zap.Logger, error) {
	logger, err := zap.NewProduction()
	if err != nil {
		return nil, fmt.Errorf("can't initialize zap logger: %w", err)
	}
	return logger, nil
}

// newConfig loads the application configuration.
func newConfig(logger *zap.Logger) (*config.Config, error) {
	cfg, err := config.LoadConfig()
	if err != nil {
		logger.Fatal("Failed to load configuration", zap.Error(err))
		return nil, err // Should not reach here due to Fatal
	}
	return cfg, nil
}

// newOtelTracerProvider sets up the OpenTelemetry TracerProvider.
func newOtelTracerProvider(lc fx.Lifecycle, logger *zap.Logger, cfg *config.Config) (oteltrace.TracerProvider, error) {
	var tp oteltrace.TracerProvider
	var err error
	ctx := context.Background()

	if cfg.OtelExporterEndpoint != "" {
		traceExporter, err := otlptracehttp.New(ctx, otlptracehttp.WithEndpoint(cfg.OtelExporterEndpoint), otlptracehttp.WithInsecure())
		if err != nil {
			return nil, fmt.Errorf("failed to create OTLP HTTP trace exporter: %w", err)
		}

		res, err := resource.New(ctx,
			resource.WithAttributes(
				semconv.ServiceNameKey.String("timetodo"),
				semconv.ServiceVersionKey.String(cfg.Version),
			),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create OpenTelemetry resource: %w", err)
		}

		sdkTP := sdktrace.NewTracerProvider(
			sdktrace.WithBatcher(traceExporter),
			sdktrace.WithResource(res),
		)
		otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
		tp = sdkTP
		logger.Info("OTLP HTTP trace exporter initialized", zap.String("endpoint", cfg.OtelExporterEndpoint))

		lc.Append(fx.Hook{
			OnStop: func(ctx context.Context) error {
				logger.Info("Shutting down OTel tracer provider")
				return sdkTP.Shutdown(ctx)
			},
		})
	} else {
		logger.Info("OpenTelemetry exporter endpoint not configured, using NoopTracerProvider")
		tp = noop.NewTracerProvider()
	}
	otel.SetTracerProvider(tp)
	return tp, err
}

// newTracer creates a specific tracer instance.
func newTracer(tp oteltrace.TracerProvider) oteltrace.Tracer {
	return tp.Tracer("timetodo/fx")
}

// newTokenStore initializes the token store based on configuration.
func newTokenStore(lc fx.Lifecycle, logger *zap.Logger, cfg *config.Config) (storage.TokenStore, error) {
	var tokenStore storage.TokenStore
	var err error
	ctx := context.Background()

	switch cfg.StorageType {
	case "firestore":
		if cfg.GCPProjectID == "" {
			logger.Fatal("Firestore storage selected but GCP_PROJECT_ID is not set")
			return nil, fmt.Errorf("firestore storage selected but GCP_PROJECT_ID is not set")
		}
		tokenStore, err = storage.NewFirestoreTokenStore(ctx, cfg.GCPProjectID, logger, cfg)
		if err != nil {
			logger.Fatal("Failed to initialize Firestore token store", zap.Error(err))
			return nil, err
		}
	case "inmemory":
		tokenStore = storage.NewInMemoryTokenStore(logger)
		logger.Warn("using inmemory token store. Did you mean to do this?")
	default:
		err = fmt.Errorf("invalid storage type: %s", cfg.StorageType)
		logger.Fatal("Invalid storage type", zap.String("storageType", cfg.StorageType), zap.Error(err))
		return nil, err
	}

	lc.Append(fx.Hook{
		OnStop: func(ctx context.Context) error {
			logger.Info("Closing token store")
			return tokenStore.Close()
		},
	})
	return tokenStore, nil
}

// newPebbleTimelineService creates a new PebbleTimelineService.
func newPebbleTimelineService(cfg *config.Config, tracer oteltrace.Tracer, logger *zap.Logger) *service.PebbleTimelineService {
	return service.NewPebbleTimelineService(cfg.PebbleTimelineAPIURL, tracer, logger)
}

// newTodoistService creates a new TodoistService.
func newTodoistService(tracer oteltrace.Tracer, logger *zap.Logger, config *config.Config) *service.TodoistService {
	return service.NewTodoistService(tracer, logger, config)
}

// newHttpHandlers creates the HTTP handlers.
func newHttpHandlers(
	logger *zap.Logger,
	cfg *config.Config,
	tokenStore storage.TokenStore,
	todoistService *service.TodoistService,
	pebbleService *service.PebbleTimelineService,
	tracer oteltrace.Tracer,
) *handler.HttpHandlers {
	return handler.NewHttpHandlers(logger, cfg.TodoistOAuthConfig, tokenStore, cfg, todoistService, pebbleService, tracer)
}

// registerHooks sets up the HTTP server and routes.
func registerHooks(
	lc fx.Lifecycle,
	logger *zap.Logger,
	cfg *config.Config,
	handlers *handler.HttpHandlers,
	tp oteltrace.TracerProvider,
) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/me", handlers.HandleMe)
	mux.HandleFunc("DELETE /api/v1/me", handlers.HandleDeleteMe)
	mux.HandleFunc("POST /api/v1/todoist", handlers.HandleTodoistWebhook)

	mux.HandleFunc("GET /auth/login", handlers.HandleTodoistLogin)
	mux.HandleFunc("GET /auth/callback", handlers.HandleTodoistCallback)
	mux.HandleFunc("GET /auth/delete", handlers.HandleDeletePage)

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET /robots.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("User-agent: *\nDisallow: /\n")) // go away!!!!!!
	})

	mux.HandleFunc("GET /api/v1/googletasks", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body><img src=\"https://http.cat/418\" alt=\"I'm a teapot\" /></body></html>"))
	})

	var httpHandler http.Handler = mux
	if cfg.OtelExporterEndpoint != "" {
		httpHandler = otelhttp.NewHandler(mux, "timetodo-http",
			otelhttp.WithTracerProvider(tp), // Use the injected TracerProvider
			otelhttp.WithPropagators(otel.GetTextMapPropagator()),
		)
	}

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%s", cfg.Port),
		Handler:      httpHandler,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	lc.Append(fx.Hook{
		OnStart: func(ctx context.Context) error {
			go func() {
				logger.Info("Server starting", zap.String("address", srv.Addr))
				if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					logger.Fatal("Could not listen on address", zap.String("address", srv.Addr), zap.Error(err))
				}
			}()
			return nil
		},
		OnStop: func(ctx context.Context) error {
			logger.Info("Server shutting down...")
			ctxShutdown, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			return srv.Shutdown(ctxShutdown)
		},
	})
}

// NewApp creates a new FX application.
func NewApp() *fx.App {
	return fx.New(
		fx.Provide(
			newLogger,
			newConfig,
			newOtelTracerProvider,
			newTracer,
			newTokenStore,
			newPebbleTimelineService,
			newTodoistService,
			newHttpHandlers,
		),
		fx.Invoke(registerHooks),
		fx.NopLogger,
	)
}
