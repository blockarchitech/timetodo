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
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"blockarchitech.com/timetodo/internal/config"
	"blockarchitech.com/timetodo/internal/handler"
	"blockarchitech.com/timetodo/internal/repository"
	"blockarchitech.com/timetodo/internal/service"
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.20.0"
	"go.uber.org/zap"
)

type App struct {
	logger *zap.Logger
	cfg    *config.Config
	server *http.Server
}

func NewApp() *App {
	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("can't initialize zap logger: %v", err)
	}
	defer logger.Sync()

	cfg, err := config.LoadConfig()
	if err != nil {
		logger.Fatal("Failed to load configuration", zap.Error(err))
	}

	return &App{
		logger: logger,
		cfg:    cfg,
	}
}

func (a *App) Run() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var tp *sdktrace.TracerProvider
	if a.cfg.OtelExporterEndpoint != "" {
		tp = a.initTracerProvider(ctx)
		defer func() {
			if err := tp.Shutdown(ctx); err != nil {
				a.logger.Error("Error shutting down tracer provider", zap.Error(err))
			}
		}()
		otel.SetTracerProvider(tp)
		otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	}

	userRepo, err := a.initUserRepository(ctx)
	if err != nil {
		a.logger.Fatal("Failed to initialize user repository", zap.Error(err))
	}
	defer userRepo.Close()

	tracer := otel.Tracer("timetodo")

	pebbleService := service.NewPebbleTimelineService(a.cfg.PebbleTimelineAPIURL, tracer, a.logger)
	todoistService := service.NewTodoistService(tracer, a.logger, a.cfg)

	handlers := handler.NewHttpHandlers(a.logger, a.cfg.TodoistOAuthConfig, userRepo, a.cfg, todoistService, pebbleService, tracer)

	router := a.setupRouter(handlers, tp)

	a.server = &http.Server{
		Addr:         fmt.Sprintf(":%s", a.cfg.Port),
		Handler:      router,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		a.logger.Info("Server starting", zap.String("address", a.server.Addr))
		if err := a.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			a.logger.Fatal("Could not listen on address", zap.String("address", a.server.Addr), zap.Error(err))
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	a.logger.Info("Server shutting down...")

	ctxShutdown, cancelShutdown := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelShutdown()

	if err := a.server.Shutdown(ctxShutdown); err != nil {
		a.logger.Fatal("Server shutdown failed", zap.Error(err))
	}
	a.logger.Info("Server exited properly")
}

func (a *App) initTracerProvider(ctx context.Context) *sdktrace.TracerProvider {
	traceExporter, err := otlptracehttp.New(ctx, otlptracehttp.WithEndpoint(a.cfg.OtelExporterEndpoint), otlptracehttp.WithInsecure())
	if err != nil {
		a.logger.Fatal("Failed to create OTLP HTTP trace exporter", zap.Error(err))
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceNameKey.String("timetodo"),
			semconv.ServiceVersionKey.String(a.cfg.Version),
		),
	)
	if err != nil {
		a.logger.Fatal("Failed to create OpenTelemetry resource", zap.Error(err))
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(traceExporter),
		sdktrace.WithResource(res),
	)
	a.logger.Info("OTLP HTTP trace exporter initialized", zap.String("endpoint", a.cfg.OtelExporterEndpoint))
	return tp
}

func (a *App) initUserRepository(ctx context.Context) (repository.UserRepository, error) {
	switch a.cfg.StorageType {
	case "firestore":
		if a.cfg.GCPProjectID == "" {
			return nil, fmt.Errorf("firestore storage selected but GCP_PROJECT_ID is not set")
		}
		return repository.NewFirestoreUserRepository(ctx, a.cfg.GCPProjectID, a.logger, a.cfg)
	case "inmemory":
		a.logger.Warn("using inmemory user repository. Did you mean to do this?")
		return repository.NewInMemoryUserRepository(a.logger), nil
	default:
		return nil, fmt.Errorf("invalid storage type: %s", a.cfg.StorageType)
	}
}

func (a *App) setupRouter(handlers *handler.HttpHandlers, tp *sdktrace.TracerProvider) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())

	if tp != nil {
		router.Use(otelgin.Middleware("timetodo-http", otelgin.WithTracerProvider(tp)))
	}

	handlers.RegisterRoutes(router)

	router.GET("/healthz", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	router.GET("/robots.txt", func(c *gin.Context) {
		c.Header("Content-Type", "text/plain")
		c.String(http.StatusOK, "User-agent: *\nDisallow: /\n")
	})

	return router
}
