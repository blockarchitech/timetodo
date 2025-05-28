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

package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// PebbleTimelineService handles interactions with the Pebble Timeline API.
type PebbleTimelineService struct {
	apiURL     string
	httpClient *http.Client
	tracer     trace.Tracer
	logger     *zap.Logger
}

// NewPebbleTimelineService creates a new PebbleTimelineService.
func NewPebbleTimelineService(apiURL string, tracer trace.Tracer, logger *zap.Logger) *PebbleTimelineService {
	return &PebbleTimelineService{
		apiURL: apiURL,
		httpClient: &http.Client{
			Transport: otelhttp.NewTransport(http.DefaultTransport,
				otelhttp.WithTracerProvider(otel.GetTracerProvider()),
			),
			Timeout: 10 * time.Second,
		},
		tracer: tracer,
		logger: logger.Named("pebble_timeline_service"),
	}
}

// PinID is a helper struct to extract the pin ID from the JSON data.
type PinID struct {
	ID string `json:"id"`
}

// PushPin sends a pin to the Pebble Timeline API.
func (s *PebbleTimelineService) PushPin(ctx context.Context, userTimelineToken string, pinData []byte) (error, int) {
	ctx, span := s.tracer.Start(ctx, "PebbleTimelineService.PushPin")
	defer span.End()

	var pin PinID
	if err := json.Unmarshal(pinData, &pin); err != nil {
		s.logger.Error("Failed to unmarshal pin data to get ID", zap.Error(err), zap.ByteString("pinData", pinData))
		span.RecordError(err)
		span.SetStatus(codes.Error, "Unmarshal pin data failed")
		return fmt.Errorf("failed to unmarshal pin data for ID: %w", err), 0
	}

	if pin.ID == "" {
		err := fmt.Errorf("pin ID is empty in provided data")
		s.logger.Error("Pin ID is missing", zap.Error(err), zap.ByteString("pinData", pinData))
		span.RecordError(err)
		span.SetStatus(codes.Error, "Pin ID missing")
		return err, 0
	}

	s.logger.Warn("pin data", zap.ByteString("pinData", pinData), zap.String("pinID", pin.ID))

	url := fmt.Sprintf("%s/v1/user/pins/%s", s.apiURL, pin.ID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(pinData))
	if err != nil {
		s.logger.Error("Failed to create PushPin request", zap.String("url", url), zap.Error(err))
		span.RecordError(err)
		span.SetStatus(codes.Error, "Create request failed")
		return fmt.Errorf("failed to create request: %w", err), 0
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-User-Token", userTimelineToken)

	span.SetAttributes(
		attribute.String("http.url", url),
		attribute.String("pin.id", pin.ID),
	)

	s.logger.Debug("Pushing pin to Pebble Timeline API", zap.String("url", url), zap.String("pinID", pin.ID))

	resp, err := s.httpClient.Do(req)
	if err != nil {
		s.logger.Error("Failed to send PushPin request", zap.String("url", url), zap.Error(err))
		span.RecordError(err)
		span.SetStatus(codes.Error, "HTTP request failed")
		return fmt.Errorf("failed to send request: %w", err), 0
	}
	defer resp.Body.Close()

	span.SetAttributes(attribute.Int("http.status_code", resp.StatusCode))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		err := fmt.Errorf("Pebble Timeline API returned non-success status %d: %s", resp.StatusCode, string(bodyBytes))
		s.logger.Error("Pebble Timeline API error",
			zap.Int("statusCode", resp.StatusCode),
			zap.String("url", url),
			zap.String("responseBody", string(bodyBytes)),
		)
		span.RecordError(err)
		span.SetStatus(codes.Error, "API returned non-success")
		return err, resp.StatusCode // if the status code is 410, the webhook handler must delete the account as the user has removed the app from their Pebble
	}

	s.logger.Info("Successfully pushed pin to Pebble Timeline", zap.String("pinID", pin.ID), zap.Int("statusCode", resp.StatusCode))
	span.SetStatus(codes.Ok, "Pin pushed successfully")
	return nil, resp.StatusCode
}
