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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

const todoistAPIBaseURL = "https://api.todoist.com/api/v1"

// TodoistService is responsible for interacting with the Todoist API.
type TodoistService struct {
	client     *http.Client
	tracer     trace.Tracer
	logger     *zap.Logger
	apiTimeout time.Duration
}

// NewTodoistService creates a new TodoistService.
func NewTodoistService(tracer trace.Tracer, logger *zap.Logger) *TodoistService {
	client := &http.Client{
		Transport: otelhttp.NewTransport(http.DefaultTransport,
			otelhttp.WithTracerProvider(otel.GetTracerProvider()),
		),
		Timeout: 15 * time.Second,
	}
	return &TodoistService{
		client:     client,
		tracer:     tracer,
		logger:     logger.Named("todoist_service"),
		apiTimeout: 15 * time.Second,
	}
}

// todoistUserResponse is a minimal struct to unmarshal the user object from Todoist Sync API.
type TodoistUserResponse struct {
	User struct {
		ID           int64  `json:"id,string"` // Use json.Number to handle potential string or number
		Email        string `json:"email"`
		FullName     string `json:"full_name"`
		TimezoneInfo struct {
			Timezone string `json:"timezone"`
			Hours    int    `json:"hours"`
		} `json:"tz_info"`
	} `json:"user"`
	SyncToken string `json:"sync_token"`
}

// GetUserID fetches the Todoist User ID for the given access token.
func (s *TodoistService) GetUser(ctx context.Context, accessToken string) (TodoistUserResponse, error) {
	s.logger.Debug("Fetching Todoist User ID")

	formData := url.Values{}
	formData.Set("sync_token", "*")
	formData.Set("resource_types", `["user"]`)

	reqCtx, cancel := context.WithTimeout(ctx, s.apiTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, todoistAPIBaseURL+"/sync", strings.NewReader(formData.Encode()))
	if err != nil {
		s.logger.Error("Failed to create request to fetch Todoist user ID", zap.Error(err))
		return TodoistUserResponse{}, fmt.Errorf("failed to create request for Todoist user ID: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.client.Do(req)
	if err != nil {
		s.logger.Error("Request to fetch Todoist user ID failed", zap.Error(err))
		return TodoistUserResponse{}, fmt.Errorf("request to Todoist API failed: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		s.logger.Error("Failed to read response body from Todoist user ID request", zap.Error(err))
		return TodoistUserResponse{}, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		s.logger.Error("Todoist API returned non-OK status for user ID request",
			zap.Int("statusCode", resp.StatusCode),
			zap.ByteString("responseBody", bodyBytes),
		)
		return TodoistUserResponse{}, fmt.Errorf("Todoist API returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var userResp TodoistUserResponse
	if err := json.Unmarshal(bodyBytes, &userResp); err != nil {
		s.logger.Error("Failed to unmarshal Todoist user response", zap.Error(err), zap.ByteString("responseBody", bodyBytes))
		return TodoistUserResponse{}, fmt.Errorf("failed to unmarshal user response: %w", err)
	}

	return userResp, nil
}
