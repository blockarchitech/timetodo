/*
 * Copyright 2025 blockarchitech
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package handler

import (
	"blockarchitech.com/timetodo/internal/config"
	"blockarchitech.com/timetodo/internal/service"
	"blockarchitech.com/timetodo/internal/storage"
	"blockarchitech.com/timetodo/internal/types/pebble"
	"blockarchitech.com/timetodo/internal/types/todoist"
	"blockarchitech.com/timetodo/internal/utils"
	"blockarchitech.com/timetodo/internal/view"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"io"
	"net/http"
	"net/url"
	"time"
)

const (
	oauthStateCookieName               = "timetodo_oauth_state"
	oauthPebbleAccountTokenCookieName  = "timetodo_oauth_p_acc_token"
	oauthPebbleTimelineTokenCookieName = "timetodo_oauth_p_timeline_token"
	oauthCookieMaxAge                  = 300 // 5 minutes
	pebbleCloseSuccessURL              = "pebblejs://close#{\"status\":\"success\"}"
)

// HttpHandlers holds application-wide state and dependencies.
type HttpHandlers struct {
	logger                *zap.Logger
	tokenStore            storage.TokenStore
	oauth2Config          *oauth2.Config
	config                *config.Config
	htmlManager           *view.HTMLTemplateManager
	pebbleTimelineService *service.PebbleTimelineService
	todoistService        *service.TodoistService
	Tracer                trace.Tracer
	Utils                 *utils.TodoistUtils
}

// NewHttpHandlers creates a new HttpHandlers instance.
func NewHttpHandlers(
	logger *zap.Logger,
	oauth2Config *oauth2.Config,
	tokenStore storage.TokenStore,
	htmlManager *view.HTMLTemplateManager,
	cfg *config.Config,
	todoistService *service.TodoistService,
	pebbleService *service.PebbleTimelineService,
	tracer trace.Tracer,
) *HttpHandlers {
	return &HttpHandlers{
		logger:                logger.Named("http_handler"),
		tokenStore:            tokenStore,
		oauth2Config:          oauth2Config,
		config:                cfg,
		htmlManager:           htmlManager,
		pebbleTimelineService: pebbleService,
		todoistService:        todoistService,
		Tracer:                tracer,
		Utils:                 utils.NewTodoistUtils(cfg, logger.Named("todoist_utils")),
	}
}

// --- HTTP Handlers ---

// HandlePebbleConfig serves the Pebble configuration page.
// It checks for Pebble tokens and existing authentication,
// otherwise, it provides a login URL.
func (h *HttpHandlers) HandlePebbleConfig(w http.ResponseWriter, r *http.Request) {
	ctx, span := h.Tracer.Start(r.Context(), "HandlePebbleConfig")
	defer span.End()

	pebbleTimelineToken := r.URL.Query().Get("timeline_token")
	pebbleAccountToken := r.URL.Query().Get("account_token")

	span.SetAttributes(
		attribute.Bool("pebble.timeline_token_present", pebbleTimelineToken != ""),
		attribute.Bool("pebble.account_token_present", pebbleAccountToken != ""),
	)

	data := make(map[string]string)

	if pebbleTimelineToken == "" || pebbleAccountToken == "" {
		h.logger.Warn("Missing required Pebble tokens in config request")
		data["error"] = "Missing required Pebble tokens. Please open from Pebble app settings."
		h.renderConfigPage(w, data, http.StatusBadRequest)
		return
	}

	user, found, err := h.tokenStore.GetTokensByPebbleAccount(ctx, pebbleAccountToken)
	if err != nil {
		h.logger.Error("Error getting tokens by Pebble account", zap.Error(err))
		data["status"] = "error"
		data["error"] = "Could not retrieve stored configuration."
		h.renderConfigPage(w, data, http.StatusInternalServerError)
		return
	}

	if found && user.TodoistAccessToken != nil && user.TodoistAccessToken.Valid() {
		h.logger.Info("User already authenticated", zap.String("pebbleAccountToken", pebbleAccountToken))
		data["status"] = "success"
	}

	h.renderConfigPage(w, data, http.StatusOK)
}

// HandleTodoistLogin initiates the OAuth2 flow with Todoist.
// It generates a state, sets cookies, and redirects to Todoist.
func (h *HttpHandlers) HandleTodoistLogin(w http.ResponseWriter, r *http.Request) {
	_, span := h.Tracer.Start(r.Context(), "HandleTodoistLogin")
	defer span.End()

	pebbleAccountToken := r.URL.Query().Get("pebble_account_token")
	pebbleTimelineToken := r.URL.Query().Get("pebble_timeline_token")

	if pebbleAccountToken == "" || pebbleTimelineToken == "" {
		h.logger.Warn("Missing Pebble tokens in login request")
		h.httpError(w, span, "Missing Pebble account or timeline token", nil, http.StatusBadRequest)
		return
	}

	state, err := generateOAuthState()
	if err != nil {
		h.httpError(w, span, "Failed to generate OAuth state", err, http.StatusInternalServerError)
		return
	}

	h.setCookie(w, r, oauthStateCookieName, state, oauthCookieMaxAge)
	h.setCookie(w, r, oauthPebbleAccountTokenCookieName, pebbleAccountToken, oauthCookieMaxAge)
	h.setCookie(w, r, oauthPebbleTimelineTokenCookieName, pebbleTimelineToken, oauthCookieMaxAge)

	authURL := h.oauth2Config.AuthCodeURL(state)
	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

// HandleTodoistCallback handles the OAuth2 callback from Todoist.
// It validates the state, exchanges the code for a token,
// fetches user info, stores tokens, and redirects back to Pebble.
func (h *HttpHandlers) HandleTodoistCallback(w http.ResponseWriter, r *http.Request) {
	ctx, span := h.Tracer.Start(r.Context(), "HandleTodoistCallback")
	defer span.End()

	// Check for errors from Todoist
	if errMsg := r.URL.Query().Get("error"); errMsg != "" {
		h.logger.Warn("Todoist OAuth callback returned an error", zap.String("error", errMsg))
		h.redirectWithError(w, r, "Todoist authorization failed: "+errMsg)
		return
	}

	// Validate state cookie
	stateCookie, err := r.Cookie(oauthStateCookieName)
	if err != nil || r.URL.Query().Get("state") != stateCookie.Value {
		h.logger.Warn("Invalid OAuth state or cookie not found", zap.Error(err))
		h.redirectWithError(w, r, "Invalid OAuth state, please try again.")
		return
	}

	// Exchange code for token
	code := r.URL.Query().Get("code")
	todoistToken, err := h.oauth2Config.Exchange(ctx, code)
	if err != nil {
		h.logger.Error("Failed to exchange Todoist token", zap.Error(err))
		h.redirectWithError(w, r, "Todoist token exchange failed.")
		return
	}
	span.SetAttributes(attribute.Bool("todoist.token_exchanged", true))

	// Get Todoist user info
	todoistUser, err := h.todoistService.GetUser(ctx, todoistToken.AccessToken)
	if err != nil {
		h.logger.Error("Failed to get Todoist user info", zap.Error(err))
		h.redirectWithError(w, r, "Failed to retrieve Todoist user information.")
		return
	}

	// Retrieve Pebble tokens from cookies
	pebbleAccountToken, pebbleTimelineToken, err := h.getPebbleTokensFromCookies(r)
	if err != nil {
		h.logger.Error("Failed to retrieve Pebble tokens from cookies", zap.Error(err))
		h.redirectWithError(w, r, "Session error, please retry configuration.")
		return
	}

	// Store user data
	user := storage.User{
		PebbleAccountToken:  pebbleAccountToken,
		PebbleTimelineToken: pebbleTimelineToken,
		TodoistAccessToken:  todoistToken,
		TodoistUserID:       todoistUser.User.ID,
		Timezone:            todoistUser.User.TimezoneInfo.Timezone,
		TimezoneHourOffset:  todoistUser.User.TimezoneInfo.Hours,
		LastUpdated:         time.Now(),
	}

	if err := h.tokenStore.StoreTokens(ctx, pebbleAccountToken, user); err != nil {
		h.logger.Error("Failed to store tokens", zap.Error(err))
		h.redirectWithError(w, r, "Failed to save configuration.")
		return
	}

	// Clear cookies
	h.clearOAuthCookies(w, r)

	h.logger.Info("Successfully authenticated and stored tokens",
		zap.String("pebbleAccountToken", pebbleAccountToken),
		zap.Int64("todoistUserID", todoistUser.User.ID),
	)
	span.SetAttributes(
		attribute.String("pebble.account_token", pebbleAccountToken),
		attribute.Int64("todoist.user_id", todoistUser.User.ID),
	)

	// Redirect to Pebble close with success
	http.Redirect(w, r, pebbleCloseSuccessURL, http.StatusTemporaryRedirect)
}

// HandleTodoistWebhook processes incoming webhooks from Todoist.
// It verifies the signature, parses the payload, and processes relevant events.
func (h *HttpHandlers) HandleTodoistWebhook(w http.ResponseWriter, r *http.Request) {
	ctx, span := h.Tracer.Start(r.Context(), "HandleTodoistWebhook")
	defer span.End()

	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.httpError(w, span, "Failed to read webhook body", err, http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	// Verify signature
	signature := r.Header.Get("X-Todoist-Hmac-SHA256")
	if !h.Utils.VerifyTodoistSignature(signature, body) {
		h.logger.Warn("Invalid Todoist webhook signature")
		span.SetStatus(codes.Error, "Invalid signature")
		http.Error(w, "Invalid signature", http.StatusForbidden)
		return
	}

	// Unmarshal payload
	var payload todoist.WebhookPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		h.httpError(w, span, "Failed to unmarshal webhook payload", err, http.StatusBadRequest)
		return
	}

	span.SetAttributes(
		attribute.String("todoist.event_name", payload.EventName),
		attribute.Int64("todoist.user_id", payload.UserID),
	)
	h.logger.Info("Received Todoist webhook", zap.String("eventName", payload.EventName), zap.Int64("userID", payload.UserID))

	// Fetch user tokens
	user, found, err := h.tokenStore.GetTokensByTodoistUserID(ctx, payload.UserID)
	if err != nil || !found {
		logMsg := "Failed to get tokens by Todoist User ID"
		if !found {
			logMsg = "No tokens found for Todoist User ID"
		}
		h.logger.Warn(logMsg, zap.Int64("todoistUserID", payload.UserID), zap.Error(err))
		span.SetStatus(codes.Error, logMsg)
		span.RecordError(err)
		w.WriteHeader(http.StatusOK) // Return 200 OK to prevent retries
		return
	}

	// Process event
	switch payload.EventName {
	case "item:added", "item:updated":
		h.processTaskEvent(ctx, span, user, payload)
	// Add cases for "item:deleted", "item:completed" if needed
	default:
		h.logger.Info("Unhandled webhook event type", zap.String("eventName", payload.EventName))
		span.SetAttributes(attribute.String("app.webhook_unhandled_event", payload.EventName))
	}

	w.WriteHeader(http.StatusOK) // Acknowledge webhook
}

// --- Helper Functions ---

// processTaskEvent handles item:added and item:updated webhook events.
func (h *HttpHandlers) processTaskEvent(ctx context.Context, span trace.Span, user storage.User, payload todoist.WebhookPayload) {
	var taskData todoist.TaskEventData
	if err := json.Unmarshal(payload.EventData, &taskData); err != nil {
		h.logger.Error("Failed to unmarshal task data from webhook", zap.Error(err), zap.String("eventName", payload.EventName))
		span.RecordError(err)
		return
	}

	// Skip if no due date
	if taskData.Due == nil || taskData.Due.Date == "" {
		h.logger.Info("Task has no due date, skipping pin creation", zap.String("taskID", taskData.ID))
		span.SetAttributes(attribute.String("app.pin_skipped_reason", "no_due_date"))
		return
	}

	// Parse due date
	dueTime, err := h.Utils.ParseTodoistDueDateTime(taskData.Due, user.Timezone)
	if err != nil {
		h.logger.Error("Failed to parse due date from webhook task", zap.Error(err), zap.Any("dueObject", taskData.Due))
		span.RecordError(err)
		return
	}

	// Create and marshal pin
	pin := createPebblePin(payload.UserID, taskData, dueTime)
	pinJSON, err := json.Marshal(pin)
	if err != nil {
		h.logger.Error("Failed to marshal Pebble pin for webhook task", zap.Error(err))
		span.RecordError(err)
		return
	}

	// Ensure Pebble Timeline Token exists
	if user.PebbleTimelineToken == "" {
		h.logger.Warn("User has no Pebble Timeline Token, cannot push pin", zap.Int64("todoistUserID", payload.UserID))
		span.SetAttributes(attribute.String("app.pin_skipped_reason", "no_pebble_timeline_token"))
		return
	}

	// Push pin to Pebble
	err, statusCode := h.pebbleTimelineService.PushPin(ctx, user.PebbleTimelineToken, pinJSON)
	if err != nil {
		h.logger.Error("Failed to push Pebble pin from webhook task", zap.Error(err), zap.String("pinID", pin.ID))
		span.RecordError(err)
		// Handle 410 Gone: Token is invalid, delete the user account
		if statusCode == http.StatusGone {
			h.handleInvalidPebbleToken(ctx, payload.UserID)
		}
		return
	}

	h.logger.Info("Successfully pushed Pebble pin from webhook task", zap.String("pinID", pin.ID))
	span.SetAttributes(attribute.String("app.pin_id_pushed", pin.ID))
}

// handleInvalidPebbleToken deletes user data when their Pebble token is invalid (410 Gone).
func (h *HttpHandlers) handleInvalidPebbleToken(ctx context.Context, userID int64) {
	h.logger.Warn("Pebble Timeline token is no longer valid, deleting user account", zap.Int64("todoistUserID", userID))
	if err := h.tokenStore.DeleteTokensByTodoistUserID(ctx, userID); err != nil {
		h.logger.Error("Failed to delete user tokens after 410", zap.Error(err), zap.Int64("todoistUserID", userID))
	} else {
		h.logger.Info("Successfully deleted user tokens after 410", zap.Int64("todoistUserID", userID))
	}
}

// createPebblePin constructs a Pebble Pin object from task data.
func createPebblePin(userID int64, taskData todoist.TaskEventData, dueTime time.Time) pebble.Pin {
	return pebble.Pin{
		ID:   fmt.Sprintf("todoist-%d-%s", userID, taskData.ID),
		Time: dueTime.Format(time.RFC3339),
		Layout: pebble.PinLayout{
			Type:     "genericPin",
			Title:    taskData.Content,
			TinyIcon: "system://images/NOTIFICATION_FLAG",
		},
	}
}

// getPebbleTokensFromCookies retrieves Pebble account and timeline tokens from request cookies.
func (h *HttpHandlers) getPebbleTokensFromCookies(r *http.Request) (string, string, error) {
	pebbleAccountTokenCookie, errAcc := r.Cookie(oauthPebbleAccountTokenCookieName)
	pebbleTimelineTokenCookie, errTime := r.Cookie(oauthPebbleTimelineTokenCookieName)

	if errAcc != nil {
		return "", "", fmt.Errorf("account token cookie error: %w", errAcc)
	}
	if errTime != nil {
		return "", "", fmt.Errorf("timeline token cookie error: %w", errTime)
	}

	return pebbleAccountTokenCookie.Value, pebbleTimelineTokenCookie.Value, nil
}

// clearOAuthCookies removes OAuth-related cookies.
func (h *HttpHandlers) clearOAuthCookies(w http.ResponseWriter, r *http.Request) {
	h.setCookie(w, r, oauthStateCookieName, "", -1)
	h.setCookie(w, r, oauthPebbleAccountTokenCookieName, "", -1)
	h.setCookie(w, r, oauthPebbleTimelineTokenCookieName, "", -1)
}

// renderConfigPage renders the config.html template with the given data and status code.
func (h *HttpHandlers) renderConfigPage(w http.ResponseWriter, data map[string]string, statusCode int) {
	w.WriteHeader(statusCode)
	if err := h.htmlManager.Render(w, "config.html", data); err != nil {
		h.logger.Error("Failed to render config page", zap.Error(err), zap.Any("data", data))
		http.Error(w, "Failed to render page", http.StatusInternalServerError)
	}
}

// redirectWithError redirects the user to the Pebble config page with an error message.
func (h *HttpHandlers) redirectWithError(w http.ResponseWriter, r *http.Request, message string) {
	h.logger.Warn("Redirecting with error", zap.String("message", message))
	redirectURL := fmt.Sprintf("%s/config/pebble?status=error&error=%s",
		h.config.AppBaseURL,
		url.QueryEscape(message),
	)
	http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
}

// httpError logs an error, updates the span, and sends an HTTP error response.
func (h *HttpHandlers) httpError(w http.ResponseWriter, span trace.Span, message string, err error, statusCode int) {
	h.logger.Error(message, zap.Error(err))
	if span != nil {
		span.SetStatus(codes.Error, message)
		span.RecordError(err)
	}
	http.Error(w, message, statusCode)
}

// setCookie sets an HTTP cookie with common secure defaults.
func (h *HttpHandlers) setCookie(w http.ResponseWriter, r *http.Request, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https", // Check for TLS or proxy
		MaxAge:   maxAge,
		SameSite: http.SameSiteLaxMode,
	})
}

// generateOAuthState creates a random base64 string for OAuth state.
func generateOAuthState() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("failed to read random bytes for state: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
