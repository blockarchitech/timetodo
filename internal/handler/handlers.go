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
		pebbleTimelineService: pebbleService,
		todoistService:        todoistService,
		Tracer:                tracer,
		Utils:                 utils.NewTodoistUtils(cfg, logger.Named("todoist_utils")),
	}
}

// --- HTTP Handlers ---

// HandleMe handles the HTTP request the Clay config page makes to check if the user exists and is authenticated via Todoist.
func (h *HttpHandlers) HandleMe(w http.ResponseWriter, r *http.Request) {
	ctx, span := h.Tracer.Start(r.Context(), "HandlePebbleConfig")
	defer span.End()

	// Check for Authorization header
	pebbleAccountToken, pebbleTimelineToken, err := getTokensFromHeader(r)
	if err != nil {
		h.logger.Warn("Missing or invalid Authorization header", zap.Error(err))
		span.RecordError(err)
		h.httpError(w, span, "Unauthorized", err, http.StatusUnauthorized)
		return
	}

	// Retrieve user tokens from storage
	user, found, err := h.tokenStore.GetTokensByPebbleAccount(ctx, pebbleAccountToken)
	if err != nil {
		h.logger.Error("Failed to retrieve user tokens", zap.Error(err), zap.String("pebbleAccountToken", pebbleAccountToken))
		h.httpError(w, span, "Failed to retrieve user", err, http.StatusInternalServerError)
		return
	}
	if !found {
		h.logger.Warn("User not found for Pebble account token", zap.String("pebbleAccountToken", pebbleAccountToken))
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if user.PebbleTimelineToken != pebbleTimelineToken {
		h.logger.Warn("Pebble Timeline Token mismatch", zap.String("pebbleAccountToken", pebbleAccountToken))
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	// Check if a Todoist access token is available
	if user.TodoistAccessToken == nil || user.TodoistAccessToken.AccessToken == "" {
		h.logger.Warn("Todoist access token is missing for user", zap.String("pebbleAccountToken", pebbleAccountToken))
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	// Respond with user data
	w.Header().Set("Content-Type", "application/json")
	response := map[string]interface{}{
		"todoistUserID": user.TodoistUserID,
		"timezone":      user.Timezone,
	}
	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Error("Failed to encode user response", zap.Error(err))
		h.httpError(w, span, "Failed to encode user response", err, http.StatusInternalServerError)
		return
	}
}

func (h *HttpHandlers) HandleDeleteMe(w http.ResponseWriter, r *http.Request) {
	ctx, span := h.Tracer.Start(r.Context(), "HandleDeleteMe")
	defer span.End()

	// Check for Authorization header
	pebbleAccountToken, _, err := getTokensFromHeader(r)
	if err != nil {
		h.logger.Warn("Missing or invalid Authorization header", zap.Error(err))
		span.RecordError(err)
		h.httpError(w, span, "Unauthorized", err, http.StatusUnauthorized)
		return
	}

	// User exists sanity check
	_, found, err := h.tokenStore.GetTokensByPebbleAccount(ctx, pebbleAccountToken)
	if err != nil {
		h.logger.Error("Failed to retrieve user tokens", zap.Error(err), zap.String("pebbleAccountToken", pebbleAccountToken))
		h.httpError(w, span, "Failed to retrieve user", err, http.StatusInternalServerError)
		return
	}
	if !found {
		h.logger.Warn("User not found for Pebble account token", zap.String("pebbleAccountToken", pebbleAccountToken))
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// Delete user tokens from storage
	if err := h.tokenStore.DeleteTokensByPebbleAccount(ctx, pebbleAccountToken); err != nil {
		h.logger.Error("Failed to delete user tokens", zap.Error(err), zap.String("pebbleAccountToken", pebbleAccountToken))
		h.httpError(w, span, "Failed to delete user", err, http.StatusInternalServerError)
		return
	}

	h.clearOAuthCookies(w, r)

	w.WriteHeader(http.StatusNoContent)
}

// HandleDeletePage serves a simple HTML page with a button to delete the user's account.
func (h *HttpHandlers) HandleDeletePage(w http.ResponseWriter, r *http.Request) {
	// This handler is for the delete page, which is literally just a button that sends a fetch() request to the /api/v1/me endpoint.
	// This is to avoid CORS issues with the Pebble app.
	_, span := h.Tracer.Start(r.Context(), "HandleDeletePage")
	defer span.End()
	// Check for Authorization header
	pebbleAccountToken, pebbleTimelineToken, err := getTokensFromQuery(r)
	if err != nil {
		h.logger.Warn("Missing or invalid Authorization header", zap.Error(err))
		span.RecordError(err)
		h.httpError(w, span, "Unauthorized", err, http.StatusUnauthorized)
		return
	}
	// construct HTML page
	html := fmt.Sprintf(`
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Delete Account</title>
	</head>
<body>
	<h1>Delete Account</h1>
	<p>Are you sure you want to delete your account? This action cannot be undone.</p>
	<button id="delete-button">Delete Account</button>
	<script>
		document.getElementById('delete-button').addEventListener('click', function() {
			fetch('/api/v1/me', {
				method: 'DELETE',
				headers: {
					'Authorization': 'Bearer ' + btoa('%s:%s')
				}
			}).then(response => {
				if (response.ok) {
					alert('Your account has been deleted successfully.');
					window.location.href = '%s';
				} else {
					alert('Failed to delete account. Please try again later.');
				}
			}).catch(error => {
				console.error('Error deleting account:', error);
				alert('An error occurred while deleting your account. Please try again later.');
			});
		});
	</script>
</body>
</html>
`, pebbleAccountToken, pebbleTimelineToken, pebbleCloseSuccessURL)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, err = w.Write([]byte(html))
	if err != nil {
		h.logger.Error("Failed to write HTML response", zap.Error(err))
		h.httpError(w, span, "Failed to write response", err, http.StatusInternalServerError)
		return
	}
}

// HandleTodoistLogin initiates the OAuth2 flow with Todoist.
// It generates a state, sets cookies, and redirects to Todoist.
func (h *HttpHandlers) HandleTodoistLogin(w http.ResponseWriter, r *http.Request) {
	_, span := h.Tracer.Start(r.Context(), "HandleTodoistLogin")
	defer span.End()

	pebbleAccountToken, pebbleTimelineToken, err := getTokensFromQuery(r)
	if err != nil {
		h.logger.Warn("Missing or invalid Authorization header", zap.Error(err))
		span.RecordError(err)
		h.httpError(w, span, "Unauthorized", err, http.StatusUnauthorized)
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

// getTokensFromHeader retrieves Pebble account and timeline tokens from the Authorization header.
func getTokensFromHeader(r *http.Request) (string, string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", "", fmt.Errorf("missing Authorization header")
	}
	parts := utils.SplitAndTrim(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return "", "", fmt.Errorf("invalid Authorization header format")
	}
	// Base64 decode the token part
	if len(parts[1]) == 0 {
		return "", "", fmt.Errorf("missing token in Authorization header")
	}

	return getTokens(parts[1])
}

// getTokensFromQuery retrieves Pebble account and timeline tokens from the query parameters.
func getTokensFromQuery(r *http.Request) (string, string, error) {
	base := r.URL.Query().Get("token")
	if base == "" {
		return "", "", fmt.Errorf("missing token query parameter")
	}
	// Split the token into account and timeline tokens
	if !utils.IsBase64(base) {
		return "", "", fmt.Errorf("invalid token format in query parameter, expected base64 encoded string")
	}

	return getTokens(base)
}

// getTokens splits a base64 encoded token into account and timeline tokens.
func getTokens(b string) (string, string, error) {
	// Split the token into account and timeline tokens
	if !utils.IsBase64(b) {
		return "", "", fmt.Errorf("invalid token format in Authorization header, expected base64 encoded string")
	}
	// Convert base64 to string
	decoded, err := base64.StdEncoding.DecodeString(b)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode base64 token: %w", err)
	}
	tokens := utils.SplitAndTrim(string(decoded), ":")
	if len(tokens) != 2 {
		return "", "", fmt.Errorf("invalid token format in Authorization header")
	}
	return tokens[0], tokens[1], nil
}
