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

package handler

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"go.uber.org/zap"
	"golang.org/x/oauth2"

	"blockarchitech.com/timetodo/internal/config"
	"blockarchitech.com/timetodo/internal/service"
	"blockarchitech.com/timetodo/internal/storage"
	"blockarchitech.com/timetodo/internal/view"
)

const (
	oauthStateCookieName               = "timetodo_oauth_state"
	oauthPebbleAccountTokenCookieName  = "timetodo_oauth_p_acc_token"
	oauthPebbleTimelineTokenCookieName = "timetodo_oauth_p_timeline_token"
)

// HttpHandlers holds application-wide state and dependencies, managed by FX.
type HttpHandlers struct {
	logger                *zap.Logger
	tokenStore            storage.TokenStore
	oauth2Config          *oauth2.Config
	config                *config.Config
	htmlManager           *view.HTMLTemplateManager
	pebbleTimelineService *service.PebbleTimelineService
	todoistService        *service.TodoistService
	Tracer                trace.Tracer
}

// NewHttpHandlers creates a new HttpHandlers instance.
func NewHttpHandlers(logger *zap.Logger, oauth2Config *oauth2.Config, tokenStore storage.TokenStore, htmlManager *view.HTMLTemplateManager, cfg *config.Config, todoistService *service.TodoistService, pebbleService *service.PebbleTimelineService, tracer trace.Tracer) *HttpHandlers {
	return &HttpHandlers{
		logger:                logger,
		tokenStore:            tokenStore,
		oauth2Config:          oauth2Config,
		config:                cfg,
		htmlManager:           htmlManager,
		pebbleTimelineService: pebbleService,
		todoistService:        todoistService,
		Tracer:                tracer,
	}
}

// --- HTTP Handlers ---

// HandlePebbleConfig serves the Pebble configuration page.
func (h *HttpHandlers) HandlePebbleConfig(w http.ResponseWriter, r *http.Request) {
	ctx, span := h.Tracer.Start(r.Context(), "handlePebbleConfig", trace.WithAttributes(attribute.String("http.method", r.Method)))
	defer span.End()

	pebbleTimelineToken := r.URL.Query().Get("timeline_token")
	pebbleAccountToken := r.URL.Query().Get("account_token")

	span.SetAttributes(
		attribute.Bool("pebble.timeline_token_present", pebbleTimelineToken != ""),
		attribute.Bool("pebble.account_token_present", pebbleAccountToken != ""),
		attribute.String("pebble.UserAgent", r.UserAgent()), // TODO: don't log user agent
	)

	if pebbleTimelineToken == "" || pebbleAccountToken == "" {
		h.logger.Warn("Missing pebble_timeline_token or pebble_account_token")
		data := map[string]string{
			"Error": "Missing required Pebble tokens. Please open from Pebble app settings.",
		}
		if err := h.htmlManager.Render(w, "config.html", data); err != nil {
			h.logger.Error("Failed to render config page for missing tokens", zap.Error(err))
			http.Error(w, "Failed to render page", http.StatusInternalServerError)
		}
		return
	}

	userTokens, found, err := h.tokenStore.GetTokensByPebbleAccount(ctx, pebbleAccountToken)
	if err != nil {
		h.logger.Error("Error getting tokens", zap.String("pebbleAccountToken", pebbleAccountToken), zap.Error(err))
		data := map[string]string{"Status": "error", "Error": "Could not retrieve stored configuration."}
		if errRender := h.htmlManager.Render(w, "config.html", data); errRender != nil {
			h.logger.Error("Failed to render config page for token error", zap.Error(errRender))
			http.Error(w, "Failed to render page", http.StatusInternalServerError)
		}
		return
	}

	if found && userTokens.TodoistAccessToken != nil && userTokens.TodoistAccessToken.Valid() {
		h.logger.Info("User already authenticated with Todoist", zap.String("pebbleAccountToken", pebbleAccountToken))
		data := map[string]string{"Status": "success"}
		if errRender := h.htmlManager.Render(w, "config.html", data); errRender != nil {
			h.logger.Error("Failed to render config page for success status", zap.Error(errRender))
			http.Error(w, "Failed to render page", http.StatusInternalServerError)
		}
		return
	}

	loginURL := fmt.Sprintf("%s/auth/todoist/login?pebble_account_token=%s&pebble_timeline_token=%s",
		h.config.AppBaseURL,
		url.QueryEscape(pebbleAccountToken),
		url.QueryEscape(pebbleTimelineToken),
	)

	data := map[string]string{
		"TodoistLoginURL": loginURL,
	}
	if err := h.htmlManager.Render(w, "config.html", data); err != nil {
		h.logger.Error("Error rendering config page for OAuth", zap.Error(err))
		http.Error(w, "Failed to render page", http.StatusInternalServerError)
	}
}

// HandleTodoistLogin initiates the OAuth2 flow with Todoist.
func (h *HttpHandlers) HandleTodoistLogin(w http.ResponseWriter, r *http.Request) {
	_, span := h.Tracer.Start(r.Context(), "handleTodoistLogin", trace.WithAttributes(attribute.String("http.method", r.Method)))
	defer span.End()

	pebbleAccountToken := r.URL.Query().Get("pebble_account_token")
	pebbleTimelineToken := r.URL.Query().Get("pebble_timeline_token")

	if pebbleAccountToken == "" || pebbleTimelineToken == "" {
		h.logger.Warn("Missing Pebble account or timeline token in request to /auth/todoist/login")
		http.Error(w, "Missing Pebble account or timeline token", http.StatusBadRequest)
		return
	}

	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		h.logger.Error("Failed to generate OAuth state", zap.Error(err))
		http.Error(w, "Failed to generate OAuth state", http.StatusInternalServerError)
		return
	}
	state := base64.URLEncoding.EncodeToString(b)

	http.SetCookie(w, &http.Cookie{Name: oauthStateCookieName, Value: state, Path: "/", HttpOnly: true, Secure: r.TLS != nil, MaxAge: 300, SameSite: http.SameSiteStrictMode})
	http.SetCookie(w, &http.Cookie{Name: oauthPebbleAccountTokenCookieName, Value: pebbleAccountToken, Path: "/", HttpOnly: true, Secure: r.TLS != nil, MaxAge: 300, SameSite: http.SameSiteStrictMode})
	http.SetCookie(w, &http.Cookie{Name: oauthPebbleTimelineTokenCookieName, Value: pebbleTimelineToken, Path: "/", HttpOnly: true, Secure: r.TLS != nil, MaxAge: 300, SameSite: http.SameSiteStrictMode})

	authURL := h.oauth2Config.AuthCodeURL(state)
	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

// HandleTodoistCallback handles the callback from Todoist after user authorization.
func (h *HttpHandlers) HandleTodoistCallback(w http.ResponseWriter, r *http.Request) {
	ctx, span := h.Tracer.Start(r.Context(), "handleTodoistCallback", trace.WithAttributes(attribute.String("http.method", r.Method)))
	defer span.End()

	stateCookie, err := r.Cookie(oauthStateCookieName)
	if err != nil {
		h.logger.Warn("OAuth state cookie not found")
		http.Error(w, "OAuth state cookie not found", http.StatusBadRequest)
		return
	}

	if r.URL.Query().Get("state") != stateCookie.Value {
		h.logger.Warn("Invalid OAuth state")
		http.Error(w, "Invalid OAuth state", http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	todoistToken, err := h.oauth2Config.Exchange(ctx, code)
	if err != nil {
		h.logger.Error("Failed to exchange Todoist token", zap.Error(err))
		http.Redirect(w, r, h.config.AppBaseURL+"/config/pebble?status=error&error="+url.QueryEscape("Todoist token exchange failed"), http.StatusTemporaryRedirect)
		return
	}

	span.SetAttributes(attribute.Bool("todoist.token_exchanged", true))

	todoistUserID, err := h.todoistService.GetUserID(ctx, todoistToken.AccessToken)
	if err != nil {
		h.logger.Error("Failed to get Todoist user ID", zap.Error(err))
		// Not redirecting on this error, but logging it.
	}

	pebbleAccountTokenCookie, errAcc := r.Cookie(oauthPebbleAccountTokenCookieName)
	pebbleTimelineTokenCookie, errTime := r.Cookie(oauthPebbleTimelineTokenCookieName)

	if errAcc != nil || errTime != nil {
		h.logger.Error("Error retrieving pebble tokens from cookie", zap.Error(errAcc), zap.Error(errTime))
		http.Redirect(w, r, h.config.AppBaseURL+"/config/pebble?status=error&error="+url.QueryEscape("Session error, please retry configuration"), http.StatusTemporaryRedirect)
		return
	}

	pebbleAccountToken := pebbleAccountTokenCookie.Value
	pebbleTimelineToken := pebbleTimelineTokenCookie.Value

	userTokens := storage.UserTokens{
		PebbleAccountToken:  pebbleAccountToken,
		PebbleTimelineToken: pebbleTimelineToken,
		TodoistAccessToken:  todoistToken,
		TodoistUserID:       todoistUserID, // Store the fetched User ID
		LastUpdated:         time.Now(),
	}

	if err := h.tokenStore.StoreTokens(ctx, pebbleAccountToken, userTokens); err != nil {
		h.logger.Error("Failed to store tokens", zap.Error(err))
		http.Redirect(w, r, h.config.AppBaseURL+"/config/pebble?status=error&error="+url.QueryEscape("Failed to save configuration"), http.StatusTemporaryRedirect)
		return
	}

	// Clear cookies
	http.SetCookie(w, &http.Cookie{Name: oauthStateCookieName, Path: "/", MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: oauthPebbleAccountTokenCookieName, Path: "/", MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: oauthPebbleTimelineTokenCookieName, Path: "/", MaxAge: -1})

	h.logger.Info("Successfully authenticated and stored tokens", zap.String("pebbleAccountToken", pebbleAccountToken), zap.Int64("todoistUserID", todoistUserID))
	span.SetAttributes(attribute.String("pebble.account_token", pebbleAccountToken), attribute.Int64("todoist.user_id", todoistUserID))

	// Redirect to Pebble close with success
	http.Redirect(w, r, "pebblejs://close#{\"status\":\"success\"}", http.StatusTemporaryRedirect)
}

// --- Todoist Webhook Handler ---

// TodoistWebhookPayload defines the structure for incoming webhook events.
type TodoistWebhookPayload struct {
	EventName string          `json:"event_name"`
	UserID    int64           `json:"user_id"`
	EventData json.RawMessage `json:"event_data"`
	Initiator json.RawMessage `json:"initiator,omitempty"`
}

// TodoistDueDate represents the due date object from Todoist API
type TodoistDueDate struct {
	Date        string `json:"date,omitempty"`
	Datetime    string `json:"datetime,omitempty"`
	String      string `json:"string"`
	Timezone    string `json:"timezone,omitempty"`
	IsRecurring bool   `json:"is_recurring"`
}

// TodoistTaskEventData represents the event_data for item-related webhooks
type TodoistTaskEventData struct {
	ID          string          `json:"id"`
	Content     string          `json:"content"`
	Description string          `json:"description,omitempty"`
	Due         *TodoistDueDate `json:"due,omitempty"`
	Priority    int             `json:"priority"`
	ProjectID   string          `json:"project_id,omitempty"`
	UserID      int64           `json:"user_id"` // This is the user_id from the task data itself
}

// PebblePinLayout defines the layout of a Pebble timeline pin.
type PebblePinLayout struct {
	Type     string `json:"type"`
	Title    string `json:"title"`
	TinyIcon string `json:"tinyIcon"`
}

// PebblePin defines the structure of a Pebble timeline pin.
type PebblePin struct {
	ID     string          `json:"id"`
	Time   string          `json:"time"`
	Layout PebblePinLayout `json:"layout"`
}

// HandleTodoistWebhook processes incoming webhooks from Todoist.
func (h *HttpHandlers) HandleTodoistWebhook(w http.ResponseWriter, r *http.Request) {
	ctx, span := h.Tracer.Start(r.Context(), "HandleTodoistWebhook")
	defer span.End()

	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.logger.Error("Failed to read webhook body", zap.Error(err))
		span.SetStatus(codes.Error, "Failed to read body")
		span.RecordError(err)
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	signature := r.Header.Get("X-Todoist-Hmac-SHA256")
	if !h.verifyTodoistSignature(signature, body) {
		h.logger.Warn("Invalid Todoist webhook signature")
		span.SetStatus(codes.Error, "Invalid signature")
		http.Error(w, "Invalid signature", http.StatusForbidden)
		return
	}

	var payload TodoistWebhookPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		h.logger.Error("Failed to unmarshal webhook payload", zap.Error(err))
		span.SetStatus(codes.Error, "Failed to unmarshal payload")
		span.RecordError(err)
		http.Error(w, "Failed to parse request body", http.StatusBadRequest)
		return
	}

	span.SetAttributes(
		attribute.String("todoist.event_name", payload.EventName),
		attribute.Int64("todoist.user_id", payload.UserID),
	)
	h.logger.Info("Received Todoist webhook", zap.String("eventName", payload.EventName), zap.Int64("userID", payload.UserID))

	// Fetch user tokens using Todoist User ID
	userTokens, found, err := h.tokenStore.GetTokensByTodoistUserID(ctx, payload.UserID)
	if err != nil {
		h.logger.Error("Failed to get tokens by Todoist User ID for webhook", zap.Int64("todoistUserID", payload.UserID), zap.Error(err))
		span.RecordError(err)
		// Still return 200 OK to Todoist as per their recommendation for webhook errors not to retry indefinitely
		w.WriteHeader(http.StatusOK)
		return
	}
	if !found {
		h.logger.Warn("No tokens found for Todoist User ID from webhook", zap.Int64("todoistUserID", payload.UserID))
		span.SetStatus(codes.Error, "User tokens not found for webhook user ID")
		// Still return 200 OK
		w.WriteHeader(http.StatusOK)
		return
	}

	switch payload.EventName {
	case "item:added", "item:updated":
		var taskData TodoistTaskEventData
		if err := json.Unmarshal(payload.EventData, &taskData); err != nil {
			h.logger.Error("Failed to unmarshal task data from webhook", zap.Error(err), zap.String("eventName", payload.EventName))
			span.RecordError(err)
			w.WriteHeader(http.StatusOK) // Acknowledge webhook
			return
		}

		if taskData.Due == nil || taskData.Due.Date == "" {
			h.logger.Info("Task has no due date, skipping pin creation", zap.String("taskID", taskData.ID), zap.String("taskContent", taskData.Content))
			span.SetAttributes(attribute.String("app.pin_skipped_reason", "no_due_date"))
			w.WriteHeader(http.StatusOK)
			return
		}

		dueTime, err := parseTodoistDueDateTime(taskData.Due)
		if err != nil {
			h.logger.Error("Failed to parse due date from webhook task", zap.Error(err), zap.Any("dueObject", taskData.Due))
			span.RecordError(err)
			w.WriteHeader(http.StatusOK) // Acknowledge webhook
			return
		}

		pin := PebblePin{
			ID:   fmt.Sprintf("todoist-%d-%s", payload.UserID, taskData.ID),
			Time: dueTime.Format(time.RFC3339),
			Layout: PebblePinLayout{
				Type:     "genericPin",
				Title:    taskData.Content,
				TinyIcon: "system://images/TODO_EVENT",
			},
		}

		pinJSON, err := json.Marshal(pin)
		if err != nil {
			h.logger.Error("Failed to marshal Pebble pin for webhook task", zap.Error(err))
			span.RecordError(err)
			w.WriteHeader(http.StatusOK) // Acknowledge webhook
			return
		}

		if userTokens.PebbleTimelineToken == "" {
			h.logger.Warn("User has no Pebble Timeline Token, cannot push pin", zap.Int64("todoistUserID", payload.UserID))
			span.SetAttributes(attribute.String("app.pin_skipped_reason", "no_pebble_timeline_token"))
			w.WriteHeader(http.StatusOK)
			return
		}

		if err, status_code := h.pebbleTimelineService.PushPin(ctx, userTokens.PebbleTimelineToken, pinJSON); err != nil {
			h.logger.Error("Failed to push Pebble pin from webhook task", zap.Error(err), zap.String("pinID", pin.ID))
			span.RecordError(err)
			// Still return 200 OK to Todoist
			w.WriteHeader(http.StatusOK)

			// if the status_code is 410, delete their account. the timeline token is no longer valid.
			if status_code == http.StatusGone {
				h.logger.Warn("Pebble Timeline token is no longer valid, deleting user account", zap.Int64("todoistUserID", payload.UserID))
				if errDel := h.tokenStore.DeleteTokensByTodoistUserID(ctx, payload.UserID); errDel != nil {
					h.logger.Error("Failed to delete user tokens after Pebble Timeline token invalidation", zap.Error(errDel), zap.Int64("todoistUserID", payload.UserID))
				} else {
					h.logger.Info("Successfully deleted user tokens after Pebble Timeline token invalidation", zap.Int64("todoistUserID", payload.UserID))
				}
			}

			return
		}
		h.logger.Info("Successfully pushed Pebble pin from webhook task", zap.String("pinID", pin.ID))
		span.SetAttributes(attribute.String("app.pin_id_pushed", pin.ID))

	default:
		h.logger.Info("Unhandled webhook event type", zap.String("eventName", payload.EventName))
		span.SetAttributes(attribute.String("app.webhook_unhandled_event", payload.EventName))
	}

	w.WriteHeader(http.StatusOK)
}

// verifyTodoistSignature verifies the HMAC SHA256 signature of the Todoist webhook.
func (h *HttpHandlers) verifyTodoistSignature(signatureHeader string, body []byte) bool {
	mac := hmac.New(sha256.New, []byte(h.config.TodoistClientSecret))
	mac.Write(body)
	expectedMAC := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(signatureHeader), []byte(expectedMAC))
}

// parseTodoistDueDateTime converts a Todoist DueDate object to a time.Time object.
func parseTodoistDueDateTime(due *TodoistDueDate) (time.Time, error) {
	if due == nil {
		return time.Time{}, fmt.Errorf("due object is nil")
	}

	// Try parsing RFC3339 (datetime) first
	if due.Datetime != "" {
		parsedTime, err := time.Parse(time.RFC3339, due.Datetime)
		if err == nil {
			return parsedTime, nil
		}
		// If timezone is present, try parsing with timezone explicitly
		// Todoist 'datetime' is usually UTC if 'timezone' is null, or in specified timezone if 'timezone' is not null.
		// The time.RFC3339 format handles 'Z' for UTC and timezone offsets like '-07:00'.
		// If due.Timezone is not nil and not UTC, the `due.Datetime` should already be in that timezone or be UTC.
		// For simplicity, we rely on RFC3339 parsing. If specific timezone logic is needed beyond what RFC3339 handles,
		// it would need to be added here, possibly using time.LoadLocation.
	}

	// Try parsing YYYY-MM-DD (date) next
	if due.Date != "" {
		// If it's just a date, assume it's for the start of that day in the user's local timezone (or UTC if not specified).
		// For simplicity, parsing as is. If a specific time (e.g., midnight) is needed, adjust accordingly.
		layout := "2006-01-02"
		parsedTime, err := time.Parse(layout, due.Date)
		if err == nil {
			// If a timezone is specified with a date-only due date, it's ambiguous.
			// Assume the date is in that timezone. For a pin, we need a specific instant.
			// Defaulting to midnight in the given timezone if available, otherwise UTC.
			if due.Timezone != "" {
				loc, errLoc := time.LoadLocation(due.Timezone)
				if errLoc == nil {
					return time.Date(parsedTime.Year(), parsedTime.Month(), parsedTime.Day(), 0, 0, 0, 0, loc), nil
				}
			}
			return parsedTime, nil // As midnight UTC if no timezone
		}
	}

	return time.Time{}, fmt.Errorf("failed to parse due date/datetime: %s", due.String)
}
