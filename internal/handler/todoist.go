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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"blockarchitech.com/timetodo/internal/config"
	"blockarchitech.com/timetodo/internal/models"
	"blockarchitech.com/timetodo/internal/types/pebble"
	"blockarchitech.com/timetodo/internal/types/todoist"
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/oauth2"
)

// HandleTodoistLogin initiates the OAuth2 flow with Todoist.
func (h *HttpHandlers) HandleTodoistLogin(c *gin.Context) {
	_, span := h.Tracer.Start(c.Request.Context(), "HandleTodoistLogin")
	defer span.End()

	pebbleAccountToken, pebbleTimelineToken, err := h.AuthUtils.GetTokensFromQuery(c.Request)
	if err != nil {
		log.Printf("WARN: Missing or invalid Authorization header: %v", err)
		span.RecordError(err)
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	state, err := h.AuthUtils.GenerateOAuthState()
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate OAuth state"})
		return
	}

	h.AuthUtils.SetCookie(c.Writer, c.Request, config.OauthStateCookieName, state, config.OauthCookieMaxAge)
	h.AuthUtils.SetCookie(c.Writer, c.Request, config.OauthPebbleAccountTokenCookieName, pebbleAccountToken, config.OauthCookieMaxAge)
	h.AuthUtils.SetCookie(c.Writer, c.Request, config.OauthPebbleTimelineTokenCookieName, pebbleTimelineToken, config.OauthCookieMaxAge)

	scopeOverride := c.Query("scope")
	prompt := c.Query("prompt")
	if prompt == "" {
		prompt = "consent"
	}

	opts := []oauth2.AuthCodeOption{oauth2.SetAuthURLParam("prompt", prompt)}
	if scopeOverride != "" {
		opts = append(opts, oauth2.SetAuthURLParam("scope", scopeOverride))
	}
	authURL := h.oauth2Config.AuthCodeURL(state, opts...)
	c.Redirect(http.StatusTemporaryRedirect, authURL)
}

// HandleTodoistCallback handles the OAuth2 callback from Todoist.
func (h *HttpHandlers) HandleTodoistCallback(c *gin.Context) {
	ctx, span := h.Tracer.Start(c.Request.Context(), "HandleTodoistCallback")
	defer span.End()

	if errMsg := c.Query("error"); errMsg != "" {
		log.Printf("WARN: Todoist OAuth callback returned an error: %s", errMsg)
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Todoist OAuth error: " + errMsg})
		return
	}

	stateCookie, err := c.Cookie(config.OauthStateCookieName)
	if err != nil || c.Query("state") != stateCookie {
		log.Printf("WARN: Invalid OAuth state or cookie not found: %v", err)
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid state or cookie not found"})
		return
	}

	code := c.Query("code")
	todoistToken, err := h.oauth2Config.Exchange(ctx, code)
	if err != nil {
		log.Printf("ERROR: Failed to exchange Todoist token: %v", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to exchange Todoist token"})
		return
	}
	span.SetAttributes(attribute.Bool("todoist.token_exchanged", true))

	todoistUser, err := h.todoistService.GetUser(ctx, todoistToken.AccessToken)
	if err != nil {
		log.Printf("ERROR: Failed to get Todoist user info: %v", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve Todoist user info"})
		return
	}

	pebbleAccountToken, pebbleTimelineToken, err := h.AuthUtils.GetPebbleTokensFromCookies(c.Request)
	if err != nil {
		log.Printf("ERROR: Failed to retrieve Pebble tokens from cookies: %v", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve Pebble tokens"})
		return
	}

	var scopes = []string{"data:read_write"}

	user := models.User{
		PebbleAccountToken:  pebbleAccountToken,
		PebbleTimelineToken: pebbleTimelineToken,
		TodoistAccessToken:  todoistToken,
		TodoistUserID:       todoistUser.User.ID,
		Timezone:            todoistUser.User.TimezoneInfo.Timezone,
		TimezoneHourOffset:  todoistUser.User.TimezoneInfo.Hours,
		LastUpdated:         time.Now(),
		Scopes:              scopes,
	}

	existingUser, err := h.userRepo.GetByPebbleAccount(ctx, pebbleAccountToken)
	if err == nil && existingUser != nil {
		user.Preferences = existingUser.Preferences
	} else {
		user.Preferences = models.Preferences{}
	}

	if err := h.userRepo.Create(ctx, &user); err != nil {
		log.Printf("ERROR: Failed to store user: %v", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to store user"})
		return
	}

	h.AuthUtils.ClearOAuthCookies(c.Writer, c.Request)

	log.Printf("INFO: Successfully authenticated and stored tokens for pebbleAccountToken: %s, todoistUserID: %d", pebbleAccountToken, todoistUser.User.ID)
	span.SetAttributes(
		attribute.String("pebble.account_token", pebbleAccountToken),
		attribute.Int64("todoist.user_id", todoistUser.User.ID),
	)

	url := h.config.ConfigUrl + "?account=" + pebbleAccountToken + "&timeline=" + pebbleTimelineToken + "&success=true"
	c.Redirect(http.StatusTemporaryRedirect, url)
}

// HandleTodoistWebhook processes incoming webhooks from Todoist.
func (h *HttpHandlers) HandleTodoistWebhook(c *gin.Context) {
	ctx, span := h.Tracer.Start(c.Request.Context(), "HandleTodoistWebhook")
	defer span.End()

	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to read webhook body"})
		return
	}
	defer c.Request.Body.Close()

	signature := c.GetHeader("X-Todoist-Hmac-SHA256")
	if !h.TodoistUtils.VerifyTodoistSignature(signature, body) {
		log.Printf("WARN: Invalid Todoist webhook signature")
		span.SetStatus(codes.Error, "Invalid signature")
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Invalid signature"})
		return
	}

	var payload todoist.WebhookPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Failed to unmarshal webhook payload"})
		return
	}

	span.SetAttributes(
		attribute.String("todoist.event_name", payload.EventName),
		attribute.Int64("todoist.user_id", payload.UserID),
	)
	log.Printf("INFO: Received Todoist webhook for eventName: %s, userID: %d", payload.EventName, payload.UserID)

	user, err := h.userRepo.GetByTodoistUserID(ctx, payload.UserID)
	if err != nil {
		logMsg := "Failed to get user by Todoist User ID"
		log.Printf("WARN: %s for todoistUserID: %d, error: %v", logMsg, payload.UserID, err)
		span.SetStatus(codes.Error, logMsg)
		span.RecordError(err)
		c.Status(http.StatusOK)
		return
	}

	if user == nil {
		log.Printf("WARN: User not found for todoistUserID: %d", payload.UserID)
		span.SetStatus(codes.Error, "User not found")
		span.RecordError(err)
		c.Status(http.StatusOK)
		return
	}

	switch payload.EventName {
	case "item:added", "item:updated":
		h.processTaskEvent(ctx, span, user, payload)
	case "item:completed", "item:deleted":
		var taskData todoist.TaskEventData
		if err := json.Unmarshal(payload.EventData, &taskData); err == nil {
			pinID := fmt.Sprintf("todoist-%d-%s", payload.UserID, taskData.ID)
			if user.PebbleTimelineToken != "" {
				status, err := h.pebbleTimelineService.DeletePin(ctx, user.PebbleTimelineToken, pinID)
				if err != nil && status == http.StatusGone {
					h.handleInvalidPebbleToken(ctx, payload.UserID)
				}
			}
		} else {
			log.Printf("WARN: Failed to parse taskData for delete/completed: %v", err)
		}
	default:
		log.Printf("INFO: Unhandled webhook event type: %s", payload.EventName)
		span.SetAttributes(attribute.String("app.webhook_unhandled_event", payload.EventName))
	}

	c.Status(http.StatusOK)
}

// processTaskEvent handles item:added and item:updated webhook events.
func (h *HttpHandlers) processTaskEvent(ctx context.Context, span trace.Span, user *models.User, payload todoist.WebhookPayload) {
	var taskData todoist.TaskEventData
	if err := json.Unmarshal(payload.EventData, &taskData); err != nil {
		log.Printf("ERROR: Failed to unmarshal task data from webhook for eventName: %s, error: %v", payload.EventName, err)
		span.RecordError(err)
		return
	}

	var dueTime time.Time
	if taskData.Due == nil || taskData.Due.Date == "" {
		if !user.Preferences.ShouldPinWithNoDate {
			log.Printf("INFO: User prefs disallow pins without date; skipping for taskID: %s", taskData.ID)
			span.SetAttributes(attribute.String("app.pin_skipped_reason", "pref_no_pins_without_date"))
			return
		}
		loc, err := time.LoadLocation(user.Timezone)
		if err != nil {
			log.Printf("ERROR: Failed to load user timezone: %s, error: %v", user.Timezone, err)
			span.RecordError(err)
			return
		}
		hhmm := user.Preferences.ShouldPinWithNoTimeAt
		if hhmm == "" {
			hhmm = "09:00"
		}
		var hour, m int
		fmt.Sscanf(hhmm, "%d:%d", &hour, &m)
		now := time.Now().In(loc)
		dueTime = time.Date(now.Year(), now.Month(), now.Day(), hour, m, 0, 0, loc)
	} else {
		var err error
		dueTime, err = h.TodoistUtils.ParseTodoistDueDateTime(taskData.Due, user.Timezone)
		if err != nil {
			log.Printf("ERROR: Failed to parse due date from webhook task: %v, dueObject: %+v", err, taskData.Due)
			span.RecordError(err)
			return
		}
		// Task has a due date but no time
		if len(taskData.Due.Date) == len("2006-01-02") {
			if !user.Preferences.ShouldPinWithNoTime {
				log.Printf("INFO: User prefs disallow pins without time; skipping for taskID: %s", taskData.ID)
				span.SetAttributes(attribute.String("app.pin_skipped_reason", "pref_no_pins_without_time"))
				return
			}

			loc, err := time.LoadLocation(user.Timezone)
			if err == nil {
				hhmm := user.Preferences.ShouldPinWithNoTimeAt
				if hhmm == "" {
					hhmm = "09:00"
				}
				var hour, m int
				fmt.Sscanf(hhmm, "%d:%d", &hour, &m)
				dueTime = time.Date(dueTime.Year(), dueTime.Month(), dueTime.Day(), hour, m, 0, 0, loc)
			}
		}
	}

	pin := h.PebbleUtils.CreatePebblePin(payload.UserID, taskData, dueTime)
	timing := user.Preferences.ReminderTiming
	if timing == "" && user.Preferences.ShouldRemindOnDueTime {
		timing = "at"
	}
	if timing != "" {
		remTime := dueTime
		subtitle := ""
		switch timing {
		case "30m":
			remTime = dueTime.Add(-30 * time.Minute)
			subtitle = "in 30 minutes"
		case "15m":
			remTime = dueTime.Add(-15 * time.Minute)
			subtitle = "in 15 minutes"
		case "at":
			remTime = dueTime
			subtitle = "now"
		}
		if subtitle != "" {
			pin.Reminders = []pebble.Reminder{{
				Time: remTime.UTC().Format(time.RFC3339),
				Layout: pebble.ReminderLayout{
					Type:     "genericReminder",
					Title:    taskData.Content,
					Subtitle: subtitle,
					TinyIcon: "system://images/ALARM_CLOCK",
				},
			}}
		}
	}

	hasRW := false
	for _, s := range user.Scopes {
		if s == "data:read_write" {
			hasRW = true
			break
		}
	}
	if !hasRW {
		pin.Actions = nil
	}

	pinJSON, err := json.Marshal(pin)
	if err != nil {
		log.Printf("ERROR: Failed to marshal Pebble pin for webhook task: %v", err)
		span.RecordError(err)
		return
	}

	if user.PebbleTimelineToken == "" {
		log.Printf("WARN: User has no Pebble Timeline Token, cannot push pin for todoistUserID: %d", payload.UserID)
		span.SetAttributes(attribute.String("app.pin_skipped_reason", "no_pebble_timeline_token"))
		return
	}

	statusCode, err := h.pebbleTimelineService.PushPin(ctx, user.PebbleTimelineToken, pinJSON)
	if err != nil {
		log.Printf("ERROR: Failed to push Pebble pin from webhook task for pinID: %s, error: %v", pin.ID, err)
		span.RecordError(err)
		if statusCode == http.StatusGone {
			h.handleInvalidPebbleToken(ctx, payload.UserID)
		}
		return
	}

	log.Printf("INFO: Successfully pushed Pebble pin from webhook task for pinID: %s", pin.ID)
	span.SetAttributes(attribute.String("app.pin_id_pushed", pin.ID))
}

// HandleInvalidPebbleToken deletes user data when their Pebble token is invalid (410 Gone).
func (h *HttpHandlers) handleInvalidPebbleToken(ctx context.Context, userID int64) {
	log.Printf("WARN: Pebble Timeline token is no longer valid, deleting user account for todoistUserID: %d", userID)
	if err := h.userRepo.DeleteByTodoistUserID(ctx, userID); err != nil {
		log.Printf("ERROR: Failed to delete user after 410 for todoistUserID: %d, error: %v", userID, err)
	} else {
		log.Printf("INFO: Successfully deleted user after 410 for todoistUserID: %d", userID)
	}
}
