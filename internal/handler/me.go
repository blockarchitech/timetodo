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
	"fmt"
	"net/http"

	"blockarchitech.com/timetodo/internal/config"
	"blockarchitech.com/timetodo/internal/models"
	"blockarchitech.com/timetodo/internal/types/app"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// HandleGetMe handles the HTTP request the Clay config page makes to check if the user exists and is authenticated via Todoist.
func (h *HttpHandlers) HandleGetMe(c *gin.Context) {
	_, span := h.Tracer.Start(c.Request.Context(), "HandleGetMe")
	defer span.End()

	user, ok := GetUserFromContext(c)
	if !ok {
		// This should not happen if middleware is configured correctly
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user from context"})
		return
	}

	needsUpgrade := len(user.Scopes) == 1 && user.Scopes[0] == "data:read"
	c.JSON(http.StatusOK, gin.H{
		"todoistUserID": user.TodoistUserID,
		"timezone":      user.Timezone,
		"scopes":        user.Scopes,
		"needsUpgrade":  needsUpgrade,
		"preferences":   user.Preferences,
	})
}

func (h *HttpHandlers) HandleDeleteMe(c *gin.Context) {
	ctx, span := h.Tracer.Start(c.Request.Context(), "HandleDeleteMe")
	defer span.End()

	user, ok := GetUserFromContext(c)
	if !ok {
		// This should not happen if middleware is configured correctly
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user from context"})
		return
	}

	if err := h.todoistService.RevokeToken(ctx, user.TodoistAccessToken.AccessToken); err != nil {
		h.logger.Error("Failed to revoke Todoist access token", zap.Error(err), zap.Int64("todoistUserID", user.TodoistUserID))
		// Continue with deletion even if revocation fails
	}

	if err := h.userRepo.DeleteByPebbleAccount(ctx, user.PebbleAccountToken); err != nil {
		h.logger.Error("Failed to delete user", zap.Error(err), zap.String("pebbleAccountToken", user.PebbleAccountToken))
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete user"})
		return
	}

	h.AuthUtils.ClearOAuthCookies(c.Writer, c.Request)
	c.Status(http.StatusNoContent)
}

// HandleDeletePage serves a simple HTML page with a button to delete the user's account.
func (h *HttpHandlers) HandleDeletePage(c *gin.Context) {
	_, span := h.Tracer.Start(c.Request.Context(), "HandleDeletePage")
	defer span.End()

	pebbleAccountToken, pebbleTimelineToken, err := h.AuthUtils.GetTokensFromQuery(c.Request)
	if err != nil {
		h.logger.Warn("Missing or invalid Authorization header", zap.Error(err))
		span.RecordError(err)
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

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
		function getCsrf() {
			const m = document.cookie.match(/(?:^|; )ttd_csrf=([^;]+)/);
			return m ? decodeURIComponent(m[1]) : '';
		}
		document.getElementById('delete-button').addEventListener('click', function() {
			fetch('/api/v1/me', {
				method: 'DELETE',
				headers: {
					'Authorization': 'Bearer ' + btoa('%s:%s'),
					'X-CSRF-Token': getCsrf()
				},
				credentials: 'include'
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
`, pebbleAccountToken, pebbleTimelineToken, config.PebbleCloseLogoutURL)

	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(html))
}

// HandleUpdateMe updates the user's preference settings.
func (h *HttpHandlers) HandleUpdateMe(c *gin.Context) {
	ctx, span := h.Tracer.Start(c.Request.Context(), "HandleUpdateMe")
	defer span.End()

	user, ok := GetUserFromContext(c)
	if !ok {
		// This should not happen if middleware is configured correctly
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user from context"})
		return
	}

	var req app.UpdatePreferencesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON body"})
		return
	}

	if req.ShouldPinWithNoTime && req.ShouldPinWithNoTimeAt == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "shouldPinWithNoTimeAt is required when shouldPushPinWithNoTime is true"})
		return
	}
	if len(req.ShouldPinWithNoTimeAt) > 0 {
		if len(req.ShouldPinWithNoTimeAt) != 5 || req.ShouldPinWithNoTimeAt[2] != ':' {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "shouldPinWithNoTimeAt must be in HH:MM format"})
			return
		}
	}

	if req.ShouldPinWithNoDate && !req.ShouldPinWithNoTime {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "shouldPinWithNoTime must be true when shouldPinWithNoDate is true"})
		return
	}

	if req.ShouldRemindOnDueTime && req.ReminderTiming == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "reminderTiming is required when shouldRemindOnDueTime is true"})
		return
	}

	validTiming := map[string]bool{"": true, "at": true, "30m": true, "15m": true}
	if !validTiming[req.ReminderTiming] {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "reminderTiming must be one of: '', 'at', '30m', '15m'"})
		return
	}

	prefs := models.Preferences{
		ShouldPinWithNoDate:   req.ShouldPinWithNoDate,
		ShouldPinWithNoTime:   req.ShouldPinWithNoTime,
		ShouldPinWithNoTimeAt: req.ShouldPinWithNoTimeAt,
		ShouldRemindOnDueTime: req.ShouldRemindOnDueTime,
		ReminderTiming:        req.ReminderTiming,
	}

	if err := h.userRepo.UpdateUserPreferences(ctx, user.PebbleAccountToken, prefs); err != nil {
		h.logger.Error("Failed to update user preferences", zap.Error(err))
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to update preferences"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"preferences": prefs})
}
