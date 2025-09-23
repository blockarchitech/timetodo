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
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/codes"
	"go.uber.org/zap"
)

// pebbleActionRequest models the incoming Pebble timeline action payload.
type pebbleActionRequest struct {
	ActionID string `json:"actionId"`
	PinID    string `json:"pinId"`
	ID       string `json:"id"` // some implementations send just "id" for the pin id
}

// HandlePebbleAction processes a Pebble timeline action to complete or reschedule a Todoist task.
func (h *HttpHandlers) HandlePebbleAction(c *gin.Context) {
	ctx, span := h.Tracer.Start(c.Request.Context(), "HandlePebbleAction")
	defer span.End()

	user, ok := GetUserFromContext(c)
	if !ok {
		// This should not happen if middleware is configured correctly
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user from context"})
		return
	}

	var req pebbleActionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON body"})
		return
	}
	pinID := req.PinID
	if pinID == "" {
		pinID = req.ID
	}
	if pinID == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "missing pinId"})
		return
	}

	parts := strings.Split(pinID, "-")
	if len(parts) < 3 {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid pinId format"})
		return
	}
	taskID := parts[len(parts)-1]

	actionID := strings.ToLower(req.ActionID)
	var dueString string
	switch actionID {
	case "complete":
		if err := h.todoistService.CloseTask(ctx, user.TodoistAccessToken.AccessToken, taskID); err != nil {
			h.logger.Error("Failed to complete task from Pebble action", zap.Error(err), zap.String("taskID", taskID))
			span.SetStatus(codes.Error, "todoist close failed")
			c.AbortWithStatusJSON(http.StatusBadGateway, gin.H{"error": "failed to complete task"})
			return
		}
	case "today", "tomorrow", "next_weekend", "weekend":
		dueString = actionID
		if actionID == "weekend" {
			dueString = "next weekend"
		}
		if err := h.todoistService.UpdateTaskDueString(ctx, user.TodoistAccessToken.AccessToken, taskID, dueString); err != nil {
			h.logger.Error("Failed to reschedule task", zap.Error(err), zap.String("taskID", taskID), zap.String("dueString", dueString))
			c.AbortWithStatusJSON(http.StatusBadGateway, gin.H{"error": "failed to reschedule task"})
			return
		}
	default:
		h.logger.Warn("Unknown Pebble action", zap.String("actionId", req.ActionID))
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("unknown actionId: %s", req.ActionID)})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"ok":       true,
		"actionId": actionID,
		"pinId":    pinID,
		"at":       time.Now().UTC().Format(time.RFC3339),
	})
}
