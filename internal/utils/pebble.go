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

package utils

import (
	"fmt"
	"net/http"
	"time"

	"blockarchitech.com/timetodo/internal/config"
	"blockarchitech.com/timetodo/internal/types/pebble"
	"blockarchitech.com/timetodo/internal/types/todoist"
	"go.uber.org/zap"
)

type PebbleUtils struct {
	logger *zap.Logger
	config *config.Config
}

func NewPebbleUtils(logger *zap.Logger, config *config.Config) *PebbleUtils {
	return &PebbleUtils{
		logger: logger.Named("pebble_utils"),
		config: config,
	}
}

// CreatePebblePin constructs a Pebble Pin object from task data.
func (p *PebbleUtils) CreatePebblePin(userID int64, taskData todoist.TaskEventData, dueTime time.Time) pebble.Pin {
	pinID := fmt.Sprintf("todoist-%d-%s", userID, taskData.ID)
	// Build HTTP actions that call back into our server.
	actionURL := p.config.AppBaseURL + "/api/v1/pebble/action" // keep in sync with handler.RoutePebbleAction
	actions := []interface{}{
		pebble.HttpPinAction{PinAction: pebble.PinAction{Title: "Complete", Type: "http"}, URL: actionURL, Method: http.MethodPost, Headers: map[string]string{"Content-Type": "application/json"}, BodyJson: map[string]string{"id": pinID, "pinId": pinID, "actionId": "complete"}, SuccessText: "Completed", SuccessIcon: "system://images/RESULT_MUTE", FailureText: "Failed", FailureIcon: "system://images/RESULT_FAILED"},
		pebble.HttpPinAction{PinAction: pebble.PinAction{Title: "Today", Type: "http"}, URL: actionURL, Method: http.MethodPost, Headers: map[string]string{"Content-Type": "application/json"}, BodyJson: map[string]string{"id": pinID, "pinId": pinID, "actionId": "today"}, SuccessText: "Rescheduled", SuccessIcon: "system://images/TIMELINE_CALENDAR", FailureText: "Failed", FailureIcon: "system://images/RESULT_FAILED"},
		pebble.HttpPinAction{PinAction: pebble.PinAction{Title: "Tomorrow", Type: "http"}, URL: actionURL, Method: http.MethodPost, Headers: map[string]string{"Content-Type": "application/json"}, BodyJson: map[string]string{"id": pinID, "pinId": pinID, "actionId": "tomorrow"}, SuccessText: "Rescheduled", SuccessIcon: "system://images/TIMELINE_CALENDAR", FailureText: "Failed", FailureIcon: "system://images/RESULT_FAILED"},
		pebble.HttpPinAction{PinAction: pebble.PinAction{Title: "Weekend", Type: "http"}, URL: actionURL, Method: http.MethodPost, Headers: map[string]string{"Content-Type": "application/json"}, BodyJson: map[string]string{"id": pinID, "pinId": pinID, "actionId": "next_weekend"}, SuccessText: "Rescheduled", SuccessIcon: "system://images/TIMELINE_CALENDAR", FailureText: "Failed", FailureIcon: "system://images/RESULT_FAILED"},
	}
	return pebble.Pin{
		ID:   pinID,
		Time: dueTime.UTC().Format(time.RFC3339),
		Layout: pebble.PinLayout{
			Type:     "genericPin",
			Title:    taskData.Content,
			Body:     taskData.Description,
			TinyIcon: "system://images/NOTIFICATION_FLAG",
		},
		Actions: actions,
	}
}
