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
	"blockarchitech.com/timetodo/internal/storage"
	"blockarchitech.com/timetodo/internal/types/pebble"
	"blockarchitech.com/timetodo/internal/types/todoist"
	"context"
	"fmt"
	"go.uber.org/zap"
	"time"
)

type PebbleUtils struct {
	tokenStore storage.TokenStore
	logger     *zap.Logger
}

func NewPebbleUtils(tokenStore storage.TokenStore, logger *zap.Logger) *PebbleUtils {
	return &PebbleUtils{
		tokenStore: tokenStore,
		logger:     logger.Named("pebble_utils"),
	}
}

// HandleInvalidPebbleToken deletes user data when their Pebble token is invalid (410 Gone).
func (p *PebbleUtils) HandleInvalidPebbleToken(ctx context.Context, userID int64) {
	p.logger.Warn("Pebble Timeline token is no longer valid, deleting user account", zap.Int64("todoistUserID", userID))
	if err := p.tokenStore.DeleteTokensByTodoistUserID(ctx, userID); err != nil {
		p.logger.Error("Failed to delete user tokens after 410", zap.Error(err), zap.Int64("todoistUserID", userID))
	} else {
		p.logger.Info("Successfully deleted user tokens after 410", zap.Int64("todoistUserID", userID))
	}
}

// CreatePebblePin constructs a Pebble Pin object from task data.
func (p *PebbleUtils) CreatePebblePin(userID int64, taskData todoist.TaskEventData, dueTime time.Time) pebble.Pin {
	return pebble.Pin{
		ID:   fmt.Sprintf("todoist-%d-%s", userID, taskData.ID),
		Time: dueTime.UTC().Format(time.RFC3339),
		Layout: pebble.PinLayout{
			Type:     "genericPin",
			Title:    taskData.Content,
			Body:     taskData.Description,
			TinyIcon: "system://images/NOTIFICATION_FLAG",
		},
	}
}
