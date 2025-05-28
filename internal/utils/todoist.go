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
	"blockarchitech.com/timetodo/internal/config"
	"blockarchitech.com/timetodo/internal/types/todoist"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"go.uber.org/zap"
	"time"
	_ "time/tzdata"
)

// TodoistUtils provides utility functions for interacting with Todoist webhooks and data.
type TodoistUtils struct {
	config *config.Config
	logger *zap.Logger
}

// NewTodoistUtils creates a new instance of TodoistUtils.
func NewTodoistUtils(cfg *config.Config, logger *zap.Logger) *TodoistUtils {
	return &TodoistUtils{
		config: cfg,
		logger: logger.Named("todoist_utils"),
	}
}

// VerifyTodoistSignature verifies the HMAC SHA256 signature of the Todoist webhook.
func (u *TodoistUtils) VerifyTodoistSignature(signatureHeader string, body []byte) bool {
	mac := hmac.New(sha256.New, []byte(u.config.TodoistClientSecret))
	mac.Write(body)
	expectedMAC := hex.EncodeToString(mac.Sum(nil))
	// base64-decode the signature header
	if signatureHeader == "" {
		u.logger.Warn("Empty signature header received from Todoist webhook")
		return false
	}
	decodedHeader, err := base64.StdEncoding.DecodeString(signatureHeader)
	if err != nil {
		u.logger.Error("Failed to decode Todoist signature header", zap.Error(err))
		return false
	}
	headerHex := hex.EncodeToString(decodedHeader)
	return hmac.Equal([]byte(headerHex), []byte(expectedMAC))
}

// ParseTodoistDueDateTime converts a Todoist DueDate object to a time.Time object.
func (u *TodoistUtils) ParseTodoistDueDateTime(due *todoist.DueDate, timezone string) (time.Time, error) {
	if due == nil {
		return time.Time{}, fmt.Errorf("due object is nil")
	}
	// try to parse as RFC3339 first. if that fails, parse as Todoist's made-up RFC3339 format (YYYY-MM-DDTHH:MM:SS). if that fails, parse as a date-only string (YYYY-MM-DD). if that fails, return an error.
	layouts := []string{
		time.RFC3339,          // Standard RFC3339 format
		"2006-01-02T15:04:05", // Made-up RFC3339 format
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, due.Date); err == nil {
			// if we are using the made-up RFC3339 format, use the provided offset to adjust the time
			if layout == "2006-01-02T15:04:05" {
				loc, err := time.LoadLocation(timezone)
				if err != nil {
					return time.Time{}, fmt.Errorf("failed to load location for timezone %s: %w", timezone, err)
				}
				t = t.In(loc)
				_, offset := t.Zone()

				t = t.Add(time.Duration(offset) * time.Second)
			}
			return t, nil
		}
	}
	if t, err := time.Parse("2006-01-02", due.Date); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("failed to parse due date: %s", due.Date)
}
