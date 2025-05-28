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

package todoist

import "encoding/json"

// WebhookPayload defines the structure for incoming webhook events.
type WebhookPayload struct {
	EventName string          `json:"event_name"`
	UserID    int64           `json:"user_id,string"`
	EventData json.RawMessage `json:"event_data"`
	Initiator json.RawMessage `json:"initiator,omitempty"`
}

// DueDate represents the due date object from Todoist API
type DueDate struct {
	Date        string `json:"date"`
	String      string `json:"string"`
	Lang        string `json:"lang,omitempty"`
	Timezone    string `json:"timezone,omitempty"`
	IsRecurring bool   `json:"is_recurring"`
}

// TaskEventData represents the event_data for item-related webhooks
type TaskEventData struct {
	ID          string   `json:"id"`
	Content     string   `json:"content"`
	Description string   `json:"description"`
	Due         *DueDate `json:"due,omitempty"`
	Priority    int      `json:"priority"`
	ProjectID   string   `json:"project_id,omitempty"`
	UserID      int64    `json:"user_id,string"`
}
