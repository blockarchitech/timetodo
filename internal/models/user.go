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

package models

import (
	"time"

	"golang.org/x/oauth2"
)

// Preferences holds user-specific settings for the application.
type Preferences struct {
	ShouldPinWithNoDate   bool   `firestore:"shouldPinWithNoDate,omitempty" json:"shouldPinWithNoDate"`
	ShouldPinWithNoTime   bool   `firestore:"shouldPinWithNoTime,omitempty" json:"shouldPinWithNoTime"`
	ShouldPinWithNoTimeAt string `firestore:"shouldPinWithNoTimeAt,omitempty" json:"shouldPinWithNoTimeAt"`
	ShouldRemindOnDueTime bool   `firestore:"shouldRemindOnDueTime,omitempty" json:"shouldRemindOnDueTime"`
	ReminderTiming        string `firestore:"reminderTiming,omitempty" json:"reminderTiming"` // e.g., "", "at", "30m", "15m"
}

// User represents a user of the application, including their authentication details and preferences.
type User struct {
	PebbleAccountToken  string        `firestore:"pebbleAccountToken,omitempty" json:"-"`
	PebbleTimelineToken string        `firestore:"pebbleTimelineToken,omitempty" json:"-"`
	TodoistAccessToken  *oauth2.Token `firestore:"todoistAccessToken,omitempty" json:"-"`
	TodoistUserID       int64         `firestore:"todoistUserID,omitempty" json:"todoistUserID"`
	LastUpdated         time.Time     `firestore:"lastUpdated,omitempty" json:"lastUpdated"`
	Timezone            string        `firestore:"timezone,omitempty" json:"timezone"`
	TimezoneHourOffset  int           `firestore:"timezoneHourOffset,omitempty" json:"-"`
	Scopes              []string      `firestore:"scopes,omitempty" json:"scopes"`
	Preferences         Preferences   `firestore:"preferences,omitempty" json:"preferences"`
}
