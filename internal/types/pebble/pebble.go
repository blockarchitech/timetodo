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

package pebble

// PinLayout defines the layout of a Pebble timeline pin.
type PinLayout struct {
	Type     string `json:"type"`
	Title    string `json:"title"`
	Body     string `json:"body,omitempty"`
	TinyIcon string `json:"tinyIcon"`
}

// PinAction defines an action for a Pebble timeline pin.
type PinAction struct {
	Title string `json:"title"`
	Type  string `json:"type"`
}

// HttpPinAction defines an HTTP-based timeline action.
type HttpPinAction struct {
	PinAction
	URL         string            `json:"url"`
	Method      string            `json:"method"`
	Headers     map[string]string `json:"headers"`
	BodyJson    map[string]string `json:"bodyJson"`
	SuccessText string            `json:"successText"` // what will be shown on the pebble if/when the action succeeds
	SuccessIcon string            `json:"successIcon"` // the system:// icon to show on the pebble if/when the action succeeds
	FailureText string            `json:"failureText"`
	FailureIcon string            `json:"failureIcon"`
}

// ReminderLayout defines the layout for a reminder notification.
type ReminderLayout struct {
	Type     string `json:"type"`
	Title    string `json:"title"`
	Subtitle string `json:"subtitle,omitempty"`
	TinyIcon string `json:"tinyIcon,omitempty"`
}

// Reminder defines a reminder for a Pebble timeline pin.
type Reminder struct {
	Time   string         `json:"time"`
	Layout ReminderLayout `json:"layout"`
}

// Pin defines the structure of a Pebble timeline pin.
type Pin struct {
	ID        string        `json:"id"`
	Time      string        `json:"time"`
	Layout    PinLayout     `json:"layout"`
	Actions   []interface{} `json:"actions"`
	Reminders []Reminder    `json:"reminders,omitempty"`
}
