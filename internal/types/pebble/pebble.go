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
	TinyIcon string `json:"tinyIcon"`
}

// Pin defines the structure of a Pebble timeline pin.
type Pin struct {
	ID     string    `json:"id"`
	Time   string    `json:"time"`
	Layout PinLayout `json:"layout"`
}
