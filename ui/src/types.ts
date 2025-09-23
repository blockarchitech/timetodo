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

export type MeResponse = {
  todoistUserID: number;
  timezone: string;
  scopes: string[];
  needsUpgrade: boolean;
  preferences: UpdatePreferencesRequest;
};

export type UpdatePreferencesRequest = {
  shouldPinWithNoDate: boolean;
  shouldPinWithNoTimeAt: string;
  shouldRemindOnDueTime: boolean;
  reminderTiming: '' | 'at' | '30m' | '15m';
};

export type PreferencesResponse = {
  preferences: UpdatePreferencesRequest;
};
