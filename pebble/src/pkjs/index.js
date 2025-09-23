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

Pebble.addEventListener('showConfiguration', function (e) {
    Pebble.getTimelineToken(function (timeline_token) {
        var account_token = Pebble.getAccountToken();
        var url = 'https://timetodo-282379823777.us-central1.run.app/config' +
            '?timeline=' + encodeURIComponent(timeline_token) +
            '&account=' + encodeURIComponent(account_token);
        Pebble.openURL(url);
    }, function (error) {
        console.error('Error getting timeline token: ' + error);
        Pebble.openURL(encodeURIComponent("data:text/html,<html><body><h1>Error</h1><p>Failed to retrieve timeline token. Try to reinstall TimeToDo. Please note: TimeToDo does not currently work on the Core Devices mobile app.</p></body></html>"));
    });
});

Pebble.addEventListener('webviewclosed', function (e) {
    if (e && !e.response) {
        return;
    }

    Pebble.sendAppMessage({
        Close: 1,
    }, function () {
        // ok
    }, function (error) {
        // oh no, anyway
    });
});

