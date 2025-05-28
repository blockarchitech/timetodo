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

var loggedInConfig = require('./config-loggedin.json');
var loggedOutConfig = require('./config-loggedout.json');
var customClay = require('./custom-clay.js');

var Clay = require('pebble-clay');

var clay = new Clay(loggedOutConfig, customClay, { autoHandleEvents: false, userData: {
    abc: '123',
} });
Pebble.addEventListener('showConfiguration', function (e) {
    Pebble.getTimelineToken(function (timeline_token) {
        var account_token = Pebble.getAccountToken();
        var token = btoa(account_token + ':' + timeline_token);
        var auth_header = 'Bearer ' + token;

        var userData = {
            token: token
        };

        clay.meta.userData = userData;

        

        var xhr = new XMLHttpRequest();
        xhr.open('GET', 'https://timetodo-282379823777.us-central1.run.app/api/v1/me', true);
        xhr.setRequestHeader('Authorization', auth_header);
        xhr.onload = function () {
            if (xhr.status === 200) {
                // User is logged in, show logged-in config
                clay.config = loggedInConfig;   
                console.log('User data fetched successfully:', JSON.stringify(xhr.responseText));             
                Pebble.openURL(clay.generateUrl());
            } else if (xhr.status === 401) {
                // User is not logged in, show not-logged-in config
                console.warn('User is not logged in, showing logged-out config');
                Pebble.openURL(clay.generateUrl());
            } else {
                console.error('Error fetching user data: ' + xhr.statusText);
                Pebble.openURL(clay.generateUrl());
            }
        };
        xhr.onerror = function () {
            console.error('Error fetching user data: ' + xhr.statusText);
            // Fallback to not-logged-in config in case of error
            clay.config = loggedOutConfig;
            Pebble.openURL(clay.generateUrl());
        };
        xhr.send();
    }, function (error) {
        console.error('Error getting timeline token: ' + error);
        Pebble.openURL(encodeURIComponent("data:text/html,<html><body><h1>Error</h1><p>Failed to retrieve timeline token. Try to reinstall TimeToDo.</p></body></html>"));
    });
});

Pebble.addEventListener('webviewclosed', function (e) {
    if (e && !e.response) {
        return;
    }

    // Get the keys and values from each config item
    var dict = clay.getSettings(e.response);


});

