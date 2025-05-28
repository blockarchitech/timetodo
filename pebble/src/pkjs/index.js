var loggedInConfig = require('./config-loggedin.json');
var loggedOutConfig = require('./config-loggedout.json');
var customClay = require('./custom-clay.js');

var Clay = require('pebble-clay');
var clay = new Clay([], customClay, { autoHandleEvents: false });

Pebble.addEventListener('showConfiguration', function (e) {
    Pebble.getTimelineToken(function (timeline_token) {
        // make http request to https://timetodo-282379823777.us-central1.run.app/api/v1/me, with an Authorization header that is Bearer btoa(<acct_token> + ':' + <timeline_token>)
        var account_token = Pebble.getAccountToken();
        var auth_header = 'Bearer ' + btoa(account_token + ':' + timeline_token);

        clay.options.userData = {
            authorization: auth_header
        };

        var xhr = new XMLHttpRequest();
        xhr.open('GET', 'https://timetodo-282379823777.us-central1.run.app/api/v1/me', true);
        xhr.setRequestHeader('Authorization', auth_header);
        xhr.onload = function () {
            if (xhr.status === 200) {
                // User is logged in, show logged-in config
                clay.config = loggedInConfig;                
                Pebble.openURL(clay.generateUrl());
            } else if (xhr.status === 401) {
                // User is not logged in, show not-logged-in config
                clay.config = loggedOutConfig;
                Pebble.openURL(clay.generateUrl());
            } else {
                console.error('Error fetching user data: ' + xhr.statusText);
                clay.config = loggedOutConfig;
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

