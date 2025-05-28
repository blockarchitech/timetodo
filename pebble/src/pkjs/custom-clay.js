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

module.exports = function (minified) {
    var clayConfig = this;
    var _ = minified._;
    var $ = minified.$;
    var HTML = minified.HTML;

    var token = clayConfig.meta.userData.token || '';

    function loginClick() {
        var loginUrl = 'https://timetodo-282379823777.us-central1.run.app/auth/login?token=' + encodeURIComponent(token);
        window.location.href = loginUrl;
    }

    function deleteClick() {
        var xhr = new XMLHttpRequest();
        xhr.open('DELETE', 'https://timetodo-282379823777.us-central1.run.app/api/v1/me', true);
        xhr.setRequestHeader('Authorization', 'Bearer ' + token);
        xhr.onload = function () {
            if (xhr.status === 204) {
                alert('Your account has been deleted. You will be logged out.');
                window.location.href = 'pebblejs://close';
            } else {
                alert('Error in deletion request: ' + xhr.statusText);
            }
        };
        xhr.onerror = function () {
            alert('Error deleting account: ' + xhr.statusText);
        };
        xhr.send();
    }

    clayConfig.on(clayConfig.EVENTS.AFTER_BUILD, function() {
        var loginButton = clayConfig.getItemById('loginButton');
        if (!loginButton) {
            console.warn('Login button not found in the configuration.');
        } else {
            loginButton.on('click', loginClick);
        }
        
        var deleteButton = clayConfig.getItemById('deleteButton');
        if (!deleteButton) {
            console.warn('Delete button not found in the configuration.');
        } else {
            deleteButton.on('click', deleteClick);
            deleteButton.style.backgroundColor = '#ff0000'; // Set delete button color to red
            deleteButton.style.color = '#ffffff'; // Set delete button text color to white
        }

    });
};