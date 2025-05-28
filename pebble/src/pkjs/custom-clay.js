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
        var loginButton = clayConfig.getItemById('loginButton');
        loginButton.disable();
        loginButton.set('Please wait...');
        window.location.href = 'https://timetodo-282379823777.us-central1.run.app/auth/login?token=' + encodeURIComponent(token);
    }

    function deleteClick() {
        window.location.href = 'https://timetodo-282379823777.us-central1.run.app/auth/delete?token=' + encodeURIComponent(token);
    }

    clayConfig.on(clayConfig.EVENTS.AFTER_BUILD, function () {
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
        }

    });
};