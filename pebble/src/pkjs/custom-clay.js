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
                console.error('Error logging out: ' + xhr.statusText);
                alert('Error deleting account: ' + xhr.statusText);
            }
        };
        xhr.onerror = function () {
            console.error('Error deleting account: ' + xhr.statusText);
            alert('Error deleting account: ' + xhr.statusText);
        };
        xhr.send();
    }

    clayConfig.on(clayConfig.EVENTS.AFTER_BUILD, function() {
        var loginButton = clayConfig.getItemById('loginButton');
        loginButton.on('click', loginClick);

        var deleteButton = clayConfig.getItemById('deleteButton');
        if (deleteButton) {
            deleteButton.on('click', deleteClick);
        } else {
            console.warn('Delete button not found in the configuration.');
        }
    });
};