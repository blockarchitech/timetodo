Pebble.addEventListener("showConfiguration", function() {
    Pebble.getTimelineToken(function(token) {
        var url = 'https://timetodo-282379823777.us-central1.run.app/config/pebble'
        var query = new URLSearchParams({
            'timeline_token': token,
            'account_token': Pebble.getAccountToken(),
        });
        url += '?' + query.toString();
        Pebble.openURL(url);
    }, function(error) {
        console.error('Error getting timeline token: ' + error);
        Pebble.openURL('https://timetodo-282379823777.us-central1.run.app/config/pebble');
    })
});

Pebble.addEventListener("webviewclosed", function(e) {
    // close app
    Pebble.sendAppMessage({'Close': 1}, function() {
        console.log('App closed successfully');
    });
})
