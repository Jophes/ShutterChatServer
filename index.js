const net = require('net');
const gal = require('google-auth-library');
const keys = require('./keys.json');
const auth = new gal.GoogleAuth();
const client = new gal.OAuth2Client();

console.log(keys);

var server = net.createServer(function(socket) {
    console.log('Connection made');
    socket.on('data', function(data) {
        var token = data.toString()
        console.log(token);
        client.verifyIdToken(token, CLIENT_ID, function(e, login) {
            var payload = login.getPayload();
            var userid = payload['sub'];
            console.log("HELLO " + userid + " : " + payload);
        });
    });
});

server.listen(47896);