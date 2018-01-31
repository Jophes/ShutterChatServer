const net = require('net');
const gal = require('google-auth-library');
const keys = require('./keys.json');
const auth = new gal.GoogleAuth();
const client = new gal.OAuth2Client();

var server = net.createServer(function(socket) {
    console.log('Connection made');
    socket.on('data', function(data) {
        const ticket = client.verifyIdToken({idToken: data.toString(), audience: keys.nodejs.client_id}, function (err, ticket, res) {
            console.log(err);
            console.log(ticket);
            console.log(res);
        });
    });
});

server.listen(47896);