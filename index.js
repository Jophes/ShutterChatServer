const net = require('net');
const keys = require('./keys.json');

const mysql = require('mysql');
const con = mysql.createConnection({ host: "192.168.0.24", user: "student", password: "student", database: "s15409471" });

const bcrypt = require('bcrypt');
const saltRounds = 10;
/*bcrypt.hash(password, saltRounds, function(err, hash) {
    if (err) {
    }
    else {
    }
});*/
// Unique Id generation
// SELECT rand FROM (SELECT FLOOR(cast(RAND() * 4294967295 as unsigned)) AS rand UNION SELECT FLOOR(cast(RAND() * 4294967295 as unsigned)) AS rand) AS rand_nums WHERE `rand` NOT IN (SELECT uId FROM s15409471.Users) LIMIT 1;

const uuidv4 = require('uuid/v4');
//tokenStr = uuidv4();

const gal = require('google-auth-library');
const auth = new gal.GoogleAuth();
const client = new gal.OAuth2Client();

var DATA_TYPES = { LOGIN: 1, REGISTER: 2, GLOGIN: 3, CHAT: 4, GET_CHAT: 5 };

//console.log(JSON.stringify({ type: DATA_TYPES.LOGIN, username: 'Jophes', firstname: 'Joseph', lastname: 'Higgins' }));

console.log('Starting...');

function GenUniqueID(callback) {
    con.query('SELECT rand FROM (SELECT FLOOR(cast(RAND() * 4294967295 as unsigned)) AS rand UNION SELECT FLOOR(cast(RAND() * 4294967295 as unsigned)) AS rand) AS rand_nums WHERE `rand` NOT IN (SELECT uId FROM s15409471.Users) LIMIT 1;', [], function(err, rows, fields) {
        if (err) {
            console.log('Failed to get unique id');
            console.log(err);
            callback(null, err);
        }
        else {
            if (rows.length > 0 && rows[0].hasOwnProperty('rand') && rows[0].rand != null) {
                callback(rows[0].rand);
            }
            else {
                console.log('Error, random id returned doesn\'t exist');
                console.log(rows);
                callback(null, {});
            }
        }
    });
}
// GenUniqueID(function (id, err) { console.log('got id: ' + id); });

function EmailCheck(email, callback) {
    con.query('SELECT email FROM s15409471.Users WHERE Users.email = ?', [email], function(err, rows, fields) {
        if (err) {
            console.log('Failed to search database for email');
            console.log(err);
            callback(false, err);
        }
        else {
            callback(rows.length > 0);
        }
    });
}
// EmailCheck('test2', function(exists, err) { console.log('email exists: ' + exists); });

const CODES = {
    REGISTER: { EMAIL_EXISTS: 0, WEAK_PASS: 1, FATAL_ERROR: 2, SUCCESS: 3 },
    PASSWORD: { SHORT: 0, UPPER: 1, NUMBER: 2 },
    LOGIN: { EMAIL_FAIL: 0, PASS_WRONG: 1, FATAL_ERROR: 2, SUCCESS: 3 },
}

function Login(email, password, callback) {
    EmailCheck(email, function(exists, err) {
        if (err) {
            callback({code: CODES.LOGIN.FATAL_ERROR, message: 'An error occured!'});
        }
        else {
            if (exists) {
                con.query('SELECT password FROM s15409471.Users WHERE Users.email = ?;', [email], function(err, rows, fields) {
                    if (err) {
                        console.log('Failed to fetch password from database!');
                        console.log(err);
                        callback({code: CODES.LOGIN.FATAL_ERROR, message: 'An error occured!'});
                    }
                    else {
                        if (rows.length > 0 && rows[0].hasOwnProperty('password') && rows[0].password != null) {
                            bcrypt.compare(password, rows[0].password, function(err, res) {
                                if (err) {
                                    console.log('Failed to compare hashed string to real string');
                                    console.log(err);
                                    callback({code: CODES.LOGIN.FATAL_ERROR, message: 'An error occured!'});
                                }
                                else {
                                    if (res) {
                                        console.log('User: "' + email + '" logged in');
                                        callback({code: CODES.LOGIN.SUCCESS});
                                    }
                                    else {
                                        console.log('User: "' + email + '" attempted to log in using an incorrect password');
                                        callback({code: CODES.LOGIN.PASS_WRONG, message: 'Password incorrect'});
                                    }
                                }
                            });
                        }
                        else {
                            console.log('Error, couldn\'t find password that should exist');
                            console.log(rows);
                            callback({code: CODES.LOGIN.FATAL_ERROR, message: 'An error occured!'});
                        }
                    }
                });
            }
            else {
                console.log('User attempted to log in using email: "' + email + '" that doesn\'t exist');
                callback({code: CODES.LOGIN.EMAIL_FAIL, message: 'Email is not registered'});
            }
        }
    });
}
/*Login('test10', 'Password', function(err) {
    console.log(err);
});*/

function PasswordStrength(password) {
    var errors = [];
    if (password != null) {
        if (password.length <= 2) {
            errors.push({code: CODES.PASSWORD.SHORT, message: 'Password must be longer than 2 characters'});
        }
        if (password.search(/[A-Z]/) < 0) {
            errors.push({code: CODES.PASSWORD.UPPER, message: 'Password must contain an upper case letter'});
        }
        if (password.search(/[0-9]/) < 0) {
            errors.push({code: CODES.PASSWORD.NUMBER, message: 'Password must contain a number'});
        }
    }
    return errors;
}
//console.log(PasswordStrength('Password1'));

function Register(email, password, callback) {
    const passwordErrors = PasswordStrength(password);
    if (passwordErrors.length == 0) {
        GenUniqueID(function (id, err) {
            if (err) {
                callback({code: CODES.REGISTER.FATAL_ERROR, message: 'An error occured!'});
            } 
            else {
                EmailCheck(email, function(exists, err) {
                    if (err) {
                        callback({code: CODES.REGISTER.FATAL_ERROR, message: 'An error occured!'});
                    }
                    else {
                        if (exists) {
                            console.log('Register attempt failed, email "' + email + '" already exists!');
                            callback({code: CODES.REGISTER.EMAIL_EXISTS, message: 'Email already registered'});
                        }
                        else {
                            bcrypt.hash(password, saltRounds, function(err, hash) {
                                if ((password == null && err) || !err) {
                                    if (password != null) {
                                        con.query('INSERT INTO s15409471.Users (uId, email, password) VALUES (?, ?, ?);', [id, email, hash], function(err, rows, fields) {
                                            if (err) {
                                                console.log('Failed to insert user into database!');
                                                console.log(err);
                                                callback({code: CODES.REGISTER.FATAL_ERROR, message: 'An error occured!'});
                                            }
                                            else {
                                                console.log('User: "' + email + '" registered');
                                                callback({code: CODES.REGISTER.SUCCESS});
                                            }
                                        });
                                    }
                                    else {
                                        con.query('INSERT INTO s15409471.Users (uId, email) VALUES (?, ?);', [id, email], function(err, rows, fields) {
                                            if (err) {
                                                console.log('Failed to insert user into database!');
                                                console.log(err);
                                                callback({code: CODES.REGISTER.FATAL_ERROR, message: 'An error occured!'});
                                            }
                                            else {
                                                console.log('User: "' + email + '" registered');
                                                callback({code: CODES.REGISTER.SUCCESS});
                                            }
                                        });
                                    }
                                }
                                else {
                                    console.log('Register attempt failed, could not hash password!');
                                    console.log(err);
                                    callback({code: CODES.REGISTER.FATAL_ERROR, message: 'An error occured!'});
                                }
                            });
                        }
                    }
                });
            }
        });
    }
    else {
        callback({code: CODES.REGISTER.WEAK_PASS, weaknesses: passwordErrors});
    }
}
/*Register('test11', 'Password1', function(err) {
    if (err.code == CODES.REGISTER.SUCCESS) {
        console.log('Succesfully created account');
    }
    else {
        console.log(err);
    }
});*/

function ChangeName(email, name, callback) {

}

function GLogin(gId, email, name, callback) {
    EmailCheck(email, function(exists, err) {
        if (err) {
            console.log(err);
        }
        else {
            if (exists) {
                con.query('SELECT gUsers.gId, email, password FROM s15409471.Users, s15409471.gUsers WHERE gUsers.uId = Users.uId AND gUsers.gId = ?;', [gId], function(err, rows, fields) {
                    if (err) {
                        console.log(err);
                    }
                    else {
                        if (rows[0].gId == gId && rows[0].email == email) {
                            // Email exists and matches gId in database, sign in complete
                            console.log('Sign in complete');
                        }
                        else {
                            // Email exists but no gId matches, link email to gId and ask for password to continue

                        }
                    }
                });
            }
            else {
                // Email does not exist, register account and link to gId
                Register(email, null, function(err) {
                    console.log(err);
                });
            }
        }
    });
}
GLogin(51321, 'test90', 'Fred', function() {

});

//console.log(JSON.stringify({type: 0, email: 'test10', password: 'Password1'}));

var server = net.createServer(function(socket) {
    console.log('Connection made');
    socket.on('data', function(data) {
        var obj = {};
        try {
            obj = JSON.parse(data.toString());
        }
        catch (e) {
            console.log('Failed to parse message from ' + socket.remoteAddress);
        }
        if (obj.hasOwnProperty('type')) {
            console.log(data.toString());
            switch (obj.type) {
                case DATA_TYPES.LOGIN:
                    if (obj.hasOwnProperty('email') && obj.hasOwnProperty('password')) {
                        Login(obj.email, obj.password, function(err) {
                            socket.write(JSON.stringify(err));
                        });
                    }
                    else {
                        console.log('Recieved Login message without email and password properties');
                    }
                    break;
                case DATA_TYPES.REGISTER:
                    if (obj.hasOwnProperty('email') && obj.hasOwnProperty('password')) {
                        Register(obj.email, obj.password, function(err) {
                            socket.write(JSON.stringify(err));
                        });
                    }
                    else {
                        console.log('Recieved Register message without email and password properties');
                    }
                    break;
                case DATA_TYPES.GLOGIN:
                    if (obj.hasOwnProperty('idToken')) {
                        client.verifyIdToken({idToken: obj.idToken, audience: keys.nodejs.client_id}, function (err, ticket) {
                            if (!err && ticket && ticket.hasOwnProperty('payload') && ticket.payload.hasOwnProperty('sub')) {
                                console.log('Attempt login using google id: ' + ticket.payload.sub);
                                console.log(ticket);
                                
                            }
                        });
                    }
                    else {
                        console.log('Recieved GLogin message without idToken property');
                    }
                    break;
                case DATA_TYPES.CHAT:
                
                    break;
                case DATA_TYPES.GET_CHAT:
                    
                    break;
                default:
                    console.log('Invalid message type value');
                    break;
            }
        }
    });

    socket.on('end', function() {
        console.log('Connected Ended');
    });
    socket.on('error', function(err) {
        console.log('Socket error!');
        console.log(err);
        console.log('Possible abrubt closing of socket on remote end, attempting to continue');
    });
});

server.listen(47896);

process.on('SIGINT', function() {
    console.log('...Stopping');
    process.exit();
});