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

var DATA_TYPES = { LOGIN: 1, REGISTER: 2, GLOGIN: 3, CHAT: 4, GET_CHAT: 5, TOKEN_AUTH: 7 };

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
                            console.log('Account can only be accessed by Google Login');
                            callback({code: CODES.LOGIN.GONLY, message: 'Account can only be accessed by Google Login'});
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

function GIdCheck(gId, callback) {
    con.query('SELECT gId FROM s15409471.gUsers WHERE gUsers.gId = ?;', [gId], function(err, rows, fields) {
        if (err) {
            console.log(err);
            callback(false, err);
        }
        else {
            if (rows.length > 0 && rows[0] != null && rows[0].gId == gId) {
                callback(true);
            }
            else {
                callback(false);
            }
        }
    });
}
/*GIdCheck(51322, function(exists, err) {
    if (err) {
        console.log(err);
    }
    else {
        console.log('gId: ' + 51322 + ' check returned: ' + exists);
    }
});*/

function LinkGAccount(gId, email, callback) {
    con.query('INSERT INTO gUsers (uId, gId) (SELECT Users.uId, ? FROM Users WHERE Users.email = ? LIMIT 0,1);', [gId, email], function(err, rows, fields) {
        if (err) {
            console.log(err);
            callback(err);
        }
        else {
            console.log('gId: "' + gId + '" has been linked too: "' + email + '"');
            callback();
        }
    });
}

function GLogin(gId, email, name, callback) {
    EmailCheck(email, function(exists, err) {
        if (err) {
            console.log(err);
            callback({code: CODES.GLOGIN.FATAL_ERROR});
        }
        else {
            if (exists) {
                con.query('SELECT gId, email, password FROM s15409471.Users, s15409471.gUsers WHERE gUsers.uId = Users.uId AND gUsers.gId = ?;', [gId], function(err, rows, fields) {
                    if (err) {
                        console.log(err);
                        callback({code: CODES.GLOGIN.FATAL_ERROR, message: 'An error occured!'});
                    }
                    else {
                        if (rows.length > 0 && rows[0] != null) {
                            if (rows[0].gId == gId && rows[0].email == email) {
                                // Email exists and matches gId in database, sign in complete
                                console.log(gId + ':' + email + ' signed in');
                                callback({code: CODES.GLOGIN.SUCCESS});
                            }
                            else {
                                console.log('gId exists but does not match the email provided from Google');
                                callback({code: CODES.GLOGIN.EMAIL_MISMATCH, message: 'Your Google Email does not match our records'});
                            }
                        }
                        else {
                            // Email exists but no gId matches, link email to gId and ask for password to continue
                            console.log('Link required');
                            LinkGAccount(gId, email, function(err) {
                                if (err) {
                                    console.log(err);
                                    callback({code: CODES.GLOGIN.FATAL_ERROR, message: 'An error occured!'});
                                }
                                else {
                                    callback({code: CODES.GLOGIN.SUCCESS});
                                }
                            });
                        }
                    }
                });
            }
            else {
                // Email does not exist, check to ensure the gId does not already exist
                GIdCheck(gId, function(exists, err) {
                    if (err) {
                        console.log(err);
                        callback({code: CODES.GLOGIN.FATAL_ERROR, message: 'An error occured!'});
                    }
                    else {
                        if (exists) {
                            console.log('gId: ' + gId + ' already exists');
                            callback({code: CODES.GLOGIN.GID_EXISTS, message: 'Google Id already exists in our records'});
                        }
                        else {
                            Register(email, null, function(err) {
                                if (err.code == CODES.REGISTER.SUCCESS) {
                                    // Link account
                                    LinkGAccount(gId, email, function(err) {
                                        if (err) {
                                            callback({code: CODES.GLOGIN.FATAL_ERROR, message: 'An error occured!'});
                                        }
                                        else {
                                            callback({code: CODES.GLOGIN.SUCCESS});
                                        }
                                    });
                                }
                                else {
                                    console.log('Error attempting to auto register google account');
                                    callback({code: CODES.GLOGIN.FATAL_ERROR, message: 'An error occured!'});
                                }
                            });
                        }
                    }
                });
            }
        }
    });
}
/*GLogin(51327, 'test97', 'Fred', function(err) {
    console.log(err);
});*/

//console.log(JSON.stringify({type: 0, email: 'test10', password: 'Password1'}));

const CODES = {
    RESPONDING: { REGISTER: 0, PASSWORD: 1, LOGIN: 2, GLOGIN: 3, TOKEN_GEN: 4 },
    REGISTER: { EMAIL_EXISTS: 0, WEAK_PASS: 1, FATAL_ERROR: 2, SUCCESS: 3 },
    PASSWORD: { SHORT: 0, UPPER: 1, NUMBER: 2 },
    LOGIN: { EMAIL_FAIL: 0, PASS_WRONG: 1, FATAL_ERROR: 2, GONLY: 3, SUCCESS: 4 },
    GLOGIN: { VERIFY_FAIL: 0, EMAIL_MISMATCH: 1, UNLINKED_EXISTS: 2, GID_EXISTS: 3, FATAL_ERROR: 4, SUCCESS: 5 },
    TOKEN_GEN: { FATAL_ERROR: 0, SUCCESS: 1 },
    TOKEN_AUTH: { INVALID: 0, FATAL_ERROR: 1, SUCCESS: 2 },
}

function GenerateToken(uId, callback) {
    var tokenStr = uuidv4();
    con.query('INSERT INTO s15409471.Tokens (uId, token) VALUES (?, ?);', [uId, tokenStr], function (err, rows, fields) {
        if (err) {
            console.log(err);
            callback({ code: CODES.TOKEN_GEN.FATAL_ERROR });
        }
        else {
            console.log('Generated token for uId: "' + uId + '" token: "' + tokenStr + '"');
            callback({ code: CODES.TOKEN_GEN.SUCCESS, token: tokenStr });
        }
    });
}
/*GenerateToken('156150544', function(err) {
    console.log(err)
});*/

function AuthToken(token, callback) {
    con.query('SELECT uId FROM s15409471.Tokens WHERE token = ?;', [token], function (err, rows, fields) {
        if (err) {
            console.log(err);
            callback({ code: CODES.TOKEN_AUTH.FATAL_ERROR });
        }
        else {
            if (rows.length > 0 && rows[0] != null && rows[0].uId != null) {
                console.log('Token: "' + token + '" authenticated to be uId: "' + rows[0].uId + '"');
                callback({ code: CODES.TOKEN_AUTH.SUCCESS, uId: rows[0].uId });
            }
            else {
                console.log('Token: "' + token + '" attempted to authenticate but does not exist in database');
                callback({ code: CODES.TOKEN_AUTH.INVALID });
            }
        }
    });
}
/*AuthToken('b08b4c94-1cb1-4bcb-bc72-6655c4f35f41', function(err) {
    console.log(err)
});*/

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
                            err.responding = CODES.RESPONDING.LOGIN;
                            console.log(err);
                            socket.write(JSON.stringify(err)+"\n");
                        });
                    }
                    else {
                        console.log('Recieved Login message without email and password properties');
                    }
                    break;
                case DATA_TYPES.REGISTER:
                    if (obj.hasOwnProperty('email') && obj.hasOwnProperty('password') && obj.password != null) {
                        Register(obj.email, obj.password, function(err) {
                            err.responding = CODES.RESPONDING.REGISTER;
                            console.log(err);
                            socket.write(JSON.stringify(err)+"\n");
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
                                if (ticket.payload.email_verified) {
                                    //console.log('Attempt login using google id: ' + ticket.payload.sub);
                                    //console.log(ticket);
                                    GLogin(ticket.payload.sub, ticket.payload.email, ticket.payload.name, function(err) {
                                        err.responding = CODES.RESPONDING.GLOGIN;
                                        console.log(err);
                                        socket.write(JSON.stringify(err)+"\n");
                                    });
                                }
                                else {
                                    console.log('Email not verified, denied access');
                                    socket.write(JSON.stringify({respoding: CODES.RESPONDING.GLOGIN, code: CODES.GLOGIN.VERIFY_FAIL, message: 'Google email is not verified, please verify before registering.'})+"\n");
                                }
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
                case DATA_TYPES.TOKEN_AUTH:
                    
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