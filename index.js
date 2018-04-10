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
                con.query('SELECT uId, password FROM s15409471.Users WHERE Users.email = ?;', [email], function(err, rows, fields) {
                    if (err) {
                        console.log('Failed to fetch password from database!');
                        console.log(err);
                        callback({code: CODES.LOGIN.FATAL_ERROR, message: 'An error occured!'});
                    }
                    else {
                        if (rows.length > 0 && rows[0].hasOwnProperty('password') && rows[0].password != null && rows[0].uId != null) {
                            bcrypt.compare(password, rows[0].password, function(err, res) {
                                if (err) {
                                    console.log('Failed to compare hashed string to real string');
                                    console.log(err);
                                    callback({code: CODES.LOGIN.FATAL_ERROR, message: 'An error occured!'});
                                }
                                else {
                                    if (res) {
                                        console.log('User: "' + email + '" logged in');
                                        callback({code: CODES.LOGIN.SUCCESS, uId: rows[0].uId});
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
                                                callback({code: CODES.REGISTER.SUCCESS, uId: id});
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
                                                callback({code: CODES.REGISTER.SUCCESS, uId: id});
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


function GetUIdFromGId(gId, callback) {
    con.query('SELECT uId FROM s15409471.gUsers WHERE gId = ?;', [gId], function (err, rows, fields) {
        if (err) {
            console.log(err);
            callback(null);
        }
        else {
            if (rows.length > 0 && rows[0] != null && rows[0].uId != null) {
                console.log('Found uId: "' + rows[0].uId + '" for gId: "' + gId + '"');
                callback(rows[0].uId);
            }
            else {
                console.log('Failed to find uId for gId: "' + gId + '"');
                callback(null);
            }
        }
    });
}

function GenerateToken(uId, callback) {
    var tokenStr = uuidv4();
    con.query('INSERT INTO s15409471.Tokens (uId, token) VALUES (?, ?);', [uId, tokenStr], function (err, rows, fields) {
        if (err) {
            console.log(err);
            callback(null);
        }
        else {
            console.log('Generated token for uId: "' + uId + '" token: "' + tokenStr + '"');
            callback(tokenStr);
        }
    });
}
// VALIDATE UID FIRST
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

// Get user's profile
function GetProfile(uId, callback) {
    con.query('SELECT email, IFNULL(name, \'\') as name, picture FROM Users WHERE uId = ?;', [uId], function (err, rows, fields) {
        if (err) {
            console.log(err);
            callback(null);
        }
        else {
            if (rows.length > 0 && rows[0] != null) {
                var returnData = {
                    uId: uId,
                    email: rows[0].email,
                    name: rows[0].name,
                };
                if (rows[0].picture != null) {
                    returnData.url = rows[0].picture;
                }
                callback(returnData);
            }
            else {
                callback(null);
            }
        }
    });
}
/*GetProfile(1467209517, function(data) {
    if (data == null) {
        // Error
    }
    else {
        console.log(data);
    }
});*/

// Get user's chat history and other users
function GetChatOverview(uId, callback) {
    var todaysDate = new Date();
    //con.query('SELECT * FROM (SELECT uId, email, name, picture, sender, reciever, message, sent, status FROM s15409471.Messages, s15409471.Users WHERE (Messages.sender = ? AND Messages.reciever = Users.uId) OR (Messages.sender = Users.uId AND Messages.reciever = ?) ORDER BY sent DESC) AS Sorted GROUP BY uId ORDER BY sent DESC;', [uId, uId], function (err, rows, fields) {
    //con.query('SELECT uId, email, name, picture, sender, reciever, IFNULL(message, \'\') AS message, sent, IFNULL(status, 0) AS status FROM s15409471.Users LEFT JOIN s15409471.Messages ON (Users.uId = Messages.sender OR Users.uId = Messages.reciever) WHERE uId != ? AND ((sender = ? OR reciever = ?) OR (isnull(sender) AND isnull(reciever))) ORDER BY sent DESC;', [uId, uId, uId], function (err, rows, fields) {
    con.query('SELECT * FROM (SELECT * FROM (SELECT uId, email, name, picture, sender, reciever, IFNULL(message, \'\') AS message, sent, IFNULL(status, 0) AS status FROM s15409471.Users LEFT JOIN (SELECT * FROM s15409471.Messages WHERE (sender = ? OR reciever = ?)) AS Messages ON (Users.uId = Messages.sender OR Users.uId = Messages.reciever) WHERE uId != ? ORDER BY sent DESC) AS Sorted GROUP BY uId) AS Sorted ORDER BY sent DESC;', [uId, uId, uId], function (err, rows, fields) {
        if (err) {
            console.log(err);
            callback(null);
        }
        else {
            var chatOverview = [];
            for (const i in rows) {
                if (rows.hasOwnProperty(i)) {
                    const row = rows[i];
                    var chatView = {
                        uId: row.uId,
                        name: (row.name == null ? row.email : row.name),
                        sender: (row.sender != null && row.sender == uId),
                        lastMessage: (row.sender == uId ? 'You: ' : '') + row.message,
                        status: row.status,
                    };
                    
                    if (row.sent != null) {
                        var dateTime = new Date(row.sent);
                        if (dateTime.getFullYear() != todaysDate.getFullYear()) {
                            chatView.lastTime = dateTime.getFullYear();
                        }
                        else if (dateTime.getDate() != todaysDate.getDate()) {
                            var dayDiff = Math.floor((todaysDate - dateTime) / (1000*60*60*24));
                            if (dayDiff >= 7) {
                                var months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
                                chatView.lastTime = dateTime.getDate() + " " + months[dateTime.getMonth()];
                            }
                            else {
                                var days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
                                chatView.lastTime = days[dateTime.getDay()];
                            }
                        }
                        else {
                            chatView.lastTime = dateTime.getHours() + ":" + dateTime.getMinutes();
                        }
                    }
                    else {
                        chatView.lastTime = null;
                    }

                    if (row.picture != null) {
                        chatView.url = row.picture;
                    }
                    chatOverview.push(chatView);
                }
            }
            callback(chatOverview);
        }
    });
}
/*GetChatOverview(1467209517, function(data) {
    if (data == null) {
        // Error
    }
    else {
        console.log(data);
    }
});*/

// Get messages between users
function GetChat() {

}

function SetProfileName(uId, name, callback) {
    con.query('UPDATE Users SET name=? WHERE uId=?;', [name, uId], function (err, rows, fields) {
        if (err) {
            console.log(err);
        }
        else {
            callback();
        }
    });
}

function SetMessagesRead(user, other, callback) {
    con.query('UPDATE Messages SET status = 1 WHERE Messages.sender = ? AND Messages.reciever = ?;', [user, other], function (err, rows, fields) {
        if (err) {
            console.log(err);
        }
        else {
            callback();
        }
    });
}

function GetUserMessages(user, other, callback) {
    con.query('SELECT * FROM (SELECT sender, type, message, sent FROM Messages WHERE (sender = ? AND reciever = ?) or (sender = ? AND reciever = ?) ORDER BY sent DESC LIMIT 0, 50) AS Sorted ORDER BY sent ASC;', [user, other, other, user], function (err, rows, fields) {
        if (err) {
            console.log(err);
            callback(null);
        }
        else {
            var userMessages = [];
            for (const i in rows) {
                if (rows.hasOwnProperty(i)) {
                    const row = rows[i];
                    userMessages.push({
                        sender: row.sender,
                        msgType: row.type,
                        message: row.message,
                        sent: row.sent
                    });
                }
            }
            callback(userMessages);
        }
    });
}
/*GetUserMessages('114815412', '1467209517', function(messages) {
    if (messages != null) {
        console.log(messages);
    }
});*/

function SendMessage(user, type, other, message, callback) {
    con.query('INSERT INTO Messages (sender, reciever, message, type) VALUES (?, ?, ?, ?);', [user, other, message, type], function (err, rows, fields) {
        if (err) {
            console.log(err);
        }
        else {
            callback();
        }
    });
}
//SendMessage('114815412', '1467209517', 'This is a test message');

const CODES = {
    RESPONDING: { REGISTER: 0, PASSWORD: 1, LOGIN: 2, GLOGIN: 3, TOKEN_AUTH: 4, GET_CHATS: 5, GET_MESSAGES: 6, GET_PROFILE: 7 },
    REGISTER: { EMAIL_EXISTS: 0, WEAK_PASS: 1, FATAL_ERROR: 2, SUCCESS: 3 },
    PASSWORD: { SHORT: 0, UPPER: 1, NUMBER: 2 },
    LOGIN: { EMAIL_FAIL: 0, PASS_WRONG: 1, FATAL_ERROR: 2, GONLY: 3, SUCCESS: 4 },
    GLOGIN: { VERIFY_FAIL: 0, EMAIL_MISMATCH: 1, UNLINKED_EXISTS: 2, GID_EXISTS: 3, FATAL_ERROR: 4, SUCCESS: 5 },
    TOKEN_AUTH: { INVALID: 0, FATAL_ERROR: 1, SUCCESS: 2 }
}

var DATA_TYPES = { LOGIN: 1, REGISTER: 2, GLOGIN: 3, CHAT: 4, GET_CHATS: 5, GET_PROFILE: 6, TOKEN_AUTH: 7, UPDATE_PROFILE: 8, GET_MESSAGES: 9, SEND_MESSAGE: 10, MESSAGES_READ: 11 };

var clients = {};

function Client(socket) {
    var self = this;

    this.uId = null;
    this.socket = socket;

    self.sendMessages = function(uId, other = null) {
        if (uId != null) {
            console.log("Sending " + uId + " message data");
            if (other != null) {
                GetUserMessages(uId, other, function(messages) {
                    if (messages != null) {
                        //console.log(messages);
                        socket.write(JSON.stringify({responding: CODES.RESPONDING.GET_MESSAGES, messages: messages, other: other})+"\n");
                    }
                });
            }
            GetChatOverview(uId, function(data) {
                if (data == null) {
                    // Error
                }
                else {
                    //console.log(data);
                    socket.write(JSON.stringify({responding: CODES.RESPONDING.GET_CHATS, chats: data})+"\n");
                }
            });
        }
    }

    self.sendProfile = function(uId) {
        if (uId != null) {
            GetProfile(uId, function(data) {
                if (data == null) {
                    // Error
                }
                else {
                    //console.log(data);
                    socket.write(JSON.stringify({responding: CODES.RESPONDING.GET_PROFILE, profile: data})+"\n");
                }
            });
        }
    }

    self.setUId = function(uId) {
        if (uId != null) {
            if (self.uId != null) {
                delete clients[self.uId];
            }
            self.uId = uId;
            clients[self.uId] = self;
            
            self.sendMessages(uId);
            self.sendProfile(uId);
        }
    };
    
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
                            if (err.code == CODES.LOGIN.SUCCESS && err.uId != null) {
                                GenerateToken(err.uId, function(token) {
                                    if (token == null) {
                                        err.code = CODES.LOGIN.FATAL_ERROR;
                                        console.log(err);
                                        socket.write(JSON.stringify(err)+"\n");
                                    }
                                    else {
                                        err.token = token;
                                        console.log(err);
                                        self.setUId(err.uId);
                                        socket.write(JSON.stringify(err)+"\n");
                                    }
                                });
                            }
                            else {
                                console.log(err);
                                socket.write(JSON.stringify(err)+"\n");
                            }
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
                            if (err.code == CODES.REGISTER.SUCCESS && err.uId != null) {
                                GenerateToken(err.uId, function(token) {
                                    if (token == null) {
                                        err.code = CODES.REGISTER.FATAL_ERROR;
                                        console.log(err);
                                        socket.write(JSON.stringify(err)+"\n");
                                    }
                                    else {
                                        err.token = token;
                                        console.log(err);
                                        self.setUId(err.uId);
                                        socket.write(JSON.stringify(err)+"\n");
                                        self.sendMessages(err.uId);
                                    }
                                });
                            }
                            else {
                                console.log(err);
                                socket.write(JSON.stringify(err)+"\n");
                            }
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
                                        if (err.code == CODES.GLOGIN.SUCCESS) {
                                            GetUIdFromGId(ticket.payload.sub, function(uId) {
                                                if (uId == null) {
                                                    err.code = CODES.GLOGIN.FATAL_ERROR;
                                                    console.log(err);
                                                    socket.write(JSON.stringify(err)+"\n");
                                                }
                                                else {
                                                    GenerateToken(uId, function(token) {
                                                        if (token == null) {
                                                            err.code = CODES.GLOGIN.FATAL_ERROR;
                                                            console.log(err);
                                                            socket.write(JSON.stringify(err)+"\n");
                                                        }
                                                        else {
                                                            err.token = token;
                                                            console.log(err);
                                                            self.setUId(uId);
                                                            socket.write(JSON.stringify(err)+"\n");
                                                            self.sendMessages(uId);
                                                        }
                                                    });
                                                }
                                            });
                                        }
                                        else {
                                            console.log(err);
                                            socket.write(JSON.stringify(err)+"\n");
                                        }
                                    });
                                }
                                else {
                                    console.log('Email not verified, denied access');
                                    socket.write(JSON.stringify({responding: CODES.RESPONDING.GLOGIN, code: CODES.GLOGIN.VERIFY_FAIL, message: 'Google email is not verified, please verify before registering.'})+"\n");
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
                case DATA_TYPES.GET_CHATS:
                    if (self.uId != null) {
                        GetChatOverview(self.uId, function(data) {
                            if (data == null) {
                                // Error
                            }
                            else {
                                //console.log(data);
                                socket.write(JSON.stringify({responding: CODES.RESPONDING.GET_CHATS, chats: data, requested: true})+"\n");
                            }
                        });
                    }
                    else {
                        console.log("Recieved get chat message from not logged in session, ignoring");
                    }
                    break;
                case DATA_TYPES.GET_PROFILE:
                    if (self.uId != null) {
                        GetProfile(self.uId, function(data) {
                            if (data == null) {
                                // Error
                            }
                            else {
                                //console.log(data);
                                socket.write(JSON.stringify({responding: CODES.RESPONDING.GET_PROFILE, profile: data})+"\n");
                            }
                        });
                    }
                    else {
                        console.log("Recieved get chat message from not logged in session, ignoring");
                    }
                    break;
                case DATA_TYPES.TOKEN_AUTH:
                    if (obj.hasOwnProperty('token')) {
                        AuthToken(obj.token, function(err) {
                            err.responding = CODES.RESPONDING.TOKEN_AUTH;
                            console.log(err)
                            self.setUId(err.uId);
                            socket.write(JSON.stringify(err)+"\n");
                        });
                    }
                    else {
                        console.log('Recieved Token Auth message without token property, ignoring');
                    }
                    break;
                case DATA_TYPES.UPDATE_PROFILE:
                    if (self.uId != null && obj.hasOwnProperty('name')) {
                        SetProfileName(self.uId, obj.name, function() {
                            GetProfile(self.uId, function(data) {
                                if (data == null) {
                                    // Error
                                }
                                else {
                                    console.log(data);
                                    socket.write(JSON.stringify({responding: CODES.RESPONDING.GET_PROFILE, profile: data})+"\n");
                                }
                            });
                        });
                    }
                    else {
                        console.log("Recieved set profile from not logged in session, ignoring");
                    }
                    break;
                case DATA_TYPES.GET_MESSAGES:
                    if (self.uId != null && obj.hasOwnProperty('other')) {
                        GetUserMessages(self.uId, obj.other, function(messages) {
                            if (messages != null) {
                                //console.log(messages);
                                socket.write(JSON.stringify({responding: CODES.RESPONDING.GET_MESSAGES, messages: messages, other: obj.other, requested: true})+"\n");

                                SetMessagesRead(obj.other, self.uId, function() {
                                    //console.log("MESSAGES READ");
                                    self.sendMessages(self.uId);
                                    if (clients[obj.other] != null) {
                                        clients[obj.other].sendMessages(obj.other);
                                    }
                                });
                            }
                        });
                    }
                    else {
                        console.log("Recieved GET_MESSAGES from not logged in session, ignoring");
                    }
                    break;
                case DATA_TYPES.SEND_MESSAGE:
                    if (self.uId != null && obj.hasOwnProperty('other') && obj.hasOwnProperty('message') && obj.hasOwnProperty('msgType')) {
                        SendMessage(self.uId, obj.msgType, obj.other, obj.message, function() {
                            GetUserMessages(self.uId, obj.other, function(messages) {
                                if (messages != null) {
                                    //console.log(messages);
                                    socket.write(JSON.stringify({responding: CODES.RESPONDING.GET_MESSAGES, messages: messages, other: obj.other, requested: true})+"\n");
                                }
                            });
                            GetChatOverview(self.uId, function(data) {
                                if (data == null) {
                                    // Error
                                }
                                else {
                                    //console.log(data);
                                    socket.write(JSON.stringify({responding: CODES.RESPONDING.GET_CHATS, chats: data})+"\n");
                                }
                            });
                            if (clients[obj.other] != null) {
                                clients[obj.other].sendMessages(obj.other, self.uId);
                            }
                        });
                    }
                    else {
                        console.log("Recieved SEND_MESSAGE from not logged in session, ignoring");
                    }
                    break;
                case DATA_TYPES.MESSAGES_READ: 
                    if (self.uId != null && obj.hasOwnProperty('other')) {
                        SetMessagesRead(obj.other, self.uId, function() {
                            self.sendMessages(self.uId);
                            if (clients[obj.other] != null) {
                                clients[obj.other].sendMessages(obj.other);
                            }
                        });
                    }
                    else {
                        console.log("Recieved MESSAGES_READ from not logged in session, ignoring");
                    }
                    break;
                default:
                    console.log('Invalid message type value');
                    break;
            }
        }
    });

    self.destroy = function() {
        if (self.uId != null) {
            delete clients[self.uId];
        }
    }

    socket.on('end', function() {
        self.destroy();
        console.log('Connected Ended');
    });

    socket.on('error', function(err) {
        self.destroy();
        console.log('Socket error!');
        console.log(err);
        console.log('Possible abrubt closing of socket on remote end, attempting to continue');
    });
}

var server = net.createServer(function(socket) {
    var client = new Client(socket);
});

server.listen(47896);

process.on('SIGINT', function() {
    console.log('Stopping...');
    process.exit();
    console.log("... Stopped");
});

console.log("... Started");