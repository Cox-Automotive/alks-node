/*jslint node: true */
'use strict';

let _       = require('underscore'),
    request = require('request'),
    moment  = require('moment'),
    Buffer  = require('buffer').Buffer;

// process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0; // for testing self-signed endpoints

let ALKS_MAX_DURATION = 18, // reducing due to EB not honoring long sessions: , 24, 36 ],
    AWS_SIGNIN_URL    = 'https://signin.aws.amazon.com/federation',
    AWS_CONSOLE_URL   = 'https://console.aws.amazon.com/',
    SANITIZE_FIELDS   = [ 'password', 'refreshToken', 'accessToken', 'accessKey', 'secretKey', 'sessionToken' ],
    DEFAULT_UA        = 'alks-node',
    STATUS_SUCCESS    = 'success';

let getMessageFromBadResponse = function(results){
    if (results.body) {
        if (results.body.errors) {
            return results.body.errors;
        }
    }
    return 'Bad response received, please check API URL.';
};

let log = function(section, msg, options){
    if(options.debug){
        console.error([ '[', section, ']: ', msg ].join(''));
    }
};

let sanitizeData = function(data){
    let cleansed = {};
    _.each(data, function(val, field){
        cleansed[field] = _.contains(SANITIZE_FIELDS, field) ? '********' : val;
    });

    return cleansed;
};

let injectAuth = function(payload, headers, auth, options, callback){
    payload = payload || {};
    headers = headers || {};

    if(auth.token){
        log('api:injectAuth', 'getting refresh token', options);
        exports.refreshTokenToAccessToken(payload, auth.token, { }, function(err, data){
            if(err){
                return callback(err);
            }
            headers.Authorization = 'Bearer ' + data.accessToken;
            delete payload.token;
            delete payload.password;
            delete payload.userid;
            callback();
        });
    }
    else{
        let base64BasicCredentials = Buffer.from(payload.userid + ':' + auth.password).toString('base64');
        headers.Authorization = 'Basic ' + base64BasicCredentials;
        delete payload.token;
        delete payload.password;
        delete payload.userid;
        // console.error('\nWARNING: ALKS credential authentication is deprecated, please switch to two-factor authentication (alks developer login2fa).\n');
        callback();
    }
};

exports.getDurations = function(account, auth, opts, callback){
    if (arguments.length === 0) return [1]; // for legacy support

    let options = _.extend({
        debug: false,
        ua:    DEFAULT_UA
    }, opts);
    let headers = { 'User-Agent': options.ua };
    let accountId = account.alksAccount.substring(0,12);
    let endpoint = account.server + '/loginRoles/id/' + accountId + '/' + account.alksRole;
    let payload = _.extend({
        account: account.alksAccount,
        role: account.alksRole
    }, account);

    injectAuth(payload, headers, auth, options, function(err){
        if(err) return callback(err);

        log('api:getDurations', 'getting max key duration: ' + endpoint, options);

        request({
            url: endpoint,
            method: 'GET',
            headers: headers
        }, function(err, results) {
            if(err){
                return callback(err);
            }
            if(results.statusCode !== 200){
                return callback(new Error(getMessageFromBadResponse(results)));
            }

            let body = JSON.parse(results.body);

            if(body.statusMessage.toLowerCase() !== STATUS_SUCCESS){
                return callback(new Error(results.body.statusMessage));
            }

            let maxKeyDuration = Math.min(ALKS_MAX_DURATION, body.loginRole.maxKeyDuration);
            let durations = [];
            for(let i=1; i<=maxKeyDuration; i++) durations.push(i);
            callback(null, durations);
        });
    });
};

exports.createKey = function(account, auth, duration, opts, callback){
    let payload = _.extend({
        sessionTime: duration,
        account: account.alksAccount,
        role: account.alksRole
    }, account),
        options = _.extend({
            debug: false,
            ua:    DEFAULT_UA
    }, opts),
        endpoint = account.server + '/getKeys/',
        headers = { 'User-Agent': options.ua };

    injectAuth(payload, headers, auth, options, function(err){
        if(err) return callback(err);

        log('api:createKey', 'creating key at endpoint: ' + endpoint, options);
        log('api:createKey', 'with data: ' + JSON.stringify(sanitizeData(payload), null, 4), options);

        request({
            url: endpoint,
            method: 'POST',
            json: payload,
            headers: headers
        }, function(err, results){

            if(err){
                return callback(err);
            }
            else if(results.statusCode !== 200){
                return callback(new Error(getMessageFromBadResponse(results)));
            }
            else if(results.body.statusMessage.toLowerCase() !== STATUS_SUCCESS){
                return callback(new Error(results.body.statusMessage));
            }

            callback(null, {
                accessKey:    results.body.accessKey,
                secretKey:    results.body.secretKey,
                sessionToken: results.body.sessionToken,
                alksAccount:  account.alksAccount,
                alksRole:     account.alksRole,
                sessionTime:  payload.sessionTime,
                expires:      moment().add(payload.sessionTime, 'hours')
            }, account, auth);
        });
    });
};

exports.createIamKey = function(account, auth, duration, opts, callback){
    if(arguments.length < 5){ // for legacy calls to createIamKey
        callback = opts;
        opts = duration;
        duration = 1;
    }
    let payload = _.extend({
        sessionTime: duration,
        account: account.alksAccount,
        role: account.alksRole
    }, account),
        options = _.extend({
            debug: false,
            ua:    DEFAULT_UA
    }, opts),
        endpoint = account.server + '/getIAMKeys/',
        headers = { 'User-Agent': options.ua };

    injectAuth(payload, headers, auth, options, function(err){
        if(err) return callback(err);

        log('api:createIamKey', 'creating IAM key at endpoint: ' + endpoint, options);
        log('api:createIamKey', 'with data: ' + JSON.stringify(sanitizeData(payload), null, 4), options);

        request({
            url: endpoint,
            method: 'POST',
            json: payload,
            headers: headers
        }, function(err, results){
            if(err){
                return callback(err);
            }
            else if(results.statusCode !== 200){
                return callback(new Error(getMessageFromBadResponse(results)));
            }
            else if(results.body.statusMessage.toLowerCase() !== STATUS_SUCCESS){
                return callback(new Error(results.body.statusMessage));
            }

            callback(null, {
                accessKey:    results.body.accessKey,
                secretKey:    results.body.secretKey,
                sessionToken: results.body.sessionToken,
                alksAccount:  account.alksAccount,
                alksRole:     account.alksRole,
                sessionTime:  payload.sessionTime,
                expires:      moment().add(payload.sessionTime, 'hours')
            }, account, auth);
        });
    });
};

exports.createLongTermKey = function(account, auth, iamUserName, opts, callback){
    let payload = _.extend({
        account: account.alksAccount,
        role: account.alksRole,
        iamUserName: iamUserName
    }, account),
        options = _.extend({
            debug: false,
            ua:    DEFAULT_UA
    }, opts),
        endpoint = account.server + '/accessKeys/',
        headers = { 'User-Agent': options.ua };

    injectAuth(payload, headers, auth, options, function(err){
        if(err) return callback(err);

        log('api:createLongTermKey', 'creating key at endpoint: ' + endpoint, options);
        log('api:createLongTermKey', 'with data: ' + JSON.stringify(sanitizeData(payload), null, 4), options);

        request({
            url: endpoint,
            method: 'POST',
            json: payload,
            headers: headers
        }, function(err, results){
            if(err){
                log('api:createLongTermKey', 'error creating ltk: ' + endpoint, err);
                return callback(err);
            }
            else if(results.statusCode !== 200){
                log('api:createLongTermKey', 'error creating ltk: ' + results.body, opts);
                return callback(new Error(getMessageFromBadResponse(results)));
            }
            else if(results.body.statusMessage.toLowerCase() !== STATUS_SUCCESS){
                callback(new Error(results.body.statusMessage));
            }

            callback(null, {
                accessKey:    results.body.accessKey,
                secretKey:    results.body.secretKey,
                iamUserName:  results.body.iamUserName,
                iamUserArn:   results.body.iamUserArn,
                alksAccount:  account.alksAccount,
                alksRole:     account.alksRole
            }, account, auth);
        });
    });
};

exports.createIamRole = function(account, auth, roleName, roleType, includeDefaultPolicies, enableAlksAccess, opts, callback){
    let payload = _.extend({
        account: account.alksAccount,
        role: account.alksRole,
        roleName: roleName,
        roleType: roleType,
        includeDefaultPolicy: includeDefaultPolicies ? '1' : '0',
        enableAlksAccess: enableAlksAccess
    }, account),
        options = _.extend({
            debug: false,
            ua:    DEFAULT_UA
    }, opts),
        endpoint = account.server + '/createRole/',
        headers = { 'User-Agent': options.ua };

    injectAuth(payload, headers, auth, options, function(err){
        if(err) return callback(err);

        log('api:createIamRole', 'creating IAM role at endpoint: ' + endpoint, options);
        log('api:createIamRole', 'with data: ' + JSON.stringify(sanitizeData(payload), null, 4), options);

        request({
            url: endpoint,
            method: 'POST',
            json: payload,
            headers: headers
        }, function(err, results){
            if(err){
                return callback(err);
            }
            else if(results.statusCode !== 200){
                return callback(new Error(getMessageFromBadResponse(results)));
            }

            if(results.body.statusMessage.toLowerCase() === STATUS_SUCCESS){
                callback(null, results.body);
            }
            else{
                if(results.body.errors && results.body.errors.length){
                    callback(new Error(results.body.errors[0]), null);
                }
                else{
                    callback(new Error(results.body.statusMessage), null);
                }
            }
        });
    });
};

exports.createIamTrustRole = function(account, auth, roleName, roleType, trustArn, enableAlksAccess, opts, callback){
    let payload = _.extend({
        account: account.alksAccount,
        role: account.alksRole,
        roleName: roleName,
        roleType: roleType,
        trustArn: trustArn,
        enableAlksAccess: enableAlksAccess
    }, account),
        options = _.extend({
            debug: false,
            ua:    DEFAULT_UA
    }, opts),
        endpoint = account.server + '/createNonServiceRole/',
        headers = { 'User-Agent': options.ua };

    injectAuth(payload, headers, auth, options, function(err){
        if(err) return callback(err);

        log('api:createIamTrustRole', 'creating IAM trust role at endpoint: ' + endpoint, options);
        log('api:createIamTrustRole', 'with data: ' + JSON.stringify(sanitizeData(payload), null, 4), options);

        request({
            url: endpoint,
            method: 'POST',
            json: payload,
            headers: headers
        }, function(err, results){
            if(err){
                return callback(err);
            }
            else if(results.statusCode !== 200){
                return callback(new Error(getMessageFromBadResponse(results)));
            }

            if(results.body.statusMessage.toLowerCase() === STATUS_SUCCESS){
                callback(null, results.body);
            }
            else{
                if(results.body.errors && results.body.errors.length){
                    callback(new Error(results.body.errors[0]), null);
                }
                else{
                    callback(new Error(results.body.statusMessage), null);
                }
            }
        });
    });
};

exports.getAccounts = function(server, userid, auth, opts, callback){
    let payload = { userid: userid, server: server },
        options = _.extend({
        debug: false,
        ua: DEFAULT_UA
    }, opts),
        endpoint = server + '/getAccounts/',
        headers = { 'User-Agent': options.ua };

    injectAuth(payload, headers, auth, options, function(err){
        if(err) return callback(err);

        log('api:getAccounts', 'getting accounts at endpoint: ' + endpoint, options);
        log('api:getAccounts', 'with data: ' + JSON.stringify(sanitizeData(payload), null, 4), options);

        request({
            url: endpoint,
            method: 'POST',
            json: payload,
            headers: headers
        }, function(err, results){
            if(err){
                return callback(err);
            }
            else if(results.statusCode !== 200){
                return callback(new Error(getMessageFromBadResponse(results)));
            }

            let accounts = [];

            _.each(results.body.accountListRole, function(role, acct){
                accounts.push({
                    account: acct,
                    role: role[0].role,
                    iam: role[0].iamKeyActive
                });
            });

            accounts = _.sortBy(accounts, function(account){ return account.account; });

            callback(null, accounts);
        });
    });
};

exports.getIamRoleTypes = function(server, userid, auth, opts, callback){
    let payload = { userid: userid, server: server },
        options = _.extend({
        debug: false,
        ua: DEFAULT_UA
    }, opts),
        endpoint = server + '/getAWSRoleTypes/',
        headers = { 'User-Agent': options.ua };

    injectAuth(payload, headers, auth, options, function(err){
        if(err) return callback(err);

        log('api:getIamRoleTypes', 'getting role types at endpoint: ' + endpoint, options);
        log('api:getIamRoleTypes', 'with data: ' + JSON.stringify(sanitizeData(payload), null, 4), options);

        request({
            url: endpoint,
            method: 'POST',
            json: payload,
            headers: headers
        }, function(err, results){
            if(err){
                return callback(err);
            }
            else if(results.statusCode !== 200){
                return callback(new Error(getMessageFromBadResponse(results)));
            }

            callback(null, JSON.parse(results.body.roleTypes));
        });
    });
};

exports.generateConsoleUrl = function(key, opts, callback){
    let payload = {
        sessionId:   key.accessKey,
        sessionKey:  key.secretKey,
        sessionToken: key.sessionToken
    },
        options = _.extend({
            debug: false,
            ua:    DEFAULT_UA
    }, opts);

    let urlParms = '?Action=getSigninToken&SessionType=json&Session=' + encodeURIComponent(JSON.stringify(payload)),
        endpoint = AWS_SIGNIN_URL + urlParms;

    log('api:generateConsoleUrl', 'generating console url at endpoint: ' + endpoint, options);
    log('api:generateConsoleUrl', 'with data: ' + JSON.stringify(sanitizeData(payload), null, 4), options);
    log('ua', options.ua, options)
    request({
        url: endpoint,
        method: 'GET',
        headers: {
            'User-Agent': options.ua
        }
    }, function(err, results){
        if(err){
            return callback(err);
        }
        else if(results.statusCode !== 200){
            return callback(new Error(results.body));
        }
        else{
            let returnedData = JSON.parse(results.body);

            if(!_.isEmpty(returnedData.SigninToken)){
                let consoleUrl = [
                    AWS_SIGNIN_URL,
                    '?Action=login',
                    '&Destination=',
                    encodeURIComponent(AWS_CONSOLE_URL),
                    '&SigninToken=',
                    encodeURIComponent(returnedData.SigninToken)
                ].join('');

                return callback(null, consoleUrl)
            }
            else{
                console.log(results.body)
                return callback(new Error('AWS didnt return signin token!'));
            }
        }
    });
};

exports.deleteIamRole = function(account, auth, roleName, opts, callback){
    let payload = _.extend({
        account: account.alksAccount,
        role: account.alksRole,
        roleName: roleName
    }, account),
        options = _.extend({
            debug: false,
            ua:    DEFAULT_UA
    }, opts),
        endpoint = account.server + '/deleteRole/',
        headers = { 'User-Agent': options.ua };

    injectAuth(payload, headers, auth, options, function(err){
        if(err) return callback(err);

        log('api:deleteIamRole', 'deleting IAM role at endpoint: ' + endpoint, options);
        log('api:deleteIamRole', 'with data: ' + JSON.stringify(sanitizeData(payload), null, 4), options);

        request({
            url: endpoint,
            method: 'POST',
            json: payload,
            headers: headers
        }, function(err, results){
            if(err){
                return callback(err);
            }
            else if(results.statusCode !== 200){
                return callback(new Error(getMessageFromBadResponse(results)));
            }

            if(results.body.errors && results.body.errors.length){
                callback(new Error(results.body.errors[0]), null);
            }
            else{
                callback(null, results.body);
            }
        });
    });
};

exports.deleteLongTermKey = function(account, auth, iamUserName, opts, callback){
    let payload = _.extend({
        account: account.alksAccount,
        role: account.alksRole,
        iamUserName: iamUserName
    }, account),
        options = _.extend({
            debug: false,
            ua:    DEFAULT_UA
    }, opts),
        endpoint = account.server + '/IAMUser/',
        headers = { 'User-Agent': options.ua };

    injectAuth(payload, headers, auth, options, function(err){
        if(err) return callback(err);

        log('api:deleteLongTermKey', 'creating key at endpoint: ' + endpoint, options);
        log('api:deleteLongTermKey', 'with data: ' + JSON.stringify(sanitizeData(payload), null, 4), options);

        request({
            url: endpoint,
            method: 'DELETE',
            json: payload,
            headers: headers
        }, function(err, results){
            if(err){
                return callback(err);
            }
            else if(results.statusCode !== 200){
                log('api:deleteLongTermKey', 'received bad response: ' + endpoint, results.body);

                if(results.body.errors && results.body.errors.length){
                    return callback(new Error(results.body.errors[0]), null);
                }
                else{
                    return callback(new Error(results.body.statusMessage));
                }
            }

            callback(null, results.body);
        });
    });
};

exports.refreshTokenToAccessToken = function(account, token, opts, callback){
    let payload = _.extend({
        account: account.alksAccount,
        refreshToken: token
    }, account),
        options = _.extend({
            debug: false,
            ua:    DEFAULT_UA
    }, opts),
        endpoint = account.server + '/accessToken/';

    log('api:refreshTokenToAccessToken', 'exchanging refresh token for access token at endpoint: ' + endpoint, options);
    log('api:refreshTokenToAccessToken', 'with data: ' + JSON.stringify(sanitizeData(payload), null, 4), options);

    request({
        url: endpoint,
        method: 'POST',
        json: payload,
        headers: {
            'User-Agent': options.ua
        }
    }, function(err, results){
        if(err){
            return callback(err);
        }
        else if(results.statusCode !== 200){
            return callback(new Error(getMessageFromBadResponse(results)));
        }

        if(results.body.errors && results.body.errors.length){
            callback(new Error(results.body.errors[0]), null);
        }
        else{
            callback(null, results.body);
        }
    });
};
