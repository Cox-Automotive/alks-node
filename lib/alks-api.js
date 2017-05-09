/*jslint node: true */
'use strict';

var _       = require('underscore'),
    request = require('request'),
    moment  = require('moment');

var exports = module.exports = {};

var ALKS_DURATIONS  = [ 2, 6, 12, 18 ], // reducing due to EB not honoring long sessions: , 24, 36 ],
    AWS_SIGNIN_URL  = 'https://signin.aws.amazon.com/federation',
    AWS_CONSOLE_URL = 'https://console.aws.amazon.com/',
    SANITIZE_FIELDS = [ 'password' ],
    DEFAULT_UA      = 'alks-node',
    STATUS_SUCCESS  = 'success'

exports.getDurations = function(){
    return ALKS_DURATIONS;
};

var getMessageFromBadResponse = function(results){
    if(results.body){
        if(results.body.statusMessage){
            return results.body.statusMessage;
        }
    }

    return 'Bad response received, please check API URL.';
};

var log = function(section, msg, options){
    if(options.debug){
        console.error([ '[', section, ']: ', msg ].join(''));
    }
}

var sanitizeData = function(data){
    var cleansed = {};
    _.each(data, function(val, field){
        cleansed[field] = _.contains(SANITIZE_FIELDS, field) ? '********' : val;
    });

    return cleansed;
}

exports.createKey = function(account, password, duration, opts, callback){
    var payload = _.extend({
        password: password,
        sessionTime: duration,
        account: account.alksAccount,
        role: account.alksRole
    }, account),
        options = _.extend({
            debug: false,
            ua:    DEFAULT_UA
    }, opts),
        endpoint = account.server + '/getKeys/';

    log('api:createKey', 'creating key at endpoint: ' + endpoint, options);
    log('api:createKey', 'with data: ' + JSON.stringify(sanitizeData(payload), null, 4), options);

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
        }, account, password);
    });
};

exports.createIamKey = function(account, password, opts, callback){
    var payload = _.extend({
        password: password,
        sessionTime: 1,
        account: account.alksAccount,
        role: account.alksRole
    }, account),
        options = _.extend({
            debug: false,
            ua:    DEFAULT_UA
    }, opts),
        endpoint = account.server + '/getIAMKeys/';

    log('api:createIamKey', 'creating IAM key at endpoint: ' + endpoint, options);
    log('api:createIamKey', 'with data: ' + JSON.stringify(sanitizeData(payload), null, 4), options);

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
        }, account, password);
    });
};

exports.createIamRole = function(account, password, roleName, roleType, includeDefaultPolicies, opts, callback){
    var payload = _.extend({
        password: password,
        account: account.alksAccount,
        role: account.alksRole,
        roleName: roleName,
        roleType: roleType,
        includeDefaultPolicy: includeDefaultPolicies ? '1' : '0'
    }, account),
        options = _.extend({
            debug: false,
            ua:    DEFAULT_UA
    }, opts),
        endpoint = account.server + '/createRole/';

    log('api:createIamRole', 'creating IAM role at endpoint: ' + endpoint, options);
    log('api:createIamRole', 'with data: ' + JSON.stringify(sanitizeData(payload), null, 4), options);

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

        if(results.body.statusMessage.toLowerCase() === STATUS_SUCCESS){
            callback(null, results.body );
        }
        else{
            callback(new Error(results.body.statusMessage), null);
        }
    });
};

exports.getAccounts = function(server, userid, password, opts, callback){
    var payload = { userid: userid, password: password },
        options = _.extend({
        debug: false,
        ua: DEFAULT_UA
    }, opts),
        endpoint = server + '/getAccounts/';

    log('api:getAccounts', 'getting accounts at endpoint: ' + endpoint, options);
    log('api:getAccounts', 'with data: ' + JSON.stringify(sanitizeData(payload), null, 4), options);

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

        var accounts = [];

        // new API style to support IAM
        if(results.body.accountListRole){
            var accounts = [];

            _.each(results.body.accountListRole, function(role, acct){
                accounts.push({
                    account: acct,
                    role: role[0].role,
                    iam: role[0].iamKeyActive
                });
            });
        }
        // v1 API style without IAM
        else{
            _.each(results.body.accountRoles, function(role, acct){
                accounts.push({
                    account: acct,
                    role: role[0],
                    iam: false
                });
            });
        }

        accounts = _.sortBy(accounts, function(account){ return account.account; });

        callback(null, accounts);
    });
};

exports.getIamRoleTypes = function(server, userid, password, opts, callback){
    var payload = { userid: userid, password: password },
        options = _.extend({
        debug: false,
        ua: DEFAULT_UA
    }, opts),
        endpoint = server + '/getAWSRoleTypes/';

    log('api:getIamRoleTypes', 'getting role types at endpoint: ' + endpoint, options);
    log('api:getIamRoleTypes', 'with data: ' + JSON.stringify(sanitizeData(payload), null, 4), options);

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

        callback(null, JSON.parse(results.body.roleTypes));
    });
};

exports.generateConsoleUrl = function(key, opts, callback){
    var payload = {
        sessionId:   key.accessKey,
        sessionKey:  key.secretKey,
        sessionToken: key.sessionToken
    },
        options = _.extend({
            debug: false,
            ua:    DEFAULT_UA
    }, opts);

    var urlParms = '?Action=getSigninToken&SessionType=json&Session=' + encodeURIComponent(JSON.stringify(payload)),
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
            var returnedData = JSON.parse(results.body);

            if(!_.isEmpty(returnedData.SigninToken)){
                var consoleUrl = [
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

exports.deleteIamRole = function(account, password, roleName, opts, callback){
    var payload = _.extend({
        password: password,
        account: account.alksAccount,
        role: account.alksRole,
        roleName: roleName
    }, account),
        options = _.extend({
            debug: false,
            ua:    DEFAULT_UA
    }, opts),
        endpoint = account.server + '/deleteRole/';

    log('api:deleteIamRole', 'deleting IAM role at endpoint: ' + endpoint, options);
    log('api:deleteIamRole', 'with data: ' + JSON.stringify(sanitizeData(payload), null, 4), options);

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
