/*jslint node: true */
'use strict';

var _       = require('underscore'),
    request = require('request'),
    moment  = require('moment');

var exports = module.exports = {};

var ALKS_DURATIONS               = [ 2, 6, 12, 18 ], // reducing due to EB not honoring long sessions: , 24, 36 ],
    ACCOUNT_SELECTION_DELIMITER  = ' :: ',
    AWS_SIGNIN_URL               = 'https://signin.aws.amazon.com/federation',
    AWS_CONSOLE_URL              = 'https://console.aws.amazon.com/';

exports.getDurations = function(){
    return ALKS_DURATIONS;
};

exports.getAccountSelectorDelimiter = function(){
    return ACCOUNT_SELECTION_DELIMITER;
};

var getMessageFromBadResponse = function(results){
    if(results.body){
        if(results.body.statusMessage){
            return results.body.statusMessage;
        }
    }

    return 'Bad response received, please check API URL.';
};

exports.createKey = function(account, password, duration, callback){
    var payload = _.extend({
        password: password,
        sessionTime: duration,
        account: account.alksAccount,
        role: account.alksRole
    }, account);

    request({
        url: account.server + '/getKeys/',
        method: 'POST',
        json: payload
    }, function(err, results){
        if(err){
            return callback(err);
        }
        else if(results.statusCode !== 200){
            return callback(new Error(getMessageFromBadResponse(results)));
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

exports.createIamKey = function(account, password, callback){
    var payload = _.extend({
        password: password,
        sessionTime: 1,
        account: account.alksAccount,
        role: account.alksRole
    }, account);

    request({
        url: account.server + '/getIAMKeys/',
        method: 'POST',
        json: payload
    }, function(err, results){
        if(err){
            return callback(err);
        }
        else if(results.statusCode !== 200){
            return callback(new Error(getMessageFromBadResponse(results)));
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

exports.createIamRole = function(account, password, roleName, roleType, includeDefaultPolicies, callback){
    var payload = _.extend({
        password: password,
        account: account.alksAccount,
        role: account.alksRole,
        roleName: roleName,
        roleType: roleType,
        includeDefaultPolicy: includeDefaultPolicies ? '1' : '0'
    }, account);

    request({
        url: account.server + '/createRole/',
        method: 'POST',
        json: payload
    }, function(err, results){
        if(err){
            return callback(err);
        }
        else if(results.statusCode !== 200){
            return callback(new Error(getMessageFromBadResponse(results)));
        }

        if(results.body.statusMessage === 'Success'){
            callback(null, results.body );
        }
        else{
            callback(new Error(results.body.statusMessage), null);
        }
    });
};

exports.getAccounts = function(server, userid, password, options, callback){
    var opts = _.extend({
        filters: {}
    }, options);

    request({
        url: server + '/getAccounts/',
        method: 'POST',
        json: { userid: userid, password: password }
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
            var accountRolesFitlered = {};
            _.each(results.body.accountListRole, function(role, acct){
                if((opts.filters.iamOnly && !role[0].iamKeyActive)
                 || (!opts.filters.iamOnly && role[0].iamKeyActive)){
                    return;
                }
                accountRolesFitlered[acct] = role;
            });

            var accounts = [];
            _.each(accountRolesFitlered, function(role, acct){
                accounts.push([acct, role[0].role].join(ACCOUNT_SELECTION_DELIMITER));
            });
        }
        // v1 API style without IAM
        else{
            _.each(results.body.accountRoles, function(role, acct){
                accounts.push([acct, role[0]].join(ACCOUNT_SELECTION_DELIMITER));
            });
        }

        accounts = _.sortBy(accounts, function(account){ return account; });

        callback(null, accounts);
    });
};

exports.getIamRoleTypes = function(server, userid, password, callback){
    request({
        url: server + '/getAWSRoleTypes/',
        method: 'POST',
        json: { userid: userid, password: password }
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

exports.generateConsoleUrl = function(key, callback){
    var payload = {
        sessionId:   key.accessKey,
        sessionKey:  key.secretKey,
        sessionToken: key.sessionToken
    };

    var urlParms = '?Action=getSigninToken&SessionType=json&Session=' + encodeURIComponent(JSON.stringify(payload));

    request({
        url: AWS_SIGNIN_URL + urlParms,
        method: 'GET'
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