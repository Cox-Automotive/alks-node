#ALKS Node Client

[![NPM](https://nodei.co/npm/alks-node.png?downloads=true&downloadRank=true&stars=true)](https://nodei.co/npm/alks-node/)

[![Build Status](https://travis-ci.org/Cox-Automotive/alks-node.svg?branch=master)](https://travis-ci.org/Cox-Automotive/alks-node)

## About
Node client for interfacting with ALKS services.

## Usage

```js
var alks = require('alks-node');
```

## Utilities

### getDurations()

Returns array of valid session durations.

```js
alks.getDurations();
```

## Methods

### createKey(account, password, duration, options, callback)

Creates a new session key with the provided information. Returns a JSON document.

```js
var data = {
    alksAccount: 'alksAccount',
    alksRole: 'alksRole',
    sessionTime: 2,
    server: 'endpoint',
    userid: 'my-network-id',
    password: 'my-network-password'
};

alks.createKey(data, 'password', 2, function(err, key){
    if(err) console.error(err);
    else console.log(JSON.stringify(key));
});
```

### getAccounts(server, userid, password, options, callback)

Returns a collection of accounts.

```js
alks.getAccounts('server', 'username', 'password', {}, function(err, accounts){
    if(err) console.error(err);
    else console.log(JSON.stringify(accounts));
});
```

### generateConsoleUrl(key, options, callback)

Returns a AWS console URL for a given key. The URL is good for 15 minutes.

```js
alks.generateConsoleUrl(alksKey, function(err, url){
    if(err) console.error(err);
    else console.log('The console URL is: %s', url);
});
```

### getIamRoleTypes(server, userid, password, options, callback)

Returns a list of current IAM role types.

### createIamKey(account, password, options, callback)

Generates a new session for use in creating IAM roles and console sessions.

### createIamRole(account, password, roleName, roleType, includeDefaultPolicies, options, callback)

Creates a new IAM role, provided account must contain valid ALKS IAM session.