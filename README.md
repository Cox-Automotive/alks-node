#ALKS Node Client

[![NPM](https://nodei.co/npm/alks-node.png?downloads=true&downloadRank=true&stars=true)](https://nodei.co/npm/alks-node/)

[![Build Status](https://travis-ci.org/Cox-Automotive/alks-node.svg?branch=master)](https://travis-ci.org/Cox-Automotive/alks-node)

## About
Node client for interfacting with the [ALKS](https://github.com/Cox-Automotive/ALKS) services.

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

### getAccountSelectorDelimiter()

Returns string dilimeter used for account/role seperation.

```js
alks.getAccountSelectorDelimiter();
```

## Methods

### createKey(account, password, duration, callback)

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

Returns a collection of accounts. Options filter allows you to switch between IAM and non-IAM accounts.

```js
alks.getAccounts('server', 'username', 'password', {filters: { iamOnly: false }}, function(err, accounts){
    if(err) console.error(err);
    else console.log(JSON.stringify(accounts));
});
```

### generateConsoleUrl(key, callback)

Returns a AWS console URL for a given key. The URL is good for 15 minutes.

```js
alks.generateConsoleUrl(alksKey, function(err, url){
    if(err) console.error(err);
    else console.log('The console URL is: %s', url);
});
```

### getIamRoleTypes(server, userid, password, callback)

### createIamKey(account, password, callback)

### createIamRole(account, password, roleName, roleType, includeDefaultPolicies, callback)