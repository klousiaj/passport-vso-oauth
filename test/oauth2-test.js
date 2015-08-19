var vows = require('vows');
var assert = require('assert');
var util = require('util');
var VsoStrategy = require('passport-vso-oauth/oauth2');


vows.describe('VsoStrategy').addBatch({
  
  'strategy': {
    topic: function() {
      return new VsoStrategy({
        clientID: 'ABC123',
        clientSecret: 'secret'
      },
      function() {});
    },
    
    'should be named vso': function (strategy) {
      console.log(strategy);
      assert.equal(strategy.name, 'vso');
    },
  }
  
}).export(module);