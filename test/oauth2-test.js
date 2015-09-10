var vows = require('vows');
var assert = require('assert');
var util = require('util');
var VsoStrategy = require('node-oauth2-vso');


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
      assert.equal(strategy.name, 'vso');
    },
  }
  
}).export(module);