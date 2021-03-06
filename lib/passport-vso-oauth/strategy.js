/**
 * Module dependencies.
 */
var util = require('util');
var utils = require('utils');
var uri = require('url');
var uid = require('uid2');
var OAuth2Strategy = require('passport-oauth').OAuth2Strategy;
var InternalOAuthError = require('passport-oauth').InternalOAuthError;
var AuthorizationError = require('passport-oauth').AuthorizationError;
var Profile = require('./profile');
var VsoOAuth2 = require('node-oauth2-vso').VsoOAuth2;

var DEPRECATED_SCOPES = {};

/**
 * `Strategy` constructor.
 *
 * The VSOs authentication strategy authenticates requests by delegating to
 * VSOs using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken`, and then calls the `done` callback, which should be set to 
 * `false` if the credentials are not valid.  If an exception occured, `err` 
 * should be set.
 *
 * Options:
 *   - `clientID`      your VSO application's client id
 *   - `clientSecret`  your VSO application's client secret
 *   - `callbackURL`   URL to which VSO will redirect the user after granting authorization
 *
 * Examples:
 *
 *     passport.use(new VsoStrategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/vso/callback'
 *       },
 *       function(accessToken, refreshToken, done) {
 *         done(err, user);
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  options = options || {};
  options.authorizationURL = options.authorizationURL || 'https://app.vssps.visualstudio.com/oauth2/authorize';
  options.tokenURL = options.tokenURL || 'https://app.vssps.visualstudio.com/oauth2/token';

  OAuth2Strategy.call(this, options, verify);
  this.name = 'vso';
  this._profileURL = options.profileURL || 'https://app.vssps.visualstudio.com/_apis/profile/profiles/me?api-version=1.0';
  this._key = options.sessionKey;
  this._passReqToCallback = options.passReqToCallback || false;
  this._state = true;
  this._oauth2 = new VsoOAuth2(options.clientID, options.clientSecret,
    '', options.authorizationURL, options.tokenURL, options.customHeaders);
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);


OAuth2Strategy.prototype.authenticate = function (req, options) {
  options = options || {};
  var self = this;
  
  if (req.query && req.query.error) {
    if (req.query.error == 'access_denied') {
      return this.fail({ message: req.query.error_description });
    } else {
      return this.error(new AuthorizationError(req.query.error_description, req.query.error, req.query.error_uri));
    }
  }

  var callbackURL = options.callbackURL || this._callbackURL;
  if (callbackURL) {
    var parsed = uri.parse(callbackURL);
    if (!parsed.protocol) {
      // The callback URL is relative, resolve a fully qualified URL from the
      // URL of the originating request.
      callbackURL = uri.resolve(utils.originalURL(req, { proxy: this._trustProxy }), callbackURL);
    }
  }

  if (req.query && req.query.code) {
    var code = req.query.code;

    if (this._state) {
      if (!req.session) { return this.error(new Error('OAuth2Strategy requires session support when using state. Did you forget app.use(express.session(...))?')); }

      var key = this._key;
      if (!req.session[key]) {
        return this.fail({ message: 'Unable to verify authorization request state.' }, 403);
      }
      var state = req.session[key].state;
      if (!state) {
        return this.fail({ message: 'Unable to verify authorization request state.' }, 403);
      }

      delete req.session[key].state;
      if (Object.keys(req.session[key]).length === 0) {
        delete req.session[key];
      }

      if (state !== req.query.state) {
        return this.fail({ message: 'Invalid authorization request state.' }, 403);
      }
    }

    var params = this.tokenParams(options);
    params.redirect_uri = callbackURL;

    this._oauth2.getOAuthAccessToken(code, params,
      function (err, accessToken, refreshToken, params) {
        if (err) { return self.error(self._createOAuthError('Failed to obtain access token', err)); }

        self._loadUserProfile(accessToken, function (err, profile) {
          if (err) { return self.error(err); }

          function verified(err, user, info) {
            if (err) { return self.error(err); }
            if (!user) { return self.fail(info); }
            self.success(user, info);
          }

          try {
            if (self._passReqToCallback) {
              var arity = self._verify.length;
              if (arity == 6) {
                self._verify(req, accessToken, refreshToken, params, profile, verified);
              } else { // arity == 5
                self._verify(req, accessToken, refreshToken, profile, verified);
              }
            } else {
              var arity = self._verify.length;
              if (arity == 5) {
                self._verify(accessToken, refreshToken, params, profile, verified);
              } else { // arity == 4
                self._verify(accessToken, refreshToken, profile, verified);
              }
            }
          } catch (ex) {
            return self.error(ex);
          }
        });
      }
      );
  } else {
    var params = this.authorizationParams(options);
    params.redirect_uri = callbackURL;
    var scope = options.scope || this._scope;
    if (scope) {
      if (Array.isArray(scope)) { scope = scope.join(this._scopeSeparator); }
      params.scope = scope;
    }
    var state = options.state;
    if (state) {
      params.state = state;
    } else if (this._state) {
      if (!req.session) { return this.error(new Error('OAuth2Strategy requires session support when using state. Did you forget app.use(express.session(...))?')); }

      var key = this._key;
      state = uid(24);
      if (!req.session[key]) { req.session[key] = {}; }
      req.session[key].state = state;
      params.state = state;
    }

    var location = this._oauth2.getAuthorizeUrl(params);
    this.redirect(location);
  }
};

// get the user profile from the appropriate endpoint 
OAuth2Strategy.prototype.userProfile = function(accessToken, done) {
  var url = uri.parse(this._profileURL);
  if (this._profileFields) {
    var fields = this._convertProfileFields(this._profileFields);
    if (fields !== '') { url.search = (url.search ? url.search + '&' : '') + 'fields=' + fields; }
  }
  url = uri.format(url);

  this._oauth2.get(url, accessToken, function (err, body, res) {
    var json;
    
    if (err) {
      if (err.data) {
        try {
          json = JSON.parse(err.data);
        } catch (_) {}
      }
      
      if (json && json.error && typeof json.error == 'object') {
        return done(new InternalOAuthError(json.error.message, json.error.type, json.error.code, json.error.error_subcode));
      }
      return done(new InternalOAuthError('Failed to fetch user profile', err));
    }
    
    try {
      json = JSON.parse(body);
    } catch (ex) {
      return done(new Error('Failed to parse user profile'));
    }

    var profile = Profile.parse(json);
    profile.provider = 'vso';
    profile._raw = body;
    profile._json = json;

    done(null, profile);
  });
};

OAuth2Strategy.prototype.authorizationParams = function (options) {
  var params = {};
  params['response_type'] = 'Assertion';
  return params;
}

/**
 * Override to provide the specific token parameters required by the
 * VSO AccessToken call.
 */
OAuth2Strategy.prototype.tokenParams = function (options) {
  var params = {};
  params['grant_type'] = 'urn:ietf:params:oauth:grant-type:jwt-bearer';
  return params;
};

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;