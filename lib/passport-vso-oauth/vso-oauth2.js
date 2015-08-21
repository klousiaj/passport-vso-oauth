var util = require('util'),
  querystring = require('querystring'),
  OAuth2 = require('oauth').OAuth2;

function VsoOAuth2(clientId, clientSecret, baseSite, authorizePath, accessTokenPath, customHeaders) {
  this._clientId = clientId;
  this._clientSecret = clientSecret;
  this._baseSite = baseSite;
  this._authorizeUrl = authorizePath || "/oauth/authorize";
  this._accessTokenUrl = accessTokenPath || "/oauth/access_token";
  this._accessTokenName = "access_token";
  this._authMethod = "Bearer";
  this._customHeaders = customHeaders || {};
  this._useAuthorizationHeaderForGET = true;
}

util.inherits(VsoOAuth2, OAuth2);

OAuth2.prototype.getOAuthAccessToken = function (code, params, callback) {
  var params = params || {};
  params['client_assertion'] = this._clientSecret;
  params['assertion'] = code;

  var post_data = querystring.stringify(params);
  var post_headers = {
    'Content-Type': 'application/x-www-form-urlencoded'
  };

  this._request("POST",
    this._getAccessTokenUrl(),
    post_headers,
    post_data,
    null,
    function (error, data, response) {
      if (error) {
        callback(error);
      } else {
        var results = JSON.parse(data);
        var access_token = results["access_token"];
        var refresh_token = results["refresh_token"];
        delete results["refresh_token"];
        callback(null, access_token, refresh_token, results); // callback results =-=
      }
    });
}

/**
 * Expose `VsoOAuth2`.
 */
module.exports = VsoOAuth2;