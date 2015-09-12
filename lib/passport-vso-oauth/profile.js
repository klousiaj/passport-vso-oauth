/**
 * Parse profile.
 *
 * @param {Object|String} json
 * @return {Object}
 * @api private
 */
exports.parse = function(json) {
  if ('string' == typeof json) {
    json = JSON.parse(json);
  }
  
  var profile = {};
  profile.id = json.id;
  profile.displayName = json.displayName;
  profile.emailAddress = json.emailAddress;
  profile.timeStamp = json.timeStamp;
  
  return profile;
};