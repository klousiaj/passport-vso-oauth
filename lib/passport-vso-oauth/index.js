/**
 * Module dependencies.
 */
var OAuth2Strategy = require('./strategy');


/**
 * Framework version.
 */
require('pkginfo')(module, 'version');

/**
 * Expose constructors.
 */
exports.Strategy =
exports.OAuth2Strategy = OAuth2Strategy;