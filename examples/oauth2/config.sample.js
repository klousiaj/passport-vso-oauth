var config = {};

config.vso = {};

config.vso.clientId = process.env.CLIENT_ID || '--invalid-client-id--';
config.vso.clientSecret = process.env.CLIENT_SECRET || '--invalid-client-secret--';
config.vso.callbackUrl = process.env.CALLBACK_URL || 'http://localhost:3000/callback';
config.vso.scopeList = ['vso.code'];

module.exports = config;