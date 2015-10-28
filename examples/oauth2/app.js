var express = require('express');
var morgan = require('morgan');
var bodyParser = require('body-parser');
var cookieParser = require('cookie-parser');
var methodOverride = require('method-override');
var uuid = require('uuid');
var ejsMate = require('ejs-mate');
var session = require('express-session');
var passport = require('passport');
var util = require('util');
var request = require('request');
var fs = require('fs');

var config;
try {
  config = require('./config.js')
} catch (ex) {
  config = {
    vso: {
      clientId: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackUrl: process.env.CALLBACK_URL,
      scopeList: process.env.SCOPE_LIST,
      cookieSecret: process.env.COOKIE_SECRET,
      // if it isn't configured in the config.js then don't use it.
      useHttps: false
    }
  }
}

var VsoStrategy;
try {
  // this is for local work with the entire tree
  VsoStrategy = require('../../lib/passport-vso-oauth/index').OAuth2Strategy;
} catch (ex) {
  // this is for deployment to a remote server where I've only deployed a git subtree and the module
  // isn't on a relative path.
  VsoStrategy = require('passport-vso-oauth').OAuth2Strategy;
}

var strategy = new VsoStrategy({
  clientID: config.vso.clientId,
  clientSecret: config.vso.clientSecret,
  callbackURL: config.vso.callbackUrl,
  scope: config.vso.scopeList,
  passReqToCallback: true
},
  function (req, accessToken, refreshToken, params, profile, done) {
    // asynchronous verification, for effect...
    process.nextTick(function () {
      req.session.token = {};
      req.session.token.accessToken = accessToken;
      req.session.token.refreshToken = refreshToken;
      req.session.token.expiresIn = params['expires_in'];
      return done(null, profile);
    });
  });
  
// Use the VsoStrategy within Passport and passport refresh.
passport.use(strategy);
var app = express();

app.engine('ejs', ejsMate);
// configure Express
app.set('views', __dirname + '/views');
app.set('view engine', 'ejs');
app.use(morgan('dev'));
app.use(cookieParser(config.vso.cookieSecret));
app.use(bodyParser.urlencoded());
app.use(bodyParser.json());
app.use(methodOverride());
app.use(session({
  genid: function (req) {
    return uuid.v1() // use UUIDs for session IDs
  },
  secret: 'ovechtrick'
}));

// Initialize Passport!  Also use passport.session() middleware, to support
// persistent login sessions (recommended).
app.use(passport.initialize());
app.use(passport.session());
app.use(express.static(__dirname + '/public'));

// Passport session setup.
//   To support persistent login sessions, Passport needs to be able to
//   serialize users into and deserialize users out of the session.  Typically,
//   this will be as simple as storing the user ID when serializing, and finding
//   the user by ID when deserializing.  
passport.serializeUser(function (user, done) {
  done(null, user);
});

passport.deserializeUser(function (obj, done) {
  done(null, obj);
});

// before everything, we should be checking to see if there is already a token
// and then use that token to populate the users identity. 
// app.all('/*', loadToken, fetchIdentity);

app.get('/', function (req, res) {
  res.render('index', { user: req.user });
});

app.get('/profile', ensureAuthenticated, function (req, res) {
  res.render('profile', {
    user: req.user,
    access_token: req.session.token.accessToken,
    refresh_token: req.session.token.refreshToken,
    expires_in: req.session.token.expiresIn,
    accounts: req.user.accounts
  });
});

app.get('/login', function (req, res) {
  res.render('login', { user: req.user });
});

// GET /auth/vso
//   Use passport.authenticate() as route middleware to authenticate the
//   request.  The first step in Vso authentication will involve
//   redirecting the user to Vso.com.  After authorization, vso
//   will redirect the user back to this application at /auth/vso/callback
app.get('/auth/vso',
  passport.authenticate('vso',
    {
      scope: config.vso.scopeList,
      sessionKey: 'connect.id'
    }),
  function (req, res) {
    // The request will be redirected to Vso for authentication, so this
    // function will not be called.
  });

// GET /auth/vso/callback
//   Use passport.authenticate() as route middleware to authenticate the
//   request.  If authentication fails, the user will be redirected back to the
//   login page.  Otherwise, the primary route function will be called,
//   which, in this example, will redirect the user to the home page.
app.get('/auth/vso/callback',
  passport.authenticate('vso', { failureRedirect: '/login' }),
  function (req, res) {
    // // write out a cookie that holds the refresh token.
    // res.cookie('do6.id', req.token, {
    //   secure: true,
    //   httpOnly: true,
    //   signed: true,
    //   maxAge: 1209600000 // 14 days
    // });
    res.redirect('/');
  });

app.get('/logout', function (req, res) {
  req.logout();
  res.redirect('/');
});

app.get('/refresh', ensureAuthenticated, function (req, res) {

  var params = { grant_type: 'refresh_token', redirect_uri: config.vso.callbackUrl };
  /*refresh.requestNewAccessToken('vso', req.session.token.refreshToken, params, function (err, accessToken, refreshToken) {
    req.session.token.accessToken = accessToken;
    req.session.token.refreshToken = refreshToken;
    if (err) {
      throw new Error('Unable to refresh the access token: ' + err.data);
    }
    res.render('profile', {
      user: req.user,
      access_token: req.session.token.accessToken,
      refresh_token: req.session.token.refreshToken,
      expires_in: req.session.token.expiresIn,
      accounts: req.user.accounts
    });
  });
*/
});

// get the accounts from the VSO 
app.get('/accounts', ensureAuthenticated, function (req, res) {
  // access the Accounts URL from VSO. Requires an access token in the session.
  var options = {
    uri: 'https://app.vssps.visualstudio.com/_apis/Accounts?',
    qs: {
      memberId: req.user.id,
      'api-version': '1.0'
    },
    json: true,
    headers: {
      'Authorization': 'Bearer ' + req.session.token.accessToken
    }
  };

  request(options, function (error, response, body) {
    if (!error && response.statusCode == 200) {
      req.user.accounts = body.value;
    } else {
      // refresh the access_token and try again.
      res.redirect('/accounts');
    }
    res.render('profile', {
      user: req.user,
      access_token: req.session.token.accessToken,
      refresh_token: req.session.token.refreshToken,
      expires_in: req.session.token.expiresIn,
      accounts: req.user.accounts
    });
  });
});

// start the web server

console.log('useHttps: ' + config.vso.useHttps);
var port = 3443;
// start the server using https
if (config.vso.useHttps){
  var https = require('https');
  // Setup HTTPS
  var cert = {
    key: fs.readFileSync('examples/oauth2/certs/private.key'),
    cert: fs.readFileSync('examples/oauth2/certs/certificate.pem')
  };
  var secureServer = https.createServer(cert, app).listen(port);
} else {
  var http = require('http');
  // the server should be started using HTTP and the https is taken care
  // of by the provider (heroku)
  var secureServer = http.createServer(app).listen(port);
}

// Simple route middleware to ensure user is authenticated.
//   Use this route middleware on any resource that needs to be protected.  If
//   the request is authenticated (typically via a persistent login session),
//   the request will proceed.  Otherwise, the user will be redirected to the
//   login page.
function ensureAuthenticated(req, res, next) {
  if (req.user) {
    return next();
  }
  res.redirect('/login');
};

// if the req.user isn't populated, but there is a refresh token
// get the profile from the service.
// function fetchIdentity(req, res, next) {
//   if (typeof req.user === 'undefined') {
//     return next();
//   }
//   // access the Accounts URL from VSO. Requires an access token in the session.
//   var options = {
//     uri: 'https://app.vssps.visualstudio.com/_apis/profile/profiles/me?',
//     qs: {
//       'api-version': '1.0'
//     },
//     json: true,
//     headers: {
//       'Authorization': 'Bearer ' + req.session.token.accessToken
//     }
//   };

//   request(options, function (error, response, body) {
//     if (!error && response.statusCode == 200) {
//       req.user = body;
//       return next();
//     } else {
//       // refresh the access_token and try again.
//       refresh.requestNewAccessToken('vso', req.session.token.refreshToken, function (err, accessToken, refreshToken) {
//         req.session.token.accessToken = accessToken;
//         if (err) {
//           throw new Error('Unable to refresh the access token: ' + err.data);
//         }
//         fetchIdentity(req, res, next);
//       });
//     }
//   });
// }