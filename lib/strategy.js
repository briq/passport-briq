const OAuth2Strategy = require('passport-oauth2').Strategy;

/**
 * Creates an instance of `BriqStrategy`.
 *
 * The Briq authentication Strategy authenticates requests using the OAuth
 * 2.0 protocol on Briq.
 *
 * Applications must supply a `verify` callback, for which the function
 * signature is:
 *
 *     function(accessToken, refreshToken, profile, done) { ... }
 *
 * The verify callback is responsible for finding or creating the user, and
 * invoking `done` with the following arguments:
 *
 *     done(err, user, info);
 *
 * `user` should be set to `false` to indicate an authentication failure.
 * Additional `info` can optionally be passed as a third argument, typically
 * used to display informational messages.  If an exception occured, `err`
 * should be set.
 *
 * Mandatory options:
 *   - `clientID`          identifies client to Briq
 *   - `clientSecret`      secret used to establish ownership of the client identifer
 *   - `callbackURL`       URL to which Briq will redirect the user after obtaining authorization
 *   - `passReqToCallback` when `true`, `req` is the first argument to the verify callback (default: `false`)
 *
 * Examples:
 *
 *     passport.use(new BriqStrategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/example/callback'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @constructor
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
class Strategy extends OAuth2Strategy {

  constructor(options, verify) {
    options = options || {};
    options.authorizationURL = Strategy.BASE_URL + '/oauth/authorize';
    options.tokenURL = Strategy.BASE_URL + '/oauth/token';
    options.profileURL = Strategy.BASE_URL + '/oauth/me';

    super(options, verify);

    this.name = 'briq';
    this.profileURL = options.profileURL;
  }

  userProfile(accessToken, done) {
    return this._oauth2.get(this.profileURL, accessToken, (err, data, response) => {
      if (err) {
        return done(err);
      }
      return done(null, JSON.parse(data));
    });
  }
}

Strategy.BASE_URL = 'https://www.givebriq.com';

module.exports = Strategy;
