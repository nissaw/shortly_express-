var bcrypt = require('bcrypt-nodejs');
var flash = require('connect-flash');
var User = require('./models/user');
var Users = require('./collections/users');

var LocalStrategy = require('passport-local').Strategy;

module.exports = function(passport) {

  passport.serializeUser(function(user, done) {
    // gets saved as a session cookie
    done(null, user.attributes.id);
  });

  passport.deserializeUser(function(userId, done) {
    new User({ id: userId }).fetch().then(function(found) {
      if (found) {
        done(null, found);
      } else {
        done(true)
      }
    });
  });

  /// LOCAL SIGNUP
  passport.use('local-signup', new LocalStrategy({
    usernameField: 'username',
    passwordField: 'password',
    passReqToCallback: true
  }, function(req, username, password, done) {
    process.nextTick(function() {

      var username = req.body.username;
      var salt = bcrypt.genSaltSync(10);
      var hash = bcrypt.hashSync(req.body.password, salt);

      new User({
        username: username
      }).fetch().then(function(found) {
        if (found) {
          return done(null, false) // null = no error, false = username not valid for sign up
        } else {

          var user = new User({
            username: username,
            password: hash,
          });

          user.save().then(function(newUser) {
            Users.add(newUser);
            return done(null, newUser);
          });
        }
      });
    });
  }));

  ///LOCAL LOGIN

  passport.use('local-login', new LocalStrategy({
    usernameField: 'username',
    passwordField: 'password',
    passReqToCallback: true
  }, function(req, username, password, done) {
    process.nextTick(function() {

      var password = req.body.password;
      var username = req.body.username;

      new User({
        username: username
      }).fetch().then(function(user) {
        if (user) {
          if (bcrypt.compareSync(password, user.attributes.password)) {
            return done(null, user); // call a successful done (redirect to index)
          } else {
            return done(null, false); // return unsuccesful done(redirect to login)
          }
        } else {
          return done(null, false); // unsucessful dont (redirect to login)
        }
      });
    });
  }));






};
