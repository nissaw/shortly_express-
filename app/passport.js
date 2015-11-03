var bcrypt = require('bcrypt-nodejs');
var flash = require('connect-flash');
var User = require('./models/user');
var Users = require('./collections/users');

var LocalStrategy = require('passport-local').Strategy;

module.exports = function(passport) {
    
    passport.serializeUser(function(user, done) {
      done(null, user.id);
    });

    passport.deserializeUser(function(user, done) {
      User.findById(id, function(err, user) {
        done(err, user);
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
    }; 
