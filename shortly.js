var express = require('express');
var util = require('./lib/utility');
var partials = require('express-partials');
var bodyParser = require('body-parser');
var session = require('express-session');
var bcrypt = require('bcrypt-nodejs');
var passport = require('passport');
var flash = require('connect-flash');

var db = require('./app/config');
var Users = require('./app/collections/users');
var User = require('./app/models/user');
var Links = require('./app/collections/links');
var Link = require('./app/models/link');
var Click = require('./app/models/click');
 
var app = express();

app.set('views', __dirname + '/views');
app.set('view engine', 'ejs');
app.use(partials());

require('./app/passport.js')(passport) // pass passport for config
app.use(session({secret: 'pug loaf'}));
// required for passport
app.use(passport.initialize());
app.use(passport.session());
app.use(flash());

// Parse JSON (uniform resource locators)
app.use(bodyParser.json());
// Parse forms (signup/login)
app.use(bodyParser.urlencoded({
  extended: true
}));
app.use(express.static(__dirname + '/public'));


app.get('/', util.restrict,
  function(req, res) {
    res.render('index');
  });

app.get('/create', util.restrict,
  function(req, res) {
    res.render('index');
  });

app.get('/links', util.restrict,
  function(req, res) {
    Links.reset().fetch().then(function(links) {
      res.send(200, links.models);
    });
  });

app.post('/links',
  function(req, res) {
    var uri = req.body.url;

    if (!util.isValidUrl(uri)) {
      console.log('Not a valid url: ', uri);
      return res.send(404);
    }

    new Link({
      url: uri
    }).fetch().then(function(found) {
      if (found) {
        res.send(200, found.attributes);
      } else {
        util.getUrlTitle(uri, function(err, title) {
          if (err) {
            console.log('Error reading URL heading: ', err);
            return res.send(404);
          }

          var link = new Link({
            url: uri,
            title: title,
            base_url: req.headers.origin
          });

          link.save().then(function(newLink) {
            Links.add(newLink);
            res.send(200, newLink);
          });
        });
      }
    });
  });

/************************************************************/
// Write your authentication routes here
/************************************************************/
app.get('/profile', util.restrict,
  function(req, res){
    res.render('profile', {user: req.user});
  });

app.get('/login',
  function(req, res) {
    res.render('login', {message: req.flash('login-message')});
  });

app.get('/signup',
  function(req, res) {
    res.render('signup', {message: req.flash('signup-message')});
  });

app.post('/signup', passport.authenticate('local-signup', {
  successRedirect: '/',
  failureRedirect: '/signup',
  failureFlash: true
}));

app.post('/login', passport.authenticate('local-login', {
  successRedirect: '/',
  failureRedirect: '/login',
  failureFlash: true
}));

app.get('/auth/github',
  passport.authenticate('github'),
  function(req, res){
    // The request will be redirected to GitHub for authentication, so this
    // function will not be called.
  });

app.get('/auth/github/callback', 
  passport.authenticate('github', { failureRedirect: '/login' }),
  function(req, res) {
    res.redirect('/');
  });

app.get('/logout',
  function(req, res){
    req.logout();
    res.redirect('/login');
  });

//ORIGINAL SOLUTION BEFORE PASSPORT
// app.post('/login',
//   function(req, res) {
//     var password = req.body.password;
//     var username = req.body.username;

//     new User({
//       username: username
//     }).fetch().then(function(found) {
//       if (found) {
//         if (bcrypt.compareSync(password, found.attributes.password)){
//           req.session.regenerate(function() {
//             req.session.user = username;
//             res.redirect('/');
//           });
//         } else {
//           res.redirect('/login');
//         }
//       } else {
//         res.redirect('/login');
//       }
//     });
//   });


// app.post('/signup',
//   function(req, res) {

//     var username = req.body.username;
//     var salt = bcrypt.genSaltSync(10);
//     var hash = bcrypt.hashSync(req.body.password, salt);

//     new User({
//       username: username
//     }).fetch().then(function(found) {
//       if (found) {
//         res.redirect('/login');
//       } else {
//         var user = new User({
//           username: username,
//           password: hash,
//         });

//         user.save().then(function(newUser) {
//           Users.add(newUser);
//           req.session.regenerate(function() {
//             req.session.user = username;
//             res.redirect('/');
//           });
//         });
//       }
//     });
//   });


/************************************************************/
// Handle the wildcard route last - if all other routes fail
// assume the route is a short code and try and handle it here.
// If the short-code doesn't exist, send the user to '/'
/************************************************************/

app.get('/*', function(req, res) {
  new Link({
    code: req.params[0]
  }).fetch().then(function(link) {
    if (!link) {
      res.redirect('/');
    } else {
      var click = new Click({
        link_id: link.get('id')
      });

      click.save().then(function() {
        db.knex('urls')
          .where('code', '=', link.get('code'))
          .update({
            visits: link.get('visits') + 1,
          }).then(function() {
            return res.redirect(link.get('url'));
          });
      });
    }
  });
});

console.log('Shortly is listening on 4568');
app.listen(4568);
