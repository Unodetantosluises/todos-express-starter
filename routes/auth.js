var express = require('express');

var passport = require('passport');

var GoogleStrategy = require('passport-google-oidc');
// Configura GoogleStrategy
passport.use(new GoogleStrategy({
    clientID: process.env['GOOGLE_CLIENT_ID'],
    clientSecret: process.env['GOOGLE_CLIENT_SECRET'],
    callbackURL: '/oauth2/redirect/google',
    scope: [ 'profile' ]
}, function verify(issuer, profile, cb) {
    db.get('SELECT * FROM federated_credentials WHERE provider = ? AND subject = ?', [
           issuer,
           profile.id
    ], function(err, row) {
    if(err) { return cb(err); }
    if(!row) {
        db.run('INSERT INTO users (name) VALUES (?)', [
            profile.displayName
        ], function(err) {
            if (err) { return cb(err); }

            var id = this.lastID;
            db.run('INSERT INTO federated_credentials (user_id, provider, subject) VALUES (?, ?, ?)', [
                id,
                issuer,
                profile.id
            ], function(err) {
                if (err) { return cb(err); } 
                var user = {
                    id: id,
                    name: profile.displayName
                };
                return cb(null, user);
            });    
        });
    } else {
        db.get('SELECT * FROM users WHERE id = ?', [ row.user_id ], function(err, row) {
           if (err) { return cb(err); }
           if (!row) { return cb(null, false);}
           return cb (null, row); 
        });
    }
});
}));

var db = require('../db');

var router = express.Router();

router.get('/login', function(req, res, next) {
    res.render('login');
});

router.get('/login/federated/google', passport.authenticate('google'));
//Esta es la ruta que autentica al usuario cuando google lo redirigue de nuevo a la app
router.get('/oauth2/redirect/google', passport.authenticate('google', {
    successRedirect: '/',
    failureRedirect: '/login'
}));
//Ahora que el ciclo de redireccion esta completo, de redigir a google y de redirigir de regreso a la app

module.exports = router;