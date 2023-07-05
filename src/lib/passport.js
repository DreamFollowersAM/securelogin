const fs = require('fs')
let dictionary

const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;

const pool = require('../database');
const helpers = require('./helpers');

fs.readFile(__dirname+'/dict.txt','utf-8', (err, data) => {
  if(err){
    console.log(err);
    return
  }
  dictionary = data;
})

passport.use('local.signin', new LocalStrategy({
  usernameField: 'username',
  passwordField: 'password',
  passReqToCallback: true
}, async (req, username, password, done) => {
  const rows = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
  if (rows.length > 0) {
    const user = rows[0];
    const validPassword = await helpers.matchPassword(password, user.password)
    if (validPassword) {
      done(null, user, req.flash('success', 'Welcome ' + user.username));
    } else {
      done(null, false, req.flash('message', 'Incorrect Password'));
    }
  } else {
    return done(null, false, req.flash('message', 'The Username does not exists.'));
  }
}));

passport.use('local.signup', new LocalStrategy({
  usernameField: 'username',
  passwordField: 'password',
  passReqToCallback: true
}, async (req, username, password, done) => {

  const { fullname } = req.body;
  let newUser = {
    fullname,
    username,
    password
  };
  console.log(newUser);

  if (newUser.password.match(/([a-z].*[A-Z])|([A-Z].*[a-z])/) && newUser.password.match(/([0-9])/) && newUser.password.match(/([!,%,&,@,#,$,^,*,?,_,~])/)){
    
    if(dictionary.includes(newUser.password)){

      done(null, false, req.flash('message', 'This password exist in the common dictionaries, please try other one.'));

    } else {

      newUser.password = await helpers.encryptPassword(password);
      // Saving in the Database
      const result = await pool.query('INSERT INTO users SET ? ', newUser);
      newUser.id = result.insertId;
      done(null, newUser);
    }

  } else {

    return done(null, false, req.flash('message', 'Includes uppercase and lowercase letters, at least one special character, and one number.'));

  }
  
}));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  const rows = await pool.query('SELECT * FROM users WHERE id = ?', [id]);
  done(null, rows[0]);
});


