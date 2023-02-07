//jshint esversion:6

require('dotenv').config();

const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const app = express();
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require("mongoose-findorcreate");

app.use(express.static("public"));

app.set('view engine','ejs');

app.use(bodyParser.urlencoded({
  extended : true
}));

//Authentication and Security
//1 . username pass database
//2 . database encryption : mongoose-encryption , dotenv
//3 . hashing : md5 , bcrypt
//4 . salting and hashing : bcrypt , salting round
//5 . cookies and session : passport , passport-local , passport-local-mongoose ,express-session
//6 . OAuth 2.0 : passport-google-auth20 , mongoose-findorcreate , googleId


app.use(session({
  secret : "skidespikapi",
  resave : false ,
  saveUninitialized : false
}));

app.use(passport.initialize());
app.use(passport.session());


//database
const mongoose = require("mongoose");

const encrypt = require("mongoose-encryption");

mongoose.connect("mongodb://localhost:27017/userDB",{useNewUrlParser : true});
mongoose.set('strictQuery',true);

const userSchema = new mongoose.Schema( {
  email : String ,
  password : String,
  googleId : String
});

//
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
//



const User = mongoose.model("User",userSchema);

//
passport.use(User.createStrategy());

passport.serializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, {
      id: user.id,
      username: user.username,
      picture: user.picture
    });
  });
});

passport.deserializeUser(function(user, cb){
  process.nextTick(function() {
    return cb(null, user);
  });
});

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:4131/auth/google/secrets",
    useProfileUrl : "https://www.googleapis.com/oauth2/v3/userInfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));
//

app.get("/",function(req,res){
  res.render("home");
});

app.route("/login")
.get(function(req,res){
  res.render("login");
})

.post(function(req,res){

  const user = new User({
    username : req.body.username,
    password : req.body.password
  })

  req.login(user,function(err){
    if(err){
      console.log(err)
    }else{
      passport.authenticate("local")(req,res,function(){
        res.redirect("/secrets");
      });
    }
  })
});

app.route("/register")
.get(function(req,res){
  res.render("register");
})

.post(function(req,res){

  User.register({username :req.body.username},req.body.password,function(err,user){
    if(err){
      console.log(err);
      res.redirect("/register");
    }else{
      passport.isAuthenticated("local")(req,res,function(){
        res.redirect("/secrets");
      })
    }
  })
});

app.route("/secrets")
.get(function(req,res){
  if(req.isAuthenticated()){
    res.render("secrets");
  }else {
    res.redirect("/login");
  }
});

app.route("/logout")
.get(function(req,res){
  req.logout(function(err){
    if(err){
      console.log(err);
    }else{
      console.log("Session expired !")
    }
  });
  res.redirect("/");
});

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/google/oauth',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });


app.listen(4131,function(){
  console.log("Server up and running on port 4131");
});
