//jshint esversion:6

require('dotenv').config();

const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const app = express();
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");


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
//6 . OAuth 2.0


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
  password : String
});

//
userSchema.plugin(passportLocalMongoose);
//

// const secret = process.env.SECRET;
//
// userSchema.plugin(encrypt,{secret : secret, encryptedFields:['password']});

const User = mongoose.model("User",userSchema);

//
passport.use(User.createStrategy());

passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());
//

app.get("/",function(req,res){
  res.render("home");
});

app.route("/login")
.get(function(req,res){
  res.render("login");
})

.post(function(req,res){
  // const id = req.body.username;
  // const pass = req.body.password;
  //
  // User.findOne({email : id},function(err,foundUser){
  //   if(err){
  //     console.log(err);
  //   }else{
  //     if(foundUser){
  //       if(foundUser.password === pass){
  //         res.render("secrets");
  //       }
  //     }
  //   }
  // })

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
  // const newUser = new User({
  //   email : req.body.username,
  //   password : req.body.password
  // });
  //
  // newUser.save(function(err){
  //   if(!err){
  //     console.log("New User Created !");
  //     res.render("secrets");
  //   }else {
  //     console.log(err);
  //   }
  // });
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


app.listen(4131,function(){
  console.log("Server up and running on port 4131");
});
