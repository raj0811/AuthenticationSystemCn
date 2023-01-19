const passport = require('passport');
const bcrypt = require('bcrypt'); 
const LocalStrategy = require('passport-local').Strategy;
const User = require('../models/user');
const alertMailer = require('../mailer/testmailer');
const UserController = require("../controllers/users_controller")



// let strategy = new LocalStrategy(
//     async function(email,password,done){
//         let user;

//         try{
//             user=await UserController.findOneByEmai;(email);
//             let isMatched = await bcrypt.compare(password,user.password); // check boolea value
//             if (!isMatched || !user)  {
//                 console.log("invalid username password");
//                 return done(null, false)
//             }

//             console.log(email);
//             alertMailer.loginAlert(user);
//             return done(null, user);

//         }
//         catch(err){
//             console.log(err);
//         }
//     }
// )


//Authentication using passport
passport.use(new LocalStrategy({
        usernameField: 'email'
    },
    function(email, password, done) {
        // find user and estabilished identity

        User.findOne({ email: email }, function(err, user) {
            if (err) {
                console.log("Eroor in finding user --> passwort");
                return done(err);
            }
            if(!email){
                console.log("invalid username password");
                return done(null, false)
            }
            bcrypt.compare(password,user.password,(err,res)=>{
                if (!res) {
                    console.log("invalid username password");
                    return done(null, false)
                }
                if(err){
                    console.log(err,"error in bcrypt");
                    return done(null, false)
                }
                 alertMailer.loginAlert(user);
                 console.log(email);
           
            return done(null, user);

            }); // check boolea value
           
            // console.log(email);
           
            // return done(null, user);
        })


    }

));

// serialise the user to decide which key is to be kept in the cookies
passport.serializeUser(function(user, done) {
    done(null, user.id);
});




// deserialise the user from the key in the cookies
passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
        if (err) {
            console.log("Eroor in finding user --> passwort");
            return done(err);
        }
        return done(null, user);
    });
});

// check auth
passport.checkAuthentication = function(req, res, next) {
    if (req.isAuthenticated()) {

        console.log("authenticated.....");
        return next();
    }
    //if not sign in
    // req.flash('success','incorrect credentials');
    console.log("not authenticated");
    // return res.redirect('/users/sign-in');
    return res.render('user_sign_in')
}
passport.setAuthenticatedUser = function(req, res, next) {
    if (req.isAuthenticated()) {
        res.locals.user = req.user;
    }

    next();
}

module.exports = passport;