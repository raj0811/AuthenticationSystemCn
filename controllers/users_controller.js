const User = require("../models/user")
const alertMailer = require('../mailer/testmailer');
const resetMailer = require('../mailer/resetpasswordmailer');
const bcrypt = require('bcrypt'); 
const sendOtop=require('../mailer/resetpasswordmailer')


module.exports.profile = function(req, res) {
    return res.render('profile', {
        title: "Profile"
    })
}



module.exports.signup = function(req,res){

    if(req.isAuthenticated()){
        return res.render('profile',{
            title: 'profile'
        })

    }
    return res.render('user_sign_up',{
        title: "Signup"
    })
}

module.exports.signin = function(req,res){

    if(req.isAuthenticated()){
        return res.render('profile',{
            title: 'profile'
        })

    }
    return res.render('user_sign_in',{
        title: "Signin"
    })
}


// get signup data

module.exports.create = async function(req,res){

    const name=req.body.name;
    const email=req.body.email;
    const password=req.body.password; 
   
     
    try{
    const user= await User.findOne({email})
        


        if(!user){
            const newUser = new User({
                name,
                email,
                password
            });
            newUser.save();
            return res.redirect('/users/sign-in');

        }
        else{
            return res.redirect('back')
        }
    

}catch(err){
    console.log(err);
}
}



// create session


module.exports.createSession = function(req,res){
    req.flash('success','Logged-in Successfully');
   
    // const email = req.body.email;
    
    // let user =User.findOne({email})
    // // alertMailer.loginAlert(User);
    // console.log(user.email);
    return res.redirect('/');
}


module.exports.destroySession = function (req, res) {
    req.logout(function (err) {
        if (err) {
            console.log('err');
        }
});
    console.log("logged out");
    req.flash('success','Logged-in Successfully');
    res.redirect('/')

}

module.exports.changePassword = function(req,res){
    return res.render('changepass',{
        title: 'Change Password'
    })
}

module.exports.updatePassword = async function(req,res){

    try{

    const user = await User.findById(req.params.id);
        if(!user){
            console.log(err);
        }
        else{
            if(req.user.email == req.body.email && req.body.opass){
                let isMatched= await bcrypt.compare(req.body.opass,user.password);
                console.log(isMatched);
                console.log(req.body.opass);
                console.log(user.password);
                if(!isMatched){
                    console.log("Invalid Password ");

                }else{

                    let newpass= await bcrypt.hash(req.body.npass,10);
                    console.log(newpass);
                    console.log("pppp");
                    User.findByIdAndUpdate(req.params.id,{password: newpass },function(err,user){
                        return res.redirect('back')
                    })
                }
            }
        }
}
catch(err){
    console.log("errrr");
}


    

    // console.log(req.params.id);
    // User.findById((req.params.id),function(err,user){
        
    //     if(req.user.email == req.body.email && req.body.opass){

    //         let isMatched = bcrypt.compare(req.body.opass,user.password); // check boolea value
    //             if (isMatched) {
    //                 console.log("valid username password");
    //                 User.findByIdAndUpdate(req.params.id,{password: req.body.npass},function(err,user){
    //                     return res.redirect('back');
    //                 })
                   
    //             }
    
    //         console.log("correct ");
    //     }
    // })
    // console.log("hiiii");


   
}




// render forget password page
module.exports.forgetPassword = function(req,res){
    return res.render('forgetpassword',{
        title: "ForgetPassword"
    });
    // return res.render('changepass');
}





module.exports.randomNum = async function(req,res){

    const email = await req.body.email;

    try{
       


    const user = await User.findById(req.params.id);
    // const user = await User.findOne({
    //     email
    // });


    // var max=9999;
    // var min = 1000;
    // let k= Math.floor(
    // Math.random()*(max-min)+min
    // )



    var chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        var string_length = 8;
        var randomstring = '';
        for (var i=0; i<string_length; i++) {
            var rnum = Math.floor(Math.random() * chars.length);
            randomstring += chars.substring(rnum,rnum+1);
        }


        var k = randomstring

        console.log(k,"heeeheheheheheh");
    var mail = req.user.email
    var name = req.user.name
    console.log(req.user.name);
        resetMailer.resetMail(k,mail,name)

        console.log(req.params.id,"save");
       

        // console.log(k);
       

        var otp;
    //    console.log(req.session);

    let newpassword= await bcrypt.hash(k,10);
    console.log("new pass",newpassword);
    User.findByIdAndUpdate(req.params.id,{password: newpassword}, function(err,user){
        req.flash('success','Password Reset and send  Successfully');
        return res.redirect('back')

    })
       
       
       

    }
    catch(err){
        console.log("error",err);
    }
}

// module.exports.randomNum0 = function(req,res){

//     var max=9999;
//     var min = 1000;
//    var k= Math.floor(
//     Math.random()*(max-min)+min
//     )


//     User.findById(req.params.id, function(err,user){

//         // console.log(req.user.email);
//         // console.log(k);
//         var mail = req.user.email
//         resetMailer.resetMail(k,mail)
//     })

    
// }

// Render Confirm Password Page

module.exports.confirmPassword = function(req,res){
    // return res.render('setpassword');
    // return res.render('changepass');

    console.log("ooo");
    console.log(req.session.value);
    
    
}