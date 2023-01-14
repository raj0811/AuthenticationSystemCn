const nodeMailer = require("../config/nodemailer");
const User = require("../models/user");
const session = require('express-session');



exports.resetMail = (k,user,name) => {
    console.log('inside Reset mailer');
    console.log(user);
    // console.log(k);
    var otp;
   

    nodeMailer.transporter.sendMail({
        from: 'rajpbarmaiya@gmail.com',
        to: user,
        // to:"rpbarmaiya@gmail.com",
        subject: "Password reseted Successfully",
        html: `<h1> Hey ${name} your Password Hasbeen Reseted <br> Your new Temporary password  is ${k} <br> We suggest you to Reset ASAP </h1>`
    },
    (err,info)=>{
        if(err){
            console.log('error in sending mail',err);
        }
        console.log("mail sent",info);
        return;
    }
    );
} 

