const nodeMailer = require("../config/nodemailer");
const User = require("../models/user");




exports.loginAlert = (user) => {
    console.log('inside alert mailer');
    // console.log(k);
   

    // console.log(user.email);

    nodeMailer.transporter.sendMail({
        from: 'rajpbarmaiya@gmail.com',
        to: user.email,
        // to:"rpbarmaiya@gmail.com",
        subject: "new login alert",
        html: '<h1>login loginAlert</h1>'
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