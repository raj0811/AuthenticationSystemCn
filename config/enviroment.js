const devlopment={
    name: "devlopment",
    
    smtp: {
        service: 'gmail',
        host: 'smtp.gmail.com',
        port: 587,
        secure: false,
        auth:{
             user: process.env.GMAIL,
            pass: process.env.APP_PASS,
        }
    },

    google_client_id: process.env.GOOGLE_CLIENT_ID,
    google_client_secret: process.env.GOOGLE_CLIENT_SECRET,
    google_call_back_url: process.env.GOOGLE_CALLBACK_URL,
        
    
}

const production = {
    name: "production"
}



module.exports = devlopment
