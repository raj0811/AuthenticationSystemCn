const devlopment={
    name: "devlopment",
    
    smtp: {
        service: 'gmail',
        host: 'smtp.gmail.com',
        port: 587,
        secure: false,
        auth:{
             user: 'mrunknown.0086@gmail.com',
            pass: 'isnytfcymvjabomg'
        }
    },

    google_client_id: "297293548800-9531e9p5lt38mc702c5mkb0o6a6g0i71.apps.googleusercontent.com",
    google_client_secret: "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",
    google_call_back_url: "http://localhost:8003/users/auth/google/callback"
        
    
}

const production = {
    name: "production"
}



module.exports = devlopment
