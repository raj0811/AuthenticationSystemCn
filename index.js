const express=require('express');       
const cookieParser = require('cookie-parser');
var expressLayouts = require('express-ejs-layouts');   
const port = 8003;




const db=require('./config/mongoose');
const session = require('express-session');
const passport = require('passport');
const passportLocal = require('./config/passport-local-strategy');
// const MongoDBStore = require('connect-mongodb-session')(session);
const MongoStore = require('connect-mongo');
// const MongoStore = require('connect-mongo')(session);

const passportGoogle=require('./config/passport-google-oauth2-strategy')

const flash = require('connect-flash');
const customMware = require('./config/middleware');
const bodyParser = require('body-parser');
const app= express();
app.use(express.static('assets'));

// passport.use(strategy);
app.use(bodyParser.json());
app.use(bodyParser.urlencoded());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());



app.use(expressLayouts);

// setup view engin
app.set('view engine', 'ejs');
app.set('views', './views');


app.use(session({
    name: 'issueTracker',
    secret:'#skey',
    saveUninitialized: false,
    resave: false,
    cookie: {
        maxAge: (1000 * 60 * 100)
    },
    store: MongoStore.create({

        mongoUrl: 'mongodb+srv://raj:raj0811@cluster0.xpjnzpo.mongodb.net/?retryWrites=true&w=majority',
        autoRemove: 'disabled'

    },
    function(err){
        console.log(err || 'error in connect - mongodb setup ok');
    }
    )
}));


app.use(passport.initialize());
app.use(passport.session());
// app.use(expressLayouts);


app.use(passport.setAuthenticatedUser)

app.use(flash());
app.use(customMware.setFlash)
// extract style and script from subpages to layout
app.set('layout extractStyles', true);
app.set('layout extractScripts', true);


app.use('/', require('./routes'));

app.listen(port, function(err) {
    if (err) {
        console.log(`Error in running the server: ${err}`);
    }
    console.log(`Server is running on port: ${port} `);
})