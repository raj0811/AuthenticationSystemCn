const express = require('express');
const router = express.Router();
const homeController = require('../controllers/home_controller');
const passport = require('passport');




// setv routes
router.get('/',passport.checkAuthentication,homeController.home);
router.use('/users', require('./users'));

module.exports = router; 