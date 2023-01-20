const express = require('express');
const router = express.Router();
const usersController = require('../controllers/users_controller');
const passport = require('passport');


router.get('/sign-up',usersController.signup);
router.get('/sign-in',usersController.signin);
router.get('/profile',passport.checkAuthentication,usersController.profile);
router.post('/create',usersController.create);


router.post('/create-session', passport.authenticate(
    'local', { failureRedirect: '/users/sign-in' }
), usersController.createSession);


router.get('/sign-out',usersController.destroySession);

router.get('/auth/google', passport.authenticate('google', {scope: ['profile','email']}));
router.get('/auth/google/callback', passport.authenticate('google', {failureRedirect: 'users/sign-in'}), usersController.createSession);
router.get('/changepass',passport.checkAuthentication,usersController.changePassword);
router.post('/update/:id',passport.checkAuthentication,usersController.updatePassword);
router.get('/forget-password',usersController.forgetPassword);
router.get('/randomNumber/:id',usersController.randomNum)
router.get('/confirmpassword',usersController.confirmPassword)

module.exports = router;