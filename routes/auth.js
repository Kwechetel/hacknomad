const express = require('express');
const { check } = require('express-validator');

const isAuth = require('../middleware/is-Auth');
const user = require('../controllers/auth');

const router = express.Router();

router.post('/signup',
    [
        check('user_mail').isEmail(),
        check('user_password').isLength({min: 6})
    ], 
    user.signup
);

router.get('/send/:id', 
    user.sendConfirm
);

router.post('/verify',
    isAuth, 
    user.userVerify
);

router.post('/login',
    [
        check('user_mail').isEmail(),
        check('user_password').isLength({min: 6})
    ],
    user.login
);

router.post('/update/basics',
    isAuth,
    [
        check('user_mail').isEmail()
    ],
    user.updateBasics
);

router.post('/update/password',
    isAuth,
    [
        check('user_password').isLength({min: 6})
    ],
    user.updatePassword
);

router.get('/users', isAuth, user.getAllUser );
module.exports = router;