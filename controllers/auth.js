const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const sendGridTransport = require('nodemailer-sendgrid-transport');

const db = require('../util/dbconnection');
const { validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');

exports.signup = (req, res, next) => {

    const errors = validationResult(req);

    if(!errors.isEmpty()) {
        return res.status(422).json({ errors: errors.array() });
    }
    

    db.execute(`SELECT * FROM users WHERE user_mail=?`, [req.body.user_mail]).then((rows, fieldData) => {
        
        let user = null;
        rows[0].length === 0 ? user = true : user = null

        loadUser = rows[0];

        return user; 
    })
    .then(createUser => {

        if(!createUser) {
            res.json([{user: 'User exist'}]);

            return false;
        }
    
        const pwd = req.body.user_password;
        bcrypt.hash(pwd, 12).then(hashedPwd => {
            let userDate = new Date().getTime();
            const userData = [req.body.user_first, req.body.user_last, req.body.user_mail, hashedPwd, userDate];
    
            db.execute(`INSERT INTO users (user_first, user_last, user_mail, user_password, user_date) VALUES(?, ?, ?, ?, ?)`, userData)
            .then(([rows, fieldData]) => {
                //res.json(rows)

                res.redirect(`/auth/send/${req.body.user_mail}`)
                
            })
            .catch((err) => console.log(err))
            
        });
    })

}

exports.sendConfirm = (req, res, next) => {

    let confrimToken;

    db.execute('SELECT * FROM users WHERE user_mail = ?', [req.params.id]).then((rows, fieldData) => {
        let isExist;

        rows[0].length === 0 ? isExist = null : isExist = true;

        return [isExist, rows[0]]

    })
    .then(([isExist, user]) => {

        if(!isExist) {
            return false;
        }

        confrimToken = jwt.sign({id: user[0].id}, process.env.JW_SECRETE, { expiresIn: '24h' } );

        let transporter = nodemailer.createTransport(sendGridTransport({
            auth: {
                api_key: process.env.SENDGRID_KEY
            }
        }));

        let mailOptions = {
            from: 'kwechete@hacknomad.com',
            to: req.params.id,
            subject: 'Yep app',
            text: confrimToken
        };

        console.log(req.params.id)

        if(req.params.id) {
            transporter.sendMail(mailOptions, (err, data) => {
                if(err) {
                    res.status(200).json([{message: 'Confirmation failed!'}])
                }else {
                    res.status(200).json([{message: 'Confirmation successful!'}])
                }
            });
        }
    });

}

exports.userVerify = (req, res, next) => {

    db.execute('UPDATE users SET user_verify=? WHERE id=?', ['true', req.userId]).then((rows, fieldData) => {

        if(rows[0].affectedRows === 0) {
            res.status(200).json([{message: 'User no longer available in our database'}]);

            return false;
        }
        
        res.status(200).json([{message: 'User verified successfully'}])
    })
    .catch((err) => {
        console.log(err)
    });
}

exports.login = (req, res, next) => {

    let loadUser;

    db.execute(`SELECT * FROM users WHERE user_mail=?`, [req.body.user_mail]).then((rows, fieldData) => {
        let user = null;
        rows[0].length === 0 ? user = null : user = true 

        loadUser = rows[0];

        return [user, rows[0]];
    })
    .then(([user, userData])=> {
        if(!user){
            res.status(401).json([{message: 'A user with this email could not be found.'}])

            return false;
        }
        
        const password = userData[0].user_password;

        return bcrypt.compare(req.body.user_password, password);
    })
    .then(isEqual => {
        if(!isEqual) {

            res.status(401).json([{message: "Wrong password!"}]);

            return false;
        }

        console.log('access granded', loadUser)
        
        const token  = jwt.sign(
            {
                id: loadUser[0].id
            },
            process.env.JW_SECRETE,
            { expiresIn: '24h' }
        );
        res.status(200).json([{
            token: token, 
            user_id: loadUser[0].id.toString(),
            name: loadUser[0].user_first,
            surname: loadUser[0].user_last,
            email: loadUser[0].user_first
        }]);
    })
    .catch(err => {
        if (!err.statusCode) {
          err.statusCode = 500;
        }
        next(err);
    })
}

exports.updateBasics = (req, res, next) => {

    const id = req.userId
    
    db.execute(`SELECT * FROM users WHERE user_mail = ? AND id != ? `, [req.body.user_mail, id]).then((rows,fieldData) => {
        let checkEmail;
        rows[0].length > 0 ? checkEmail = null : checkEmail = true

        return checkEmail
    })
    .then(isEmail => {

        if(!isEmail) {
            res.status(200).json([{error: 'Email already taken'}])

            return false;
        }

        const userData = [req.body.user_first, req.body.user_last, req.body.user_mail, id];

        db.execute(`UPDATE users SET user_first =  ?, user_last = ?, user_mail = ? WHERE id = ? `, userData).then((rows, fieldData) => {
            res.status(200).json(rows);
        })
    })
}

exports.updatePassword = (req, res, next) => {

    db.execute(`SELECT * FROM users WHERE id=?`, [req.userId]).then((rows, fieldData) => {
        let user = null;

        rows[0].length === 0 ? user = null : user = true

        return user;
    })
    .then(isUser => {
        if(!isUser) {
            res.json([{message: "User no longer available"}]);

            return false;
        }

        const pwd = req.body.user_password;

        bcrypt.hash(pwd, 12).then(hashedPwd => {
            db.execute(`UPDATE users SET user_password = ? WHERE id = ?`, [hashedPwd, req.userId]).then((rows, fieldData) => {
                res.json([{message: "Password changed successfully"}])
            })
        })
    })
}

exports.getAllUser = (req, res, next) => {
    db.execute(`SELECT * FROM users`).then((rows, fieldData) => {
        const usersData = rows[0];

        let getUsers = usersData.map((a) => ({
            id: a.id,
            user_first: a.user_first,
            user_last: a.user_last,
            user_mail: a.user_mail,
            user_uid: a.user_uid,
            user_date: a.user_date,
            user_verify: a.user_verify
        }))
        res.status(200).json(getUsers)
    })
}