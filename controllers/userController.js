const { validationResult } = require('express-validator')
const db = require('../config/dbConnection')
const bcrypt = require('bcryptjs');
const randomstring = require('randomstring')
const sendMail = require('../helpers/sendMail');
const jwt = require('jsonwebtoken');
const { JWT_SECRET } = process.env
const { isAthorize } = require('../middleware/auth')

const register = (req, res) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() })
    }

    db.query(`SELECT * FROM users WHERE LOWER(email) = LOWER(${db.escape(req.body.email)});`, (err, result) => {
        if (result && result.length) {
            return res.status(409).send({
                msg: 'This user already exist'
            })
        } else {
            bcrypt.hash(req.body.password, 10, (err, hash) => {
                if (err) {
                    return res.status(400).send({
                        msg: err
                    })
                } else {
                    db.query(`INSERT INTO users (name,email,password,image) VALUES ('${req.body.name}', ${db.escape(req.body.email)},${db.escape(hash)}, 'images/${req.file.filename}');`, (err, result) => {

                            if (err) {
                                return res.status(400).send({
                                    msg: err
                                })
                            }

                            const randomToken = randomstring.generate();


                            let mailSubject = 'Mail Verification';
                            let content = '<p> Hii ' + req.body.name + ',  Please <a href="http://127.0.0.1:3000/mail-verification?token=' + randomToken + '"> Verify</a> your Mail! </p> ';

                            sendMail(req.body.email, mailSubject, content);

                            db.query('UPDATE users set token=? where email=?', [randomToken, req.body.email], function(error, result) {
                                if (error) {
                                    return res.status(400).send({
                                        msg: err
                                    })
                                }
                            })


                            return res.status(200).send({
                                msg: 'The user has been register successfully'
                            })
                        }


                    )
                }
            })
        }
    })

}

const verifyMail = (req, res) => {
    var token = req.query.token;

    db.query(`SELECT * FROM users WHERE token=?`, token, function(error, result, fields) {

        if (error) {
            console.log(error.message);
        }

        if (result.length > 0) {

            db.query(`UPDATE users SET token = null, is_verified = 1 WHERE id = '${result[0].id}'`);
            return res.render('mail-verification', { message: 'Mail verified successfully' });


        } else {
            return res.render('404');
        }

    })

}

const login = (req, res) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() })
    }

    db.query(`SELECT * FROM users WHERE LOWER(email)= LOWER(${db.escape(req.body.email)});`, (err, result) => {
        if (err) {
            return res.status(400).send({
                msg: err
            })
        }

        if (!result.length) {
            return res.status(400).send({
                msg: "Email or password is incorrect"
            })
        }

        bcrypt.compare(req.body.password, result[0]['password'], (bErr, bResult) => {
            if (bErr) {
                return res.status(400).send({
                    msg: err
                })
            }

            if (bResult) {
                const jToken = jwt.sign({ id: result[0]['id'], is_admin: result[0]['is_admin'] }, JWT_SECRET, { expiresIn: '1h' })
                db.query(`UPDATE users SET last_login = now() WHERE id='${result[0]['id']}'`);

                return res.status(200).send({
                    msg: 'User Logged in successfully',
                    jtoken: jToken,
                    user: result[0]
                })

            }

            return res.status(400).send({
                msg: "Email or password is incorrect"
            })

        })

    })

}

const getUser = (req, res) => {
    const authToken = req.headers.authorization.split(' ')[1];
    const decode = jwt.verify(authToken, JWT_SECRET);

    db.query('SELECT * FROM users WHERE id=?', decode.id, function(err, result, fields) {
        if (err) throw err;

        return res.status(200).send({ success: true, data: result[0], msg: 'User Fetch Successfully' })
    })

}

const forgetPassword = (req, res) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() })
    }

    const email = req.body.email;

    db.query('SELECT * FROM users WHERE email=? limit 1', email, (err, result) => {

        if (err) {
            return res.status(400).send({
                msg: err
            })
        }

        if (result.length > 0) {
            const mailSubject = 'Forget Password';
            const randomString = randomstring.generate()
            const content = `<p> Hii ${result[0].name}, Please Click <a href="http://localhost:3000/reset-password?token=${randomString}"> Here </a> to Reset Password </p>`

            sendMail(email, mailSubject, content);

            db.query(`DELETE FROM password_reset WHERE email=${db.escape(result[0].email)}`);

            db.query(`INSERT INTO password_reset (email, token) VALUES(${db.escape(result[0].email)}, '${randomString}') `);

            return res.status(200).send({
                msg: 'Reset Mail sent Successfully'
            })
        }

        return res.status(401).send({
            msg: 'Email does not exist'
        })

    })

}

module.exports = {
    register,
    verifyMail,
    login,
    getUser,
    forgetPassword
}