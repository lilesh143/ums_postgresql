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
                const jToken = jwt.sign({ id: result[0]['id'], is_admin: result[0]['is_admin'] }, JWT_SECRET, { expiresIn: "1h" })
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

const resetPasswordLoad = (req, res) => {

    try {

        const token = req.query.token;
        if (token == undefined) {
            return res.render('404');
        }

        db.query(`SELECT * FROM password_reset WHERE token=? limit 1`, token, function(error, result, fields) {

            if (error) {
                console.log(error.message);
            }

            if (result !== undefined && result.length > 0) {

                db.query(`SELECT * FROM users WHERE email=? limit 1`, result[0].email, function(error, result, fields) {

                    if (error) {
                        console.log(error.message);
                    }

                    res.render('reset-password', { user: result[0] })

                })

            } else {
                return res.render('404');
            }

        })

    } catch (error) {
        console.log(error.message);

    }
}

const resetPassword = (req, res) => {

    console.log(req.body.user_id, req.body.user_email);

    if (req.body.password != req.body.confirm_password) {
        res.render('reset-password', { error_message: "Password does not match", user: { id: req.body.user_id, email: req.body.user_email } });

        // console.log(req.body.password, req.body.confirm_password);

    } else {


        bcrypt.genSalt(10, function(err, salt) {
            bcrypt.hash(req.body.confirm_password, 10, function(err, hash) {
                // Store hash in your password DB.

                if (err) {
                    console.log(err);
                } else {

                    db.query(`DELETE FROM password_reset WHERE email='${req.body.user_email}'`);

                    db.query(`UPDATE users SET password = '${hash}' WHERE id = '${req.body.user_id}'`);

                    return res.render('updateMsg', { message: 'Password reset successfully' });
                }
            });
        });


        // console.log(req.body.password, req.body.confirm_password);
        // bcrypt.hash(req.body.comfirm_password, 10, (err, hash) => {

        //     if (err) {
        //         console.log(err);
        //     } else {

        //         db.query(`DELETE FROM password_reset WHERE email='${req.body.user_email}'`);

        //         db.query(`UPDATE users SET password = '${hash}' WHERE id = '${req.body.user_id}'`);

        //         return res.render('updateMsg', { message: 'Password reset successfully' });
        //     }

        // })
    }


}

const updateProfile = (req, res) => {

    try {
        const errors = validationResult(req);

        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() })
        }

        const authToken = req.headers.authorization.split(' ')[1];
        const decode = jwt.verify(authToken, JWT_SECRET);

        var sql = '',
            data;

        if (req.file != undefined) {

            sql = 'UPDATE users SET name = ?, email = ?, image = ? WHERE id = ?';
            data = [req.body.name, req.body.email, 'images/' + req.file.filename, decode.id];

        } else {
            sql = 'UPDATE users SET name = ?, email = ? WHERE id = ?';
            data = [req.body.name, req.body.email, decode.id];

        }

        db.query(sql, data, function(error, result, fields) {
            if (error) {
                res.status(400).send({ msg: error })
            }

            res.status(200).send({
                msg: 'Profile updated successfully'
            })
        })

    } catch (error) {
        return res.status(400).json({ msg: error.message })
    }

}

module.exports = {
    register,
    verifyMail,
    login,
    getUser,
    forgetPassword,
    resetPasswordLoad,
    resetPassword,
    updateProfile
}