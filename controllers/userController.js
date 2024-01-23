const { validationResult } = require('express-validator');
const db = require('../config/dbConnection');
const bcrypt = require('bcryptjs');
const randomstring = require('randomstring');
const sendMail = require('../helpers/sendMail');
const jwt = require('jsonwebtoken');
const { JWT_SECRET } = process.env;
const { isAthorize } = require('../middleware/auth');

const register = (req, res) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    db.query(
        `SELECT * FROM users2 WHERE LOWER(email) = LOWER($1);`, [req.body.email],
        (err, result) => {
            console.log(result.rows.length);


            if (result.rows.length && result != undefined) {
                return res.status(409).send({
                    msg: 'This user already exists',
                });
            } else {
                bcrypt.hash(req.body.password, 10, (err, hash) => {
                    if (err) {
                        return res.status(400).send({
                            msg: err,
                        });
                    } else {
                        db.query(
                            `INSERT INTO users2 (name, email, password, image) VALUES ($1, $2, $3, $4);`, [req.body.name, req.body.email, hash, req.file.filename],
                            (err, result) => {
                                if (err) {
                                    return res.status(400).send({
                                        msg: err,
                                    });
                                }

                                const randomToken = randomstring.generate();

                                let mailSubject = 'Mail Verification';
                                let content = `<p> Hii ${req.body.name}, Please <a href="http://127.0.0.1:3000/mail-verification?token=${randomToken}"> Verify</a> your Mail! </p> `;

                                sendMail(req.body.email, mailSubject, content);

                                db.query(
                                    'UPDATE users2 SET token=$1 WHERE email=$2', [randomToken, req.body.email],
                                    (error, result) => {
                                        if (error) {
                                            return res.status(400).send({
                                                msg: error,
                                            });
                                        }
                                        return res.status(200).send({
                                            msg: 'The user has been registered successfully',
                                        });
                                    }
                                );
                            }
                        );
                    }
                });
            }
        }
    );
};

const verifyMail = (req, res) => {
    var token = req.query.token;

    db.query(
        `SELECT * FROM users2 WHERE token=$1`, [token],
        (error, result, fields) => {
            if (error) {
                console.log(error.message);
            }
            // console.log(token);
            // console.log(result.rows);
            // console.log(result.rows.length);
            // console.log([result].length);
            // console.log([result]);
            // console.log('...........................');
            // console.log([result][0]);

            if (result.rows.length > 0) {
                db.query(
                    `UPDATE users2 SET token = null, is_verified = 1 WHERE id = $1`, [result.rows[0].id]
                );
                return res.render('mail-verification', {
                    message: 'Mail verified successfully',
                });
            } else {
                return res.render('404');
            }
        }
    );
};

const login = (req, res) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    db.query(
        `SELECT * FROM users2 WHERE LOWER(email) = LOWER($1);`, [req.body.email],
        (err, result) => {
            if (err) {
                return res.status(400).send({
                    msg: err,
                });
            }
            // console.log(result);
            // console.log([result].length);
            // console.log(result.rows);
            // console.log(result.rows['password']);
            // console.log(result.rows[0]['password']);
            // console.log(result.rows[0]);



            if (!result.rows.length) {
                return res.status(400).send({
                    msg: 'Email or password is incorrect',
                });
            }

            bcrypt.compare(
                req.body.password,
                result.rows[0]['password'],
                (bErr, bResult) => {
                    if (bErr) {
                        return res.status(400).send({
                            msg: bErr,
                        });
                    }

                    if (bResult) {
                        const jToken = jwt.sign({
                                id: result.rows[0]['id'],
                                is_admin: result.rows[0]['is_admin'],
                            },
                            JWT_SECRET, { expiresIn: '1h' }
                        );
                        db.query(
                            'UPDATE users2 SET last_login = now() WHERE id=$1', [result.rows[0]['id']],
                            () => {
                                return res.status(200).send({
                                    msg: 'User Logged in successfully',
                                    jtoken: jToken,
                                    user: [result][0],
                                });
                            }
                        );
                    } else {
                        return res.status(400).send({
                            msg: 'Email or password is incorrect',
                        });
                    }
                }
            );
        }
    );
};

const getUser = (req, res) => {
    const authToken = req.headers.authorization.split(' ')[1];
    const decode = jwt.verify(authToken, JWT_SECRET);

    db.query('SELECT * FROM users2 WHERE id=$1', [decode.id], (err, result) => {
        if (err) throw err;

        return res.status(200).send({
            success: true,
            data: result.rows[0],
            msg: 'User Fetch Successfully',
        });
    });
};

const forgetPassword = (req, res) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const email = req.body.email;

    db.query(
        'SELECT * FROM users2 WHERE email=$1 LIMIT 1', [email],
        (err, result) => {
            if (err) {
                return res.status(400).send({
                    msg: err,
                });
            }

            if (result.rows.length > 0) {
                const mailSubject = 'Forget Password';
                const randomString = randomstring.generate();
                const content = `<p> Hii ${result.rows[0].name}, Please Click <a href="http://localhost:3000/reset-password?token=${randomString}"> Here </a> to Reset Password </p>`;

                sendMail(email, mailSubject, content);

                db.query('DELETE FROM password_reset WHERE email=$1', [result.rows[0].email])
                db.query('INSERT INTO password_reset (email, token) VALUES($1, $2)', [result.rows[0].email, randomString],
                    () => {
                        return res.status(200).send({
                            msg: 'Reset Mail sent Successfully',
                        });
                    }
                );
            } else {
                return res.status(401).send({
                    msg: 'Email does not exist',
                });
            }
        }
    );
};

const resetPasswordLoad = (req, res) => {
    try {
        const token = req.query.token;
        if (token == undefined) {
            return res.render('404');
        }

        db.query(
            'SELECT * FROM password_reset WHERE token=$1 LIMIT 1', [token],
            (error, result) => {
                if (error) {
                    console.log(error.message);
                }

                if (result !== undefined && result.rows.length > 0) {
                    db.query(
                        'SELECT * FROM users2 WHERE email=$1 LIMIT 1', [result.rows[0].email],
                        (error, result) => {
                            if (error) {
                                console.log(error.message);
                            }

                            res.render('reset-password', { user: result.rows[0] });
                        }
                    );
                } else {
                    return res.render('404');
                }
            }
        );
    } catch (error) {
        console.log(error.message);
    }
};

const resetPassword = (req, res) => {
    console.log(req.body.user_id, req.body.user_email);

    if (req.body.password != req.body.confirm_password) {
        res.render('reset-password', {
            error_message: 'Password does not match',
            user: { id: req.body.user_id, email: req.body.user_email },
        });
    } else {
        bcrypt.genSalt(10, function(err, salt) {
            bcrypt.hash(req.body.confirm_password, 10, function(err, hash) {
                if (err) {
                    console.log(err);
                } else {
                    db.query(
                        'DELETE FROM password_reset WHERE email=$1', [req.body.user_email],
                        () => {
                            db.query(
                                'UPDATE users2 SET password=$1 WHERE id=$2', [hash, req.body.user_id],
                                () => {
                                    return res.render('updateMsg', {
                                        message: 'Password reset successfully',
                                    });
                                }
                            );
                        }
                    );
                }
            });
        });
    }
};

const updateProfile = (req, res) => {
    try {
        const errors = validationResult(req);

        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const authToken = req.headers.authorization.split(' ')[1];
        const decode = jwt.verify(authToken, JWT_SECRET);

        var sql = '',
            data;

        if (req.file != undefined) {
            sql = 'UPDATE users2 SET name=$1, email=$2, image=$3 WHERE id=$4';
            data = [
                req.body.name,
                req.body.email,
                req.file.filename,
                decode.id,
            ];
        } else {
            sql = 'UPDATE users2 SET name=$1, email=$2 WHERE id=$3';
            data = [req.body.name, req.body.email, decode.id];
        }

        db.query(sql, data, (error, result) => {
            if (error) {
                res.status(400).send({ msg: error });
            }

            res.status(200).send({
                msg: 'Profile updated successfully',
            });
        });
    } catch (error) {
        return res.status(400).json({ msg: error.message });
    }
};

module.exports = {
    register,
    verifyMail,
    login,
    getUser,
    forgetPassword,
    resetPasswordLoad,
    resetPassword,
    updateProfile,
};