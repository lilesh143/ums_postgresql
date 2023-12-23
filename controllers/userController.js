const { validationResult } = require('express-validator')
const db = require('../config/dbConnection')
const bcrypt = require('bcryptjs');
const randomstring = require('randomstring')
const sendMail = require('../helpers/sendMail');

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

            db.query(`UPDATE users SET token = null, is_verified = 1 WHERE id = '${[result][0].id}'`);
            return res.render('mail-verification', { message: 'Mail verified successfully' });


        } else {
            return res.render('404');
        }

    })

}

module.exports = {
    register,
    verifyMail
}