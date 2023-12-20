const { check } = require("express-validator");

exports.signUpValidator = [
    check('name', 'Name is require').not().isEmpty(),
    check('email', 'Please enter valid email').isEmail().normalizeEmail({ gmail_remove_dots: true }),
    check('password', 'Password is required').isLength({ min: 6 })
]