const { check } = require("express-validator");

exports.signUpValidator = [
    check('name', 'Name is require').not().isEmpty(),
    check('email', 'Please enter valid email').isEmail().normalizeEmail({ gmail_remove_dots: true }),
    check('password', 'Password is required').isLength({ min: 6 }),
    check('image').custom((value, { req }) => {
        if (req.file.mimetype == 'image/jpeg' || req.file.mimetype == 'image/png') {
            return true;
        } else {
            return false;
        }
    }).withMessage('Please upload an image type PNG, JPEG')
]


exports.loginValidator = [
    check('email', 'Please enter valid email').isEmail().normalizeEmail({ gmail_remove_dots: true }),
    check('password', 'Password min 6 length').isLength({ min: 6 }),
]

exports.forgetValidator = [
    check('email', 'Please enter correct email').isEmail().normalizeEmail({ gmail_remove_dots: true }),
]

exports.updateValidator = [
    check('name', 'Name is require').not().isEmpty(),
    check('email', 'Please enter valid email').isEmail().normalizeEmail({ gmail_remove_dots: true }),

]