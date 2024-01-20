const express = require('express');
const router = express.Router();

const path = require('path');
const multer = require('multer');

const storage = multer.diskStorage({
    destination: function(req, file, cb) {
        cb(null, path.join(__dirname, '../public/images/'))
    },
    filename: function(req, file, cb) {
        const name = Date.now() + '-' + file.originalname;
        cb(null, name)
    }
})

const filefilter = (req, file, cb) => {
    (file.mimetype == 'image/jpeg' || file.mimetype == 'image/png') ? cb(null, true): cb(null, false)
}

const upload = multer({
    storage: storage,
    fileFilter: filefilter
});


const { signUpValidator, loginValidator, forgetValidator, updateValidator } = require('../helpers/validation');
const userController = require('../controllers/userController')
const auth = require('../middleware/auth')



router.post('/register', upload.single('image'), signUpValidator, userController.register);
router.post('/login', loginValidator, userController.login);
router.get('/get-user', auth.isAuthorize, userController.getUser);
router.post('/forget-password', forgetValidator, userController.forgetPassword)

router.post('/update-profile', upload.single('image'), updateValidator, auth.isAuthorize, userController.updateProfile)

module.exports = router;