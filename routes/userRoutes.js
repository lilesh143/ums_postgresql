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


const { signUpValidator, loginValidator } = require('../helpers/validation');
const userController = require('../controllers/userController')
const { isAuthorize } = require('../middleware/auth')



router.post('/register', upload.single('image'), signUpValidator, userController.register);
router.post('/login', loginValidator, userController.login);
router.get('/get-user', isAuthorize, userController.getUser)

module.exports = router;