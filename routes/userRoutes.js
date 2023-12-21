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


const { signUpValidator } = require('../helpers/validation');
const userController = require('../controllers/userController')


router.post('/register', upload.single('image'), signUpValidator, userController.register);

module.exports = router;