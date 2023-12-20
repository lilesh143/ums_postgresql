const express = require('express');
const router = express.Router();
const { signUpValidator } = require('../helpers/validation');
const userController = require('../controllers/userController')


router.post('/register', signUpValidator, userController.register);

module.exports = router;