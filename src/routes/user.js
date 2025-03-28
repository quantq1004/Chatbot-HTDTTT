const router = require('express').Router();
const asyncMiddleware = require('../middlewares/async');
const {
  loginValidate,
  registerValidate,
  updateUserValidate,
} = require('../validations/user');
const userController = require('../controllers/user');
const { requireAdmin } = require('../middlewares/verifyAdmin');

/* eslint-disable prettier/prettier */
router.post('/users/register', registerValidate, asyncMiddleware(userController.register));
router.post('/users/login', loginValidate, asyncMiddleware(userController.login));
router.get('/users/:id', asyncMiddleware(userController.getUserById));
router.put('/users/:id', updateUserValidate, asyncMiddleware(userController.updateUser));
router.get('/users', requireAdmin, asyncMiddleware(userController.getUsers));
/* eslint-enable prettier/prettier */

module.exports = router;
