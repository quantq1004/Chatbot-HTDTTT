const router = require('express').Router();
const asyncMiddleware = require('../middlewares/async');
const chatController = require('../controllers/chat');
const { requireAdmin } = require('../middlewares/verifyAdmin');
const { auth } = require('../middlewares/auth');

/* eslint-disable prettier/prettier */
router.post('/chats', auth, requireAdmin, asyncMiddleware(chatController.createChat));
router.get('/chats', auth, asyncMiddleware(chatController.getChats));
router.get('/chats/:id', auth, asyncMiddleware(chatController.getChat));
router.put('/chats/:id', auth, requireAdmin, asyncMiddleware(chatController.updateChat));
router.delete('/chats/:id', auth, requireAdmin, asyncMiddleware(chatController.deleteChat));
/* eslint-enable prettier/prettier */

module.exports = router;
