const router = require('express').Router();
const asyncMiddleware = require('../middlewares/async');
const conversationController = require('../controllers/conversation');
const { requireAdmin } = require('../middlewares/verifyAdmin');
const { auth } = require('../middlewares/auth');

/* eslint-disable prettier/prettier */
router.post('/conversations', auth, requireAdmin, asyncMiddleware(conversationController.createConversation));
router.get('/conversations', auth, asyncMiddleware(conversationController.getConversations));
router.get('/conversation/:id', auth, asyncMiddleware(conversationController.getConversation));
router.put('/conversation/:id', auth, requireAdmin, asyncMiddleware(conversationController.updateConversation));
router.delete('/conversation/:id', auth, requireAdmin, asyncMiddleware(conversationController.deleteConversation));
/* eslint-enable prettier/prettier */

module.exports = router;
