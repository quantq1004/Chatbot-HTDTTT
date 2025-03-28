const conversationDao = require('../daos/conversation');

const createConversation = async (req, res) => {
  const { title, userId } = req.body;
  const conversation = await conversationDao.createConversation({ title, userId });
  return res.send({ conversation });
};

// const getConversations = async (req, res) => {
//   const { search, searchFields, fields, offset, limit, sort } = req.query;
//   const query = {};

//   query.query = {};
//   if (search) query.search = search;
//   if (searchFields) query.searchFields = searchFields.split(',');
//   if (fields) query.fields = fields.split(',');
//   if (offset) query.offset = parseInt(offset, 10);
//   if (limit) query.limit = parseInt(limit, 10);
//   if (sort) query.sort = sort.split(',');

//   Object.keys(req.query)
//     .filter(
//       (q) =>
//         ['search', 'searchFields', 'fields', 'offset', 'limit', 'sort'].indexOf(
//           q,
//         ) === -1,
//     )
//     .forEach((q) => {
//       query.query[q] = ['true', 'false'].includes(req.query[q])
//         ? JSON.parse(req.query[q])
//         : req.query[q];
//     });

//   const { conversations, total } = await conversationDao.findConversations(query);

//   return res.send({ conversations, total });
// };

const getConversation = async (req, res) => {
  const { id } = req.params;
  const conversation = await conversationDao.getConversation(id);
  return res.send({ conversation });
};

const updateConversation = async (req, res) => {
  const { id } = req.params;
  const updateInfo = req.body;
  const conversation = await conversationDao.updateConversation(id, updateInfo);
  return res.send({ conversation });
};

const deleteConversation = async (req, res) => {
  const { id } = req.params;
  await conversationDao.deleteConversation(id);
  return res.send({});
};

const getConversationsByUserId = async (req, res) => {
  const userId = req.userId;
  if (!userId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const conversations = await conversationDao.getConversationsByUserId(userId);
  return res.send({ conversations });
};

module.exports = {
  createConversation,
  getConversationsByUserId,
  getConversation,
  updateConversation,
  deleteConversation,
};
