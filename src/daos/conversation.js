const { ObjectId } = require('mongoose').Types;
const Conversation = require('../models/conversations');
const daoUtils = require('./utils');

const createConversation = async ({ title, userId }) => {
  const conversation = await Conversation.create({ title, userId });
  return conversation;
};

// const findConversations = async (queryFields) => {
//   const { documents: conversations, total } = await daoUtils.findAll(
//     Conversation,
//     queryFields,
//   );
//   return { conversations, total };
// };

// const findConversations = async (queryFields) => {
//   const { documents: conversations, total } = await daoUtils.findAll(
//     Conversation,
//     queryFields,
//   );
//   return { conversations, total };
// };

const getConversationsByUserId = async (userId) => {
  const conversations = await Conversation.find({ userId }).lean();
  return conversations;
};



const getConversation = async (condition) => {
  if (ObjectId.isValid(condition)) {
    const conversation = await Conversation.findById(condition);
    return conversation;
  }
  if (typeof condition === 'object' && condition !== null) {
    const conversation = await Conversation.findOne(condition);
    return conversation;
  }
  return null;
};

const updateConversation = async (id, updateFields) => {
  const conversation = await Conversation.findByIdAndUpdate(id, updateFields, {
    new: true,
  });
  return conversation;
};

const deleteConversation = async (id) => {
  const conversation = await Conversation.findByIdAndDelete(id);
  return conversation;
};

module.exports = {
  createConversation,
  getConversationsByUserId,
  getConversation,
  updateConversation,
  deleteConversation,
};
