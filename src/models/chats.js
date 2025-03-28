const mongoose = require('mongoose');

const { ObjectId } = mongoose.Schema.Types;

const chatSchema = mongoose.Schema({
  userPrompt: { type: String, required: true },
  aiResponse: { type: String, required: true },
  conversationId: { type: ObjectId, ref: 'Conversation', required: true },
  },
  {
    timestamps: true,
  },
);

module.exports = mongoose.model('Chat', chatSchema);
