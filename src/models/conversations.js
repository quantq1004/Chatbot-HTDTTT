const mongoose = require('mongoose');

const { ObjectId } = mongoose.Schema.Types;

const conversationSchema = mongoose.Schema({
  title: { type: String, required: true },
  userId: { type: ObjectId, ref: 'User', required: true },
  },
  {
    timestamps: true,
  },
);

module.exports = mongoose.model('Conversation', conversationSchema);
