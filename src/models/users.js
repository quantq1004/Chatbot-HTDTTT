const mongoose = require('mongoose');

const userSchema = new mongoose.Schema(
  {
    email: { type: String, required: true },
    password: { type: String, required: true },
    name: { type: String, required: true },
    isAdmin: { type: Boolean, required: true, default: true },
  },
  {
    timestamps: true,
  },
);

module.exports = mongoose.model('User', userSchema);
