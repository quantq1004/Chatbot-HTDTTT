const { ObjectId } = require('mongoose').Types;
const User = require('../models/users');
const daoUtils = require('./utils');

const createUser = async ({ email, name, password }) => {
  const user = await User.create({ email, name, password });
  return user;
};

const findUser = async (condition) => {
  if (ObjectId.isValid(condition)) {
    const user = await User.findById(condition);
    return user;
  }

  if (typeof condition === 'object' && condition !== null) {
    const user = await User.findOne(condition);
    return user;
  }

  return null;
};

const getUserById = async (id) => {
  const user = await User.findById(id);
  return user;
};

const updateUser = async (id, updateFields) => {
  const user = await User.findByIdAndUpdate(id, updateFields, {
    new: true,
  });
  return user;
};

const findUsers = async (queryFields) => {
  const { documents: users, total } = await daoUtils.findAll(User, queryFields);
  return { users, total };
};

module.exports = { createUser, findUser, getUserById, updateUser, findUsers };
