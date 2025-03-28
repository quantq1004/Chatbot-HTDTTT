const { ObjectId } = require('mongoose').Types;

const { getSelectQuery } = require('./util');

const findOne = async (model, condition, fields) => {
  if (ObjectId.isValid(condition)) {
    const document = await model
      .findById(condition)
      .select(fields ? getSelectQuery(fields) : {});
    return document;
  }

  if (typeof condition === 'object' && condition !== null) {
    const document = await model
      .findOne(condition)
      .select(fields ? getSelectQuery(fields) : {});
    return document;
  }

  throw new Error('Passing invalid condition into findOne');
};

module.exports = { findOne };
