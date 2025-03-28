const { findOne } = require('./findOne');

const checkExists = async (model, condition) => {
  const document = await findOne(model, condition);
  return !!document;
};

module.exports = { checkExists };
