const { ObjectId } = require('mongoose').Types;

const updateOne = async (model, condition, updateFields) => {
  if (ObjectId.isValid(condition)) {
    const document = await model.findByIdAndUpdate(condition, updateFields, {
      new: true,
      omitUndefined: true,
    });
    return document;
  }

  if (typeof condition === 'object' && condition !== null) {
    const document = await model.findOneAndUpdate(condition, updateFields, {
      new: true,
      omitUndefined: true,
    });
    return document;
  }

  throw new Error('Passing invalid condition into updateOne');
};

module.exports = { updateOne };
