const { Joi, validate } = require('express-validation');

const login = {
  body: Joi.object({
    email: Joi.string().email().trim().lowercase().required(),
    password: Joi.string().trim().required(),
  }),
};

const register = {
  body: Joi.object({
    email: Joi.string().email().trim().lowercase().required(),
    name: Joi.string().trim().required(),
    password: Joi.string().trim(),
  }),
};

const updateUser = {
  body: Joi.object({
    email: Joi.string().email().trim().lowercase().optional(),
    name: Joi.string().trim().optional(),
    password: Joi.string().trim().optional,
  }),
};

module.exports = {
  loginValidate: validate(login, { keyByField: true }),
  registerValidate: validate(register, { keyByField: true }),
  updateUserValidate: validate(updateUser, { keyByField: true }),
};
