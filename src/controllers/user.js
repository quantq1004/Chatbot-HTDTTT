const authService = require('../services/user');
const userDao = require('../daos/user');

const register = async (req, res) => {
  const { email, name, password } = req.body;
  const user = await authService.register({ email, name, password });
  return res.send({
    user: { email: user.email, name: user.name },
  });
};

const login = async (req, res) => {
  const { email, password } = req.body;
  const { userId, accessToken } = await authService.login(email, password);
  return res.send({ user: { userId, accessToken } });
};

const getUserById = async (req, res) => {
  const { id } = req.params;
  let user = await userDao.getUserById(id);
  if (user.toObject) user = user.toObject();
  delete user.password;
  return res.send({ user });
};

const updateUser = async (req, res) => {
  const { id } = req.params;
  const updateFields = req.body;
  let user = await userDao.updateUser(id, updateFields);
  if (user.toObject) user = user.toObject();
  delete user.password;
  return res.send({ user });
};

const getUsers = async (req, res) => {
  const { search, searchFields, fields, offset, limit, sort } = req.query;
  const query = {};

  query.query = {};
  if (search) query.search = search;
  if (searchFields) query.searchFields = searchFields.split(',');
  if (fields) query.fields = fields.split(',');
  if (offset) query.offset = parseInt(offset, 10);
  if (limit) query.limit = parseInt(limit, 10);
  if (sort) query.sort = sort.split(',');

  Object.keys(req.query)
    .filter(
      (q) =>
        ['search', 'searchFields', 'fields', 'offset', 'limit', 'sort'].indexOf(
          q,
        ) === -1,
    )
    .forEach((q) => {
      query.query[q] = ['true', 'false'].includes(req.query[q])
        ? JSON.parse(req.query[q])
        : req.query[q];
    });
  const { users, total } = await userDao.findUsers(query);

  // Remove the password field from each user object
  const sanitizedUsers = users.map((user) => {
    const { password, ...rest } = user;
    return rest;
  });

  return res.send({ users: sanitizedUsers, total });
};

module.exports = { register, login, getUserById, updateUser, getUsers };
