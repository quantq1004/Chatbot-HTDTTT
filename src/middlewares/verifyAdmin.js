const authService = require('../services/user');

const requireAdmin = (req, res, next) => {
  const accessToken = req.headers.authorization.split(' ')[1];
  const { isAdmin } = authService.verifyAdmin(accessToken);
  if (!isAdmin) {
    return res.send({ status: 0, message: 'Unauthorized' });
  }
  return next();
};

module.exports = { requireAdmin };
