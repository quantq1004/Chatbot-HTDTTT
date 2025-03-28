const jwt = require('jsonwebtoken');
const CustomError = require('../errors/CustomError');
const errorCodes = require('../errors/code');
const camelCaseKeys = require('camelcase-keys');

const userDao = require('../daos/user');

const { generateRandomString } = require('../utils/random');
const {
  generateSalt,
  encryptPassword,
  comparePassword,
} = require('../utils/security');

const { JWT_SECRET_KEY, JWT_EXPIRES_TIME } = process.env;

// Convert JWT_SECRET_KEY from base64 to buffer
const jwtKey = Buffer.from(JWT_SECRET_KEY, 'base64');

// Generate Access Token
const generateAccessToken = async (userId, isAdmin) => {
  const accessToken = jwt.sign(
    { userId, isAdmin },
    jwtKey,
    { expiresIn: JWT_EXPIRES_TIME }
  );

  return accessToken;
};

// Register User
const register = async ({ email, name, password }) => {
  let user = await userDao.findUser({ email });
  if (user) throw new CustomError(errorCodes.USER_EXISTS);

  // Generate salt and encrypt password
  const salt = generateSalt();
  const hashedPassword = password || generateRandomString(16);
  const encryptedPassword = await encryptPassword(hashedPassword, salt);

  user = await userDao.createUser({
    email,
    name,
    password: encryptedPassword,
  });

  return user;
};

// User Login
const login = async (email, password) => {
  const user = await userDao.findUser({ email });
  if (!user) throw new CustomError(errorCodes.USER_NOT_FOUND);

  // Compare password
  const isCorrectPassword = await comparePassword(password, user.password);
  if (!isCorrectPassword) throw new CustomError(errorCodes.WRONG_PASSWORD);

  const { isAdmin = false, _id: userId } = user;
  const accessToken = await generateAccessToken(userId, isAdmin);

  return { userId, accessToken };
};

// Verify Admin Access
const verifyAdmin = (accessToken) => {
  try {
    const decoded = jwt.verify(accessToken, jwtKey);
    const { userId, isAdmin } = decoded;
    return { userId, isAdmin };
  } catch (err) {
    throw new CustomError(errorCodes.UNAUTHORIZED);
  }
};

const verifyAccessToken = async (accessToken) => {
  try {
    let data = jwt.verify(accessToken, jwtKey);
    data = camelCaseKeys(data);
    const { sub: userId } = data;

    if (!userId) throw new CustomError(codes.UNAUTHORIZED);

    return data;
  } catch (error) {
    console.error(`Failed to verify token: ${error.message}`);
    throw new CustomError(codes.UNAUTHORIZED);
  }
};

module.exports = {
  register,
  login,
  verifyAdmin,
  verifyAccessToken
};
