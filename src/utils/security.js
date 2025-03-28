const bcrypt = require('bcrypt');
const crypto = require('crypto');

const { PEPPER } = process.env;

const IV_LENGTH = 16; // IV length for AES256 (16 bytes)

// Convert PEPPER from base64 to buffer
const key = Buffer.from(PEPPER, 'base64');

// === AES256 Encryption ===
const encrypt = (text) => {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-ctr', key, iv);

  let encrypted = cipher.update(text);
  encrypted = Buffer.concat([encrypted, cipher.final()]);

  return `${iv.toString('hex')}:${encrypted.toString('hex')}`;
};

// === AES256 Decryption ===
const decrypt = (text) => {
  const textParts = text.split(':');
  const iv = Buffer.from(textParts.shift(), 'hex');
  const encryptedText = Buffer.from(textParts.join(':'), 'hex');

  const decipher = crypto.createDecipheriv('aes-256-ctr', key, iv);
  let decrypted = decipher.update(encryptedText);
  decrypted = Buffer.concat([decrypted, decipher.final()]);

  return decrypted.toString();
};

// === SHA512 Hashing ===
const hashSHA512 = (text) =>
  crypto.createHash('sha512').update(text).digest('hex');

// === Bcrypt Hashing ===
const hashBcrypt = async (text, salt) => {
  if (!text || !salt) throw new Error('Invalid text or salt');

  const hashedBcrypt = await bcrypt.hash(text, salt);
  return hashedBcrypt;
};

// === Bcrypt Comparison ===
const compareBcrypt = async (data, hashed) => {
  if (!data || !hashed) throw new Error('Invalid data or hashed value');
  
  return await bcrypt.compare(data, hashed);
};

// === Generate Salt for Bcrypt ===
const generateSalt = () => bcrypt.genSaltSync(10);

// === Encrypt Password ===
const encryptPassword = async (password, salt) => {
  if (!password || !salt) throw new Error('Invalid password or salt');

  // First, hash using SHA512
  const hashedSHA512 = hashSHA512(password);

  // Then, hash using bcrypt
  const hashedBcrypt = await hashBcrypt(hashedSHA512, salt);

  // Finally, encrypt using AES256
  return encrypt(hashedBcrypt);
};

// === Compare Password ===
const comparePassword = async (newPassword, oldPassword) => {
  if (!newPassword || !oldPassword) throw new Error('Invalid password');

  const decryptedPassword = decrypt(oldPassword); // Decrypt AES256 first
  const hashedSHA512 = hashSHA512(newPassword); // Then hash with SHA512

  return await compareBcrypt(hashedSHA512, decryptedPassword);
};

module.exports = {
  generateSalt,
  encryptPassword,
  comparePassword,
};
