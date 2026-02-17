require('dotenv').config();

const isProd = process.env.NODE_ENV === 'production';

const config = {
  port: parseInt(process.env.PORT || '5000', 10),
  nodeEnv: process.env.NODE_ENV || 'development',
  mongodbUri: process.env.MONGODB_URI,
  jwtSecret: process.env.JWT_SECRET,
  jwtExpiresIn: process.env.JWT_EXPIRES_IN || '24h',
};

if (isProd && !config.jwtSecret) {
  throw new Error('JWT_SECRET is required in production. Set it in environment.');
}

if (!config.jwtSecret) {
  config.jwtSecret = 'house_construction_secret_key_2024'; // dev fallback only
}

module.exports = config;
