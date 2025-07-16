// microservices-auth/shared/config/database.js
const { Pool } = require('pg');

let pool;

const connectDB = async () => {
  try {
    pool = new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
      max: 20,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 2000,
    });

    // Probar conexión
    await pool.query('SELECT NOW()');
    console.log('✅ Conexión a PostgreSQL establecida');
  } catch (error) {
    console.error('❌ Error conectando a PostgreSQL:', error);
    throw error;
  }
};

const query = async (text, params) => {
  const client = await pool.connect();
  try {
    const result = await client.query(text, params);
    return result;
  } finally {
    client.release();
  }
};

module.exports = {
  connectDB,
  query,
  pool
};

// microservices-auth/shared/config/redis.js
const { createClient } = require('redis');

let redisClient;

const connectRedis = async () => {
  try {
    redisClient = createClient({
      url: process.env.REDIS_URL || 'redis://localhost:6379'
    });

    redisClient.on('error', (err) => {
      console.error('❌ Redis Client Error:', err);
    });

    redisClient.on('connect', () => {
      console.log('✅ Conexión a Redis establecida');
    });

    await redisClient.connect();
  } catch (error) {
    console.error('❌ Error conectando a Redis:', error);
    throw error;
  }
};

module.exports = {
  connectRedis,
  redisClient: () => redisClient
};

// microservices-auth/shared/utils/jwt.js
const jwt = require('jsonwebtoken');

const generateAccessToken = (payload) => {
  return jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || '24h'
  });
};

const generateRefreshToken = (payload) => {
  return jwt.sign(
    { ...payload, type: 'refresh' },
    process.env.JWT_SECRET,
    { expiresIn: process.env.REFRESH_TOKEN_EXPIRES_IN || '7d' }
  );
};

const verifyToken = (token) => {
  return jwt.verify(token, process.env.JWT_SECRET);
};

const decodeToken = (token) => {
  return jwt.decode(token);
};

module.exports = {
  generateAccessToken,
  generateRefreshToken,
  verifyToken,
  decodeToken
};