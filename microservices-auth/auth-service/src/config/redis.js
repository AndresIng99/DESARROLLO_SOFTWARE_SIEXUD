const { createClient } = require('redis');

let redisClient;

const connectRedis = async () => {
  try {
    redisClient = createClient({
      url: process.env.REDIS_URL || 'redis://redis:6379'
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
