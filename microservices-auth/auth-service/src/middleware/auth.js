const jwt = require('jsonwebtoken');
const { redisClient } = require('../config/redis');

const authMiddleware = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        message: 'Token de acceso requerido'
      });
    }

    const token = authHeader.split(' ')[1];

    // Verificar si está en blacklist
    const redis = redisClient();
    const blacklisted = await redis.get(lacklist:);
    if (blacklisted) {
      return res.status(401).json({
        success: false,
        message: 'Token revocado'
      });
    }

    // Verificar token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();

  } catch (error) {
    if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
      return res.status(401).json({
        success: false,
        message: 'Token inválido o expirado'
      });
    }

    console.error('Error en autenticación:', error);
    res.status(500).json({
      success: false,
      message: 'Error interno del servidor'
    });
  }
};

module.exports = authMiddleware;
