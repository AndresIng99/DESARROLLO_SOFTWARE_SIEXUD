// microservices-auth/shared/middleware/auth.js
const axios = require('axios');

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

    // Verificar token con el auth-service
    const response = await axios.post(
      `${process.env.AUTH_SERVICE_URL}/auth/verify-token`,
      {},
      {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        timeout: 5000
      }
    );

    if (response.data.success) {
      req.user = response.data.data.user;
      next();
    } else {
      return res.status(401).json({
        success: false,
        message: 'Token inválido'
      });
    }

  } catch (error) {
    console.error('Error en autenticación:', error.message);
    
    if (error.response?.status === 401) {
      return res.status(401).json({
        success: false,
        message: 'Token inválido o expirado'
      });
    }

    return res.status(503).json({
      success: false,
      message: 'Servicio de autenticación no disponible'
    });
  }
};

module.exports = authMiddleware;

// microservices-auth/shared/middleware/authorization.js
const requireRole = (allowedRoles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'Usuario no autenticado'
      });
    }

    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        message: 'No tienes permisos para realizar esta acción'
      });
    }

    next();
  };
};

const requirePermission = (permission) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'Usuario no autenticado'
      });
    }

    // Lógica básica de permisos por rol
    const rolePermissions = {
      admin: ['read', 'write', 'delete', 'manage_users'],
      moderator: ['read', 'write', 'moderate'],
      user: ['read']
    };

    const userPermissions = rolePermissions[req.user.role] || [];

    if (!userPermissions.includes(permission)) {
      return res.status(403).json({
        success: false,
        message: 'No tienes permisos para realizar esta acción'
      });
    }

    next();
  };
};

module.exports = {
  requireRole,
  requirePermission
};

// microservices-auth/shared/middleware/errorHandler.js
const errorHandler = (err, req, res, next) => {
  console.error('Error:', err);

  // Error de validación de Joi
  if (err.isJoi) {
    return res.status(400).json({
      success: false,
      message: 'Datos inválidos',
      errors: err.details
    });
  }

  // Error de JWT
  if (err.name === 'JsonWebTokenError') {
    return res.status(401).json({
      success: false,
      message: 'Token inválido'
    });
  }

  if (err.name === 'TokenExpiredError') {
    return res.status(401).json({
      success: false,
      message: 'Token expirado'
    });
  }

  // Error de base de datos
  if (err.code === '23505') { // Violación de restricción única
    return res.status(409).json({
      success: false,
      message: 'El recurso ya existe'
    });
  }

  if (err.code === '23503') { // Violación de clave foránea
    return res.status(400).json({
      success: false,
      message: 'Referencia inválida'
    });
  }

  // Error genérico
  res.status(500).json({
    success: false,
    message: 'Error interno del servidor'
  });
};

module.exports = errorHandler;