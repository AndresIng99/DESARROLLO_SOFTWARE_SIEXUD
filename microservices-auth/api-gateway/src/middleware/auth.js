const authMiddleware = (req, res, next) => {
  // Middleware básico de autenticación
  next();
};

module.exports = authMiddleware;
