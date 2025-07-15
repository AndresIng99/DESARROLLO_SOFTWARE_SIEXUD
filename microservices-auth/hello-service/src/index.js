const express = require('express');
const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 3010;

app.use(express.json());

console.log('👋 Hello Service iniciando...');

// Middleware súper básico de autenticación
const simpleAuth = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({
        success: false,
        message: '❌ Token requerido'
      });
    }

    // Verificar con tu Auth Service
    const response = await axios.get('http://auth-service:3001/auth/verify', {
      headers: { Authorization: `Bearer ${token}` }
    });

    if (response.data.success) {
      req.user = response.data.data.user;
      console.log(`✅ Usuario autenticado: ${req.user.email} (${req.user.role})`);
      next();
    } else {
      return res.status(401).json({
        success: false,
        message: '❌ Token inválido'
      });
    }

  } catch (error) {
    console.error('❌ Error de autenticación:', error.message);
    return res.status(401).json({
      success: false,
      message: '❌ Error verificando token'
    });
  }
};

// =================== RUTAS SÚPER BÁSICAS ===================

// Health check (sin autenticación)
app.get('/health', (req, res) => {
  res.json({
    success: true,
    service: 'hello-service',
    status: 'OK',
    message: '👋 Hello Service funcionando'
  });
});

// Saludo público (sin autenticación)
app.get('/hello', (req, res) => {
  res.json({
    success: true,
    message: '👋 ¡Hola mundo! (público)',
    timestamp: new Date().toISOString()
  });
});

// Saludo privado (requiere login)
app.get('/hello/private', simpleAuth, (req, res) => {
  res.json({
    success: true,
    message: `👋 ¡Hola ${req.user.firstName}! (privado)`,
    user: {
      email: req.user.email,
      role: req.user.role,
      name: `${req.user.firstName} ${req.user.lastName}`
    },
    timestamp: new Date().toISOString()
  });
});

// Solo admins (requiere login + permiso)
app.get('/hello/admin', simpleAuth, async (req, res) => {
  try {
    // Verificar si es admin
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: '❌ Solo administradores'
      });
    }

    res.json({
      success: true,
      message: `👑 ¡Hola Admin ${req.user.firstName}!`,
      adminInfo: {
        email: req.user.email,
        role: req.user.role,
        specialMessage: '🎉 Tienes acceso total'
      },
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: '❌ Error verificando permisos de admin'
    });
  }
});

// Información del usuario actual
app.get('/whoami', simpleAuth, (req, res) => {
  res.json({
    success: true,
    message: '🔍 Tu información:',
    user: {
      id: req.user.id,
      email: req.user.email,
      firstName: req.user.firstName,
      lastName: req.user.lastName,
      role: req.user.role,
      isActive: req.user.isActive
    },
    timestamp: new Date().toISOString()
  });
});

// =================== INICIAR SERVIDOR ===================

app.listen(PORT, () => {
  console.log(`👋 Hello Service ejecutándose en puerto ${PORT}`);
  console.log('📍 Rutas disponibles:');
  console.log('   GET /health              - Health check (público)');
  console.log('   GET /hello               - Saludo público');
  console.log('   GET /hello/private       - Saludo privado (requiere login)');
  console.log('   GET /hello/admin         - Solo admins (requiere login + admin)');
  console.log('   GET /whoami              - Tu información (requiere login)');
});