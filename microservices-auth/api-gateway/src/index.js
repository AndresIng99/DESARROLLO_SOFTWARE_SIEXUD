const express = require('express');
const cors = require('cors');
const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 3000;

// CORS para el frontend
app.use(cors({ 
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

console.log('🚀 API Gateway V2 EXPANDIDO iniciando...');

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    service: 'api-gateway-v2', 
    timestamp: new Date().toISOString(),
    version: '2.0.0'
  });
});

// =================== PROXY HELPER ===================
async function proxyRequest(req, res, targetUrl) {
  try {
    console.log(`📨 PROXY: ${req.method} ${req.originalUrl} -> ${targetUrl}`);
    
    const config = {
      method: req.method,
      url: targetUrl,
      headers: {
        'Content-Type': 'application/json',
        ...(req.headers.authorization && { 'Authorization': req.headers.authorization })
      },
      timeout: 10000
    };

    // Agregar body para POST/PUT/PATCH
    if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
      config.data = req.body;
    }

    // Agregar query parameters
    if (Object.keys(req.query).length > 0) {
      config.params = req.query;
    }

    const response = await axios(config);
    
    console.log(`✅ PROXY SUCCESS: ${response.status}`);
    
    // Para CSV, manejar respuesta especial
    if (response.headers['content-type']?.includes('text/csv')) {
      res.setHeader('Content-Type', response.headers['content-type']);
      res.setHeader('Content-Disposition', response.headers['content-disposition']);
      res.send(response.data);
    } else {
      res.status(response.status).json(response.data);
    }
    
  } catch (error) {
    console.error(`❌ PROXY ERROR: ${error.message}`);
    
    if (error.response) {
      res.status(error.response.status).json(error.response.data);
    } else {
      res.status(500).json({
        success: false,
        message: 'Error de conexión con el servicio'
      });
    }
  }
}

// =================== RUTAS DE AUTENTICACIÓN ===================

// AUTH LOGIN
app.post('/auth/login', async (req, res) => {
  await proxyRequest(req, res, 'http://auth-service:3001/auth/login');
});

// AUTH VERIFY
app.get('/auth/verify', async (req, res) => {
  await proxyRequest(req, res, 'http://auth-service:3001/auth/verify');
});

// =================== NUEVAS RUTAS DE PERFIL ===================

// PERFIL PROPIO
app.get('/auth/profile', async (req, res) => {
  await proxyRequest(req, res, 'http://auth-service:3001/auth/profile');
});

// ACTUALIZAR PERFIL PROPIO
app.put('/auth/profile', async (req, res) => {
  await proxyRequest(req, res, 'http://auth-service:3001/auth/profile');
});

// CAMBIAR CONTRASEÑA PROPIA
app.put('/auth/password', async (req, res) => {
  await proxyRequest(req, res, 'http://auth-service:3001/auth/password');
});

// =================== RUTAS DE USUARIOS (EXISTENTES) ===================

// LISTAR USUARIOS
app.get('/users', async (req, res) => {
  await proxyRequest(req, res, 'http://auth-service:3001/users');
});

// CREAR USUARIO
app.post('/users', async (req, res) => {
  await proxyRequest(req, res, 'http://auth-service:3001/users');
});

// OBTENER USUARIO POR ID
app.get('/users/:id', async (req, res) => {
  await proxyRequest(req, res, `http://auth-service:3001/users/${req.params.id}`);
});

// ACTUALIZAR USUARIO
app.put('/users/:id', async (req, res) => {
  await proxyRequest(req, res, `http://auth-service:3001/users/${req.params.id}`);
});

// ELIMINAR USUARIO
app.delete('/users/:id', async (req, res) => {
  await proxyRequest(req, res, `http://auth-service:3001/users/${req.params.id}`);
});

// =================== NUEVAS RUTAS DE USUARIOS ===================

// CAMBIAR CONTRASEÑA DE USUARIO (admin)
app.put('/users/:id/password', async (req, res) => {
  await proxyRequest(req, res, `http://auth-service:3001/users/${req.params.id}/password`);
});

// ACTIVAR/DESACTIVAR USUARIO
app.put('/users/:id/status', async (req, res) => {
  await proxyRequest(req, res, `http://auth-service:3001/users/${req.params.id}/status`);
});

// BÚSQUEDA AVANZADA DE USUARIOS
app.get('/users/search', async (req, res) => {
  await proxyRequest(req, res, 'http://auth-service:3001/users/search');
});

// EXPORTAR USUARIOS A CSV
app.get('/users/export/csv', async (req, res) => {
  await proxyRequest(req, res, 'http://auth-service:3001/users/export/csv');
});

// =================== RUTAS DE ESTADÍSTICAS ===================

// ESTADÍSTICAS GENERALES
app.get('/users/stats/overview', async (req, res) => {
  await proxyRequest(req, res, 'http://auth-service:3001/users/stats/overview');
});

// ESTADÍSTICAS DETALLADAS
app.get('/users/stats/detailed', async (req, res) => {
  await proxyRequest(req, res, 'http://auth-service:3001/users/stats/detailed');
});

// =================== MIDDLEWARE DE LOGGING ===================
app.use((req, res, next) => {
  console.log(`📍 ${req.method} ${req.originalUrl} - ${new Date().toISOString()}`);
  next();
});

// =================== ERROR HANDLER ===================
app.use((err, req, res, next) => {
  console.error('💥 Error en API Gateway:', err);
  res.status(500).json({
    success: false,
    message: 'Error interno del API Gateway'
  });
});

// =================== CATCH ALL ===================
app.use('*', (req, res) => {
  console.log(`❓ Ruta no encontrada: ${req.method} ${req.originalUrl}`);
  res.status(404).json({
    success: false,
    message: `Ruta no encontrada: ${req.method} ${req.originalUrl}`
  });
});

app.listen(PORT, () => {
  console.log('🌐 API Gateway V2 EXPANDIDO ejecutándose en puerto ' + PORT);
  console.log('📍 Rutas disponibles:');
  console.log('');
  console.log('🔐 AUTENTICACIÓN:');
  console.log('   POST   /auth/login              - Login');
  console.log('   GET    /auth/verify             - Verificar token');
  console.log('   GET    /auth/profile            - Obtener perfil propio');
  console.log('   PUT    /auth/profile            - Actualizar perfil propio');
  console.log('   PUT    /auth/password           - Cambiar contraseña propia');
  console.log('');
  console.log('👥 GESTIÓN DE USUARIOS:');
  console.log('   GET    /users                   - Listar usuarios');
  console.log('   POST   /users                   - Crear usuario');
  console.log('   GET    /users/:id               - Obtener usuario');
  console.log('   PUT    /users/:id               - Actualizar usuario');
  console.log('   DELETE /users/:id               - Eliminar usuario');
  console.log('   PUT    /users/:id/password      - Cambiar contraseña (admin)');
  console.log('   PUT    /users/:id/status        - Activar/desactivar usuario');
  console.log('   GET    /users/search            - Búsqueda avanzada');
  console.log('   GET    /users/export/csv        - Exportar a CSV');
  console.log('');
  console.log('📊 ESTADÍSTICAS:');
  console.log('   GET    /users/stats/overview    - Estadísticas generales');
  console.log('   GET    /users/stats/detailed    - Estadísticas detalladas');
  console.log('');
  console.log('🎯 Total de endpoints: 18');
});