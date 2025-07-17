const express = require('express');
const cors = require('cors');
const axios = require('axios');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

console.log('🚀 API Gateway V2 EXPANDIDO iniciando...');

// =================== DEBUGGING DE PATHS ===================
const currentDir = __dirname;
const frontendPath = path.join(__dirname, '../../frontend');
const frontendPath2 = path.join(__dirname, '../frontend');
const frontendPath3 = '/app/frontend';

console.log('🔍 Debugging paths:');
console.log('   __dirname:', currentDir);
console.log('   Intentando path 1:', frontendPath);
console.log('   Intentando path 2:', frontendPath2);
console.log('   Intentando path 3:', frontendPath3);

// Verificar qué path existe
let validFrontendPath = null;
if (fs.existsSync(frontendPath)) {
  validFrontendPath = frontendPath;
  console.log('✅ Encontrado frontend en:', frontendPath);
} else if (fs.existsSync(frontendPath2)) {
  validFrontendPath = frontendPath2;
  console.log('✅ Encontrado frontend en:', frontendPath2);
} else if (fs.existsSync(frontendPath3)) {
  validFrontendPath = frontendPath3;
  console.log('✅ Encontrado frontend en:', frontendPath3);
} else {
  console.log('❌ No se encontró carpeta frontend en ningún path');
  console.log('📁 Contenido de __dirname:', fs.readdirSync(__dirname));
  console.log('📁 Contenido de proyecto:', fs.readdirSync(path.join(__dirname, '../..')));
}

// =================== CONFIGURACIÓN BÁSICA ===================

// CORS para el frontend
app.use(cors({ 
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

// =================== SERVIR ARCHIVOS ESTÁTICOS ===================

if (validFrontendPath) {
  // Servir archivos estáticos del frontend
  app.use('/frontend', express.static(validFrontendPath));
  console.log(`📁 Sirviendo archivos estáticos desde: ${validFrontendPath}`);
  
  // Listar archivos disponibles
  try {
    const files = fs.readdirSync(validFrontendPath);
    console.log('📄 Archivos frontend disponibles:', files);
  } catch (err) {
    console.log('❌ Error listando archivos:', err.message);
  }
} else {
  console.log('⚠️ Frontend no configurado - archivos estáticos no disponibles');
}

// Ruta raíz que redirecciona al login
app.get('/', (req, res) => {
  console.log('📍 Redireccionando a login...');
  if (validFrontendPath) {
    res.redirect('/frontend/index.html');
  } else {
    res.json({
      message: 'API Gateway funcionando',
      frontend: 'No disponible - verifique configuración',
      api: 'Disponible',
      endpoints: {
        login: 'POST /auth/login',
        health: 'GET /health'
      }
    });
  }
});

// RUTA ALTERNATIVA: Servir index.html directamente
app.get('/frontend/index.html', (req, res) => {
  if (validFrontendPath) {
    const indexPath = path.join(validFrontendPath, 'index.html');
    if (fs.existsSync(indexPath)) {
      console.log('✅ Sirviendo index.html desde:', indexPath);
      res.sendFile(indexPath);
    } else {
      console.log('❌ index.html no encontrado en:', indexPath);
      res.status(404).json({
        success: false,
        message: 'index.html no encontrado',
        searchedPath: indexPath
      });
    }
  } else {
    res.status(404).json({
      success: false,
      message: 'Frontend no configurado correctamente'
    });
  }
});

// RUTA ALTERNATIVA: Servir dashboard.html directamente
app.get('/frontend/dashboard.html', (req, res) => {
  if (validFrontendPath) {
    const dashboardPath = path.join(validFrontendPath, 'dashboard.html');
    if (fs.existsSync(dashboardPath)) {
      console.log('✅ Sirviendo dashboard.html desde:', dashboardPath);
      res.sendFile(dashboardPath);
    } else {
      console.log('❌ dashboard.html no encontrado en:', dashboardPath);
      res.status(404).json({
        success: false,
        message: 'dashboard.html no encontrado',
        searchedPath: dashboardPath
      });
    }
  } else {
    res.status(404).json({
      success: false,
      message: 'Frontend no configurado correctamente'
    });
  }
});

// RUTA ALTERNATIVA: Servir profile.html directamente
app.get('/frontend/profile.html', (req, res) => {
  if (validFrontendPath) {
    const profilePath = path.join(validFrontendPath, 'profile.html');
    if (fs.existsSync(profilePath)) {
      console.log('✅ Sirviendo profile.html desde:', profilePath);
      res.sendFile(profilePath);
    } else {
      console.log('❌ profile.html no encontrado en:', profilePath);
      res.status(404).json({
        success: false,
        message: 'profile.html no encontrado',
        searchedPath: profilePath
      });
    }
  } else {
    res.status(404).json({
      success: false,
      message: 'Frontend no configurado correctamente'
    });
  }
});

// RUTA ALTERNATIVA: Servir demo-complete.html directamente
app.get('/frontend/demo-complete.html', (req, res) => {
  if (validFrontendPath) {
    const demoPath = path.join(validFrontendPath, 'demo-complete.html');
    if (fs.existsSync(demoPath)) {
      console.log('✅ Sirviendo demo-complete.html desde:', demoPath);
      res.sendFile(demoPath);
    } else {
      console.log('❌ demo-complete.html no encontrado en:', demoPath);
      res.status(404).json({
        success: false,
        message: 'demo-complete.html no encontrado',
        searchedPath: demoPath
      });
    }
  } else {
    res.status(404).json({
      success: false,
      message: 'Frontend no configurado correctamente'
    });
  }
});

// Health check del API Gateway
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    service: 'api-gateway-v2', 
    timestamp: new Date().toISOString(),
    version: '2.0.0',
    frontend: validFrontendPath ? 'enabled' : 'disabled',
    frontendPath: validFrontendPath
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
        message: 'Error de conexión con el servicio',
        service: targetUrl
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

// Verificar permisos
app.post('/auth/check-permission', async (req, res) => {
  await proxyRequest(req, res, 'http://auth-service:3001/auth/check-permission');
});

// Health check para microservicios
app.get('/auth/microservice-health', async (req, res) => {
  await proxyRequest(req, res, 'http://auth-service:3001/auth/microservice-health');
});

// =================== RUTAS DE USUARIOS ===================

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

// =================== HELLO SERVICE ROUTES ===================

// Hello Service - Rutas públicas
app.get('/hello', async (req, res) => {
  await proxyRequest(req, res, 'http://hello-service:3010/hello');
});

app.get('/hello/health', async (req, res) => {
  await proxyRequest(req, res, 'http://hello-service:3010/health');
});

// Hello Service - Rutas privadas
app.get('/hello/private', async (req, res) => {
  await proxyRequest(req, res, 'http://hello-service:3010/hello/private');
});

app.get('/hello/admin', async (req, res) => {
  await proxyRequest(req, res, 'http://hello-service:3010/hello/admin');
});

app.get('/whoami', async (req, res) => {
  await proxyRequest(req, res, 'http://hello-service:3010/whoami');
});

// =================== MIDDLEWARE DE LOGGING ===================

app.use((req, res, next) => {
  // Solo loggear APIs, no archivos estáticos
  if (!req.originalUrl.startsWith('/frontend/')) {
    console.log(`📍 ${req.method} ${req.originalUrl} - ${new Date().toISOString()}`);
  }
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

// =================== CATCH ALL PARA RUTAS NO ENCONTRADAS ===================

app.use('*', (req, res) => {
  // No loggear 404s de archivos estáticos comunes
  if (!req.originalUrl.includes('.ico') && !req.originalUrl.includes('.map')) {
    console.log(`❓ Ruta no encontrada: ${req.method} ${req.originalUrl}`);
  }
  
  res.status(404).json({
    success: false,
    message: `Ruta no encontrada: ${req.method} ${req.originalUrl}`,
    frontendConfigured: validFrontendPath ? true : false,
    frontendPath: validFrontendPath,
    availableRoutes: {
      frontend: validFrontendPath ? [
        'GET /',
        'GET /frontend/index.html',
        'GET /frontend/dashboard.html',
        'GET /frontend/profile.html',
        'GET /frontend/demo-complete.html'
      ] : ['Frontend no configurado'],
      auth: [
        'POST /auth/login',
        'GET /auth/verify',
        'GET /auth/profile',
        'PUT /auth/profile',
        'PUT /auth/password'
      ],
      users: [
        'GET /users',
        'POST /users',
        'GET /users/:id',
        'PUT /users/:id',
        'DELETE /users/:id'
      ],
      hello: [
        'GET /hello',
        'GET /hello/private',
        'GET /hello/admin',
        'GET /whoami'
      ]
    }
  });
});

// =================== INICIAR SERVIDOR ===================

app.listen(PORT, () => {
  console.log('🌐 API Gateway V2 COMPLETO ejecutándose en puerto ' + PORT);
  console.log('');
  if (validFrontendPath) {
    console.log('🏠 FRONTEND DISPONIBLE:');
    console.log(`   http://localhost:${PORT}/                        - Home (redirecciona a login)`);
    console.log(`   http://localhost:${PORT}/frontend/index.html     - 🔐 Página de login`);
    console.log(`   http://localhost:${PORT}/frontend/dashboard.html - 📊 Dashboard principal`);
    console.log(`   http://localhost:${PORT}/frontend/profile.html   - 👤 Perfil de usuario`);
    console.log(`   http://localhost:${PORT}/frontend/demo-complete.html - 🧪 Demo completo`);
  } else {
    console.log('⚠️ FRONTEND NO DISPONIBLE - Verificar configuración de Docker');
  }
  console.log('');
  console.log('🔗 APIs DISPONIBLES:');
  console.log('   🔐 AUTENTICACIÓN: POST /auth/login, GET /auth/verify, etc.');
  console.log('   👥 USUARIOS: GET /users, POST /users, etc.');
  console.log('   👋 HELLO SERVICE: GET /hello, GET /hello/private, etc.');
  console.log('   📊 ESTADÍSTICAS: GET /users/stats/overview');
  console.log('');
  console.log('🚀 Sistema listo para usar!');
  console.log(`🎯 Comenzar en: http://localhost:${PORT}/`);
});