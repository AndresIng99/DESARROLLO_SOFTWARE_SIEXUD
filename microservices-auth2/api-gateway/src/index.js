// microservices-auth/api-gateway/src/index.js
// API GATEWAY COMPLETO CON ROLES, PERMISOS Y FRONTEND INTEGRADO

const express = require('express');
const cors = require('cors');
const axios = require('axios');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

console.log('🚀 API GATEWAY COMPLETO V3.0 iniciando...');

// =================== CONFIGURACIÓN DE PATHS ===================
const frontendPath = path.join(__dirname, '../../frontend');
let validFrontendPath = null;

console.log('🔍 Verificando frontend path:', frontendPath);
if (fs.existsSync(frontendPath)) {
  validFrontendPath = frontendPath;
  console.log('✅ Frontend encontrado en:', frontendPath);
  
  try {
    const files = fs.readdirSync(frontendPath);
    console.log('📄 Archivos frontend disponibles:', files);
  } catch (err) {
    console.log('❌ Error listando archivos:', err.message);
  }
} else {
  console.log('❌ Frontend no encontrado en:', frontendPath);
}

// =================== CONFIGURACIÓN BÁSICA ===================

app.use(cors({ 
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// =================== SERVIR ARCHIVOS ESTÁTICOS ===================

if (validFrontendPath) {
  app.use('/frontend', express.static(validFrontendPath));
  console.log(`📁 Sirviendo archivos estáticos desde: ${validFrontendPath}`);
} else {
  console.log('⚠️ Frontend no configurado - archivos estáticos no disponibles');
}

// =================== RUTAS PRINCIPALES ===================

// Ruta raíz que redirecciona al login
app.get('/', (req, res) => {
  console.log('📍 Acceso a raíz - redireccionando...');
  if (validFrontendPath) {
    res.redirect('/frontend/index.html');
  } else {
    res.json({
      success: true,
      message: '🚀 API Gateway Completo V3.0',
      features: [
        'Authentication & Authorization',
        'Role & Permission Management', 
        'User Management',
        'Frontend Integration',
        'Microservices Proxy'
      ],
      endpoints: {
        frontend: validFrontendPath ? 'Disponible en /frontend/' : 'No configurado',
        auth: 'POST /auth/login, GET /auth/verify',
        users: 'GET /users, POST /users',
        roles: 'GET /roles, POST /roles',
        health: 'GET /health'
      }
    });
  }
});

// Health check del API Gateway
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    service: 'api-gateway-complete', 
    timestamp: new Date().toISOString(),
    version: '3.0.0',
    features: {
      frontend: validFrontendPath ? 'enabled' : 'disabled',
      authentication: 'enabled',
      authorization: 'enabled',
      roleManagement: 'enabled',
      permissionManagement: 'enabled',
      userManagement: 'enabled',
      audit: 'enabled'
    },
    frontendPath: validFrontendPath
  });
});

// =================== FUNCIÓN PROXY MEJORADA ===================

async function proxyRequest(req, res, targetUrl, options = {}) {
  try {
    console.log(`📨 PROXY: ${req.method} ${req.originalUrl} -> ${targetUrl}`);
    
    const config = {
      method: req.method,
      url: targetUrl,
      headers: {
        'Content-Type': 'application/json',
        ...(req.headers.authorization && { 'Authorization': req.headers.authorization }),
        ...(options.headers || {})
      },
      timeout: 15000, // Aumentar timeout
      validateStatus: (status) => status < 500 // No lanzar error para códigos 4xx
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
    
    console.log(`✅ PROXY SUCCESS: ${response.status} - ${targetUrl}`);
    
    // Manejar respuestas especiales (CSV, archivos, etc.)
    if (response.headers['content-type']?.includes('text/csv')) {
      res.setHeader('Content-Type', response.headers['content-type']);
      res.setHeader('Content-Disposition', response.headers['content-disposition']);
      res.send(response.data);
    } else {
      res.status(response.status).json(response.data);
    }
    
  } catch (error) {
    console.error(`❌ PROXY ERROR: ${error.message} - ${targetUrl}`);
    
    if (error.response) {
      // Error del servidor de destino
      res.status(error.response.status).json(error.response.data);
    } else if (error.code === 'ECONNREFUSED') {
      // Servicio no disponible
      res.status(503).json({
        success: false,
        message: `Servicio no disponible: ${targetUrl}`,
        error: 'SERVICE_UNAVAILABLE',
        retry: true
      });
    } else if (error.code === 'ETIMEDOUT') {
      // Timeout
      res.status(504).json({
        success: false,
        message: 'Timeout del servicio',
        error: 'GATEWAY_TIMEOUT'
      });
    } else {
      // Error genérico
      res.status(500).json({
        success: false,
        message: 'Error de conexión con el servicio',
        service: targetUrl,
        error: error.message
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

// VERIFICAR PERMISOS
app.post('/auth/check-permission', async (req, res) => {
  await proxyRequest(req, res, 'http://auth-service:3001/auth/check-permission');
});

// HEALTH CHECK PARA MICROSERVICIOS
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

// ESTADÍSTICAS DE USUARIOS
app.get('/users/stats/overview', async (req, res) => {
  await proxyRequest(req, res, 'http://auth-service:3001/users/stats/overview');
});

// =================== RUTAS DE ROLES ===================

// LISTAR ROLES
app.get('/roles', async (req, res) => {
  await proxyRequest(req, res, 'http://auth-service:3001/roles');
});

// CREAR ROL
app.post('/roles', async (req, res) => {
  await proxyRequest(req, res, 'http://auth-service:3001/roles');
});

// OBTENER ROL POR ID
app.get('/roles/:id', async (req, res) => {
  await proxyRequest(req, res, `http://auth-service:3001/roles/${req.params.id}`);
});

// ACTUALIZAR ROL
app.put('/roles/:id', async (req, res) => {
  await proxyRequest(req, res, `http://auth-service:3001/roles/${req.params.id}`);
});

// ELIMINAR ROL
app.delete('/roles/:id', async (req, res) => {
  await proxyRequest(req, res, `http://auth-service:3001/roles/${req.params.id}`);
});

// CLONAR ROL
app.post('/roles/:id/clone', async (req, res) => {
  await proxyRequest(req, res, `http://auth-service:3001/roles/${req.params.id}/clone`);
});

// =================== RUTAS DE PERMISOS ===================

// LISTAR PERMISOS
app.get('/roles/permissions/all', async (req, res) => {
  await proxyRequest(req, res, 'http://auth-service:3001/roles/permissions/all');
});

// CREAR PERMISO
app.post('/roles/permissions', async (req, res) => {
  await proxyRequest(req, res, 'http://auth-service:3001/roles/permissions');
});

// =================== RUTAS DE ASIGNACIONES ===================

// ASIGNAR ROL A USUARIO
app.post('/roles/assign-user', async (req, res) => {
  await proxyRequest(req, res, 'http://auth-service:3001/roles/assign-user');
});

// =================== RUTAS DE ESTADÍSTICAS Y AUDITORÍA ===================

// ESTADÍSTICAS DE ROLES
app.get('/roles/stats/overview', async (req, res) => {
  await proxyRequest(req, res, 'http://auth-service:3001/roles/stats/overview');
});

// AUDITORÍA DE CAMBIOS
app.get('/roles/audit/changes', async (req, res) => {
  await proxyRequest(req, res, 'http://auth-service:3001/roles/audit/changes');
});

// =================== HELLO SERVICE (EJEMPLO) ===================

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

// =================== RUTAS DIRECTAS DE FRONTEND ===================

// Servir páginas HTML específicas
const frontendPages = [
  'index.html',
  'dashboard.html', 
  'profile.html',
  'roles.html',
  'demo-complete.html'
];

frontendPages.forEach(page => {
  app.get(`/frontend/${page}`, (req, res) => {
    if (validFrontendPath) {
      const filePath = path.join(validFrontendPath, page);
      if (fs.existsSync(filePath)) {
        console.log(`✅ Sirviendo ${page} desde:`, filePath);
        res.sendFile(filePath);
      } else {
        console.log(`❌ ${page} no encontrado en:`, filePath);
        res.status(404).json({
          success: false,
          message: `${page} no encontrado`,
          searchedPath: filePath
        });
      }
    } else {
      res.status(404).json({
        success: false,
        message: 'Frontend no configurado correctamente'
      });
    }
  });
});

// =================== RUTAS DE DIAGNÓSTICO ===================

// Verificar estado de todos los servicios
app.get('/system/health', async (req, res) => {
  const services = [
    { name: 'API Gateway', url: `http://localhost:${PORT}/health`, status: 'OK' },
    { name: 'Auth Service', url: 'http://auth-service:3001/health' },
    { name: 'Hello Service', url: 'http://hello-service:3010/health' }
  ];

  const healthChecks = await Promise.allSettled(
    services.slice(1).map(async service => {
      try {
        const response = await axios.get(service.url, { timeout: 5000 });
        return {
          ...service,
          status: response.data.status || 'OK',
          responseTime: Date.now()
        };
      } catch (error) {
        return {
          ...service,
          status: 'ERROR',
          error: error.message
        };
      }
    })
  );

  const results = [
    services[0], // API Gateway (siempre OK)
    ...healthChecks.map((result, index) => 
      result.status === 'fulfilled' ? result.value : { 
        ...services[index + 1], 
        status: 'ERROR', 
        error: result.reason?.message || 'Unknown error'
      }
    )
  ];

  const allHealthy = results.every(service => service.status === 'OK');

  res.status(allHealthy ? 200 : 503).json({
    success: allHealthy,
    system: 'Microservices Auth System',
    timestamp: new Date().toISOString(),
    services: results,
    summary: {
      total: results.length,
      healthy: results.filter(s => s.status === 'OK').length,
      unhealthy: results.filter(s => s.status === 'ERROR').length
    }
  });
});

// Información del sistema
app.get('/system/info', (req, res) => {
  res.json({
    success: true,
    system: {
      name: 'Microservices Auth System',
      version: '3.0.0',
      environment: process.env.NODE_ENV || 'development',
      apiGateway: {
        version: '3.0.0',
        port: PORT,
        features: [
          'authentication',
          'authorization',
          'role-management',
          'permission-management',
          'user-management',
          'frontend-integration',
          'audit-logging'
        ]
      },
      frontend: {
        enabled: validFrontendPath ? true : false,
        path: validFrontendPath,
        pages: validFrontendPath ? frontendPages : []
      }
    },
    endpoints: {
      authentication: [
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
        'DELETE /users/:id',
        'GET /users/stats/overview'
      ],
      roles: [
        'GET /roles',
        'POST /roles',
        'GET /roles/:id',
        'PUT /roles/:id',
        'DELETE /roles/:id',
        'POST /roles/:id/clone'
      ],
      permissions: [
        'GET /roles/permissions/all',
        'POST /roles/permissions'
      ],
      assignments: [
        'POST /roles/assign-user'
      ],
      statistics: [
        'GET /roles/stats/overview',
        'GET /users/stats/overview'
      ],
      audit: [
        'GET /roles/audit/changes'
      ],
      system: [
        'GET /health',
        'GET /system/health',
        'GET /system/info'
      ],
      frontend: validFrontendPath ? [
        'GET /',
        'GET /frontend/index.html',
        'GET /frontend/dashboard.html',
        'GET /frontend/profile.html',
        'GET /frontend/roles.html',
        'GET /frontend/demo-complete.html'
      ] : ['Frontend no disponible']
    }
  });
});

// =================== MIDDLEWARE DE LOGGING ===================

app.use((req, res, next) => {
  // Solo loggear APIs, no archivos estáticos
  if (!req.originalUrl.startsWith('/frontend/') && 
      !req.originalUrl.includes('.css') && 
      !req.originalUrl.includes('.js') &&
      !req.originalUrl.includes('.ico')) {
    console.log(`📍 ${req.method} ${req.originalUrl} - ${new Date().toISOString()}`);
  }
  next();
});

// =================== MANEJO DE ERRORES ===================

app.use((err, req, res, next) => {
  console.error('💥 Error en API Gateway:', err);
  
  if (err.code === 'ECONNREFUSED') {
    res.status(503).json({
      success: false,
      message: 'Servicio backend no disponible',
      error: 'SERVICE_UNAVAILABLE'
    });
  } else if (err.code === 'ETIMEDOUT') {
    res.status(504).json({
      success: false,
      message: 'Timeout del servicio',
      error: 'GATEWAY_TIMEOUT'
    });
  } else {
    res.status(500).json({
      success: false,
      message: 'Error interno del API Gateway',
      error: process.env.NODE_ENV === 'development' ? err.message : 'Internal Server Error'
    });
  }
});

// =================== CATCH ALL PARA RUTAS NO ENCONTRADAS ===================

app.use('*', (req, res) => {
  // No loggear 404s de archivos estáticos comunes
  if (!req.originalUrl.includes('.ico') && 
      !req.originalUrl.includes('.map') && 
      !req.originalUrl.includes('.css') &&
      !req.originalUrl.includes('.js')) {
    console.log(`❓ Ruta no encontrada: ${req.method} ${req.originalUrl}`);
  }
  
  res.status(404).json({
    success: false,
    message: `Ruta no encontrada: ${req.method} ${req.originalUrl}`,
    suggestion: 'Verifica la URL o consulta /system/info para ver endpoints disponibles',
    system: {
      frontendConfigured: validFrontendPath ? true : false,
      frontendPath: validFrontendPath,
      systemInfo: '/system/info',
      systemHealth: '/system/health'
    },
    quickLinks: validFrontendPath ? {
      home: '/',
      login: '/frontend/index.html',
      dashboard: '/frontend/dashboard.html',
      roles: '/frontend/roles.html',
      demo: '/frontend/demo-complete.html'
    } : {
      systemInfo: '/system/info',
      health: '/health',
      apiDocs: 'Consulta /system/info para ver todos los endpoints'
    }
  });
});

// =================== INICIAR SERVIDOR ===================

app.listen(PORT, () => {
  console.log('');
  console.log('🌐 API GATEWAY COMPLETO V3.0 ejecutándose en puerto ' + PORT);
  console.log('========================================');
  console.log('');
  
  if (validFrontendPath) {
    console.log('🏠 FRONTEND DISPONIBLE:');
    console.log(`   🏡 Home:           http://localhost:${PORT}/`);
    console.log(`   🔐 Login:          http://localhost:${PORT}/frontend/index.html`);
    console.log(`   📊 Dashboard:      http://localhost:${PORT}/frontend/dashboard.html`);
    console.log(`   🛡️ Roles:          http://localhost:${PORT}/frontend/roles.html`);
    console.log(`   👤 Perfil:         http://localhost:${PORT}/frontend/profile.html`);
    console.log(`   🧪 Demo:           http://localhost:${PORT}/frontend/demo-complete.html`);
    console.log('');
  } else {
    console.log('⚠️ FRONTEND NO DISPONIBLE - Verificar configuración de Docker');
    console.log('');
  }
  
  console.log('🔗 APIS DISPONIBLES:');
  console.log('   🔐 Autenticación:  POST /auth/login, GET /auth/verify');
  console.log('   👥 Usuarios:       GET /users, POST /users');
  console.log('   🎭 Roles:          GET /roles, POST /roles');
  console.log('   🔑 Permisos:       GET /roles/permissions/all');
  console.log('   📊 Estadísticas:   GET /users/stats/overview');
  console.log('   📋 Auditoría:      GET /roles/audit/changes');
  console.log('   👋 Hello Service:  GET /hello, GET /hello/private');
  console.log('');
  
  console.log('🛠️ HERRAMIENTAS DE DIAGNÓSTICO:');
  console.log(`   📊 Info Sistema:   http://localhost:${PORT}/system/info`);
  console.log(`   ❤️ Health Check:   http://localhost:${PORT}/system/health`);
  console.log(`   🔧 API Gateway:    http://localhost:${PORT}/health`);
  console.log('');
  
  console.log('📋 CREDENCIALES DE PRUEBA:');
  console.log('   👑 Super Admin:    superadmin@system.com / admin123');
  console.log('   🔧 Admin:          admin@admin.com / admin123');
  console.log('   👔 Manager:        manager@test.com / mod123');
  console.log('   👤 Employee:       employee@test.com / test123');
  console.log('   👁️ Guest:          guest@test.com / demo123');
  console.log('');
  
  console.log('🚀 SISTEMA COMPLETO Y LISTO PARA USAR!');
  console.log(`🎯 Comenzar en: http://localhost:${PORT}/`);
  console.log('========================================');
});

// =================== MANEJO DE SEÑALES ===================

process.on('SIGTERM', () => {
  console.log('📴 API Gateway cerrándose...');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('📴 API Gateway cerrándose...');
  process.exit(0);
});

// =================== MANEJO DE ERRORES NO CAPTURADOS ===================

process.on('unhandledRejection', (reason, promise) => {
  console.error('💥 Unhandled Rejection at:', promise, 'reason:', reason);
});

process.on('uncaughtException', (error) => {
  console.error('💥 Uncaught Exception:', error);
  process.exit(1);
});