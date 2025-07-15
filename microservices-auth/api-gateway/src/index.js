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

console.log('🚀 API Gateway SIMPLE iniciando...');

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'OK', service: 'api-gateway', timestamp: new Date().toISOString() });
});

// AUTH LOGIN - petición directa al auth-service
app.post('/auth/login', async (req, res) => {
  try {
    console.log('📨 LOGIN REQUEST recibida:', req.body);
    
    const response = await axios.post('http://auth-service:3001/auth/login', req.body, {
      headers: { 'Content-Type': 'application/json' },
      timeout: 10000
    });
    
    console.log('✅ LOGIN RESPONSE exitosa');
    res.json(response.data);
    
  } catch (error) {
    console.error('❌ LOGIN ERROR:', error.message);
    
    if (error.response) {
      res.status(error.response.status).json(error.response.data);
    } else {
      res.status(500).json({
        success: false,
        message: 'Error de conexión con auth-service'
      });
    }
  }
});

app.listen(PORT, () => {
  console.log('🌐 API Gateway SIMPLE ejecutándose en puerto ' + PORT);
});
