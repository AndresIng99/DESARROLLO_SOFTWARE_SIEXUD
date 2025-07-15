const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3001;

app.use(cors({ origin: '*' }));
app.use(express.json());

const pool = new Pool({
  connectionString: 'postgresql://postgres:password@postgres:5432/auth_db',
  ssl: false,
  max: 5,
  idleTimeoutMillis: 10000,
  connectionTimeoutMillis: 10000
});

app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    service: 'auth-service',
    timestamp: new Date().toISOString()
  });
});

app.post('/auth/login', async (req, res) => {
  console.log('=== LOGIN REQUEST ===');
  console.log('Body:', req.body);
  
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Email y contraseña son requeridos'
      });
    }

    console.log('Buscando usuario:', email);
    
    // SQL corregido - usar $1 sin escape
    const userResult = await pool.query(
      'SELECT * FROM users WHERE email = $1 AND is_active = true', 
      [email]
    );

    console.log('Usuarios encontrados:', userResult.rows.length);

    if (userResult.rows.length === 0) {
      return res.status(401).json({
        success: false,
        message: 'Credenciales inválidas'
      });
    }

    const user = userResult.rows[0];
    console.log('Usuario encontrado:', user.email);

    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    console.log('Contraseña válida:', passwordMatch);
    
    if (!passwordMatch) {
      return res.status(401).json({
        success: false,
        message: 'Credenciales inválidas'
      });
    }

    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        role: user.role,
        firstName: user.first_name,
        lastName: user.last_name
      },
      'mi_super_secreto_jwt_2024',
      { expiresIn: '24h' }
    );

    console.log('LOGIN EXITOSO para:', user.email);

    res.json({
      success: true,
      message: 'Login exitoso',
      data: {
        accessToken: token,
        user: {
          id: user.id,
          email: user.email,
          firstName: user.first_name,
          lastName: user.last_name,
          role: user.role
        }
      }
    });

  } catch (error) {
    console.error('ERROR EN LOGIN:', error);
    res.status(500).json({
      success: false,
      message: 'Error interno del servidor: ' + error.message
    });
  }
});

app.listen(PORT, () => {
  console.log('Auth Service con BD ejecutandose en puerto ' + PORT);
});
