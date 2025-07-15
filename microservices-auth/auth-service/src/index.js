const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const { v4: uuidv4 } = require('uuid');

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

// =================== MIDDLEWARE ===================

// Middleware de autenticación
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
    const decoded = jwt.verify(token, 'mi_super_secreto_jwt_2024');
    
    // Verificar que el usuario aún existe y está activo
    const userResult = await pool.query(
      'SELECT id, email, first_name, last_name, role, is_active FROM users WHERE id = $1 AND is_active = true',
      [decoded.id]
    );

    if (userResult.rows.length === 0) {
      return res.status(401).json({
        success: false,
        message: 'Usuario no encontrado o inactivo'
      });
    }

    req.user = userResult.rows[0];
    next();

  } catch (error) {
    console.error('Error en autenticación:', error);
    return res.status(401).json({
      success: false,
      message: 'Token inválido o expirado'
    });
  }
};

// Middleware de autorización por roles
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

// Middleware de validación de contraseña
const validatePassword = (password) => {
  if (!password || password.length < 6) {
    return { valid: false, message: 'La contraseña debe tener al menos 6 caracteres' };
  }
  if (!/(?=.*[a-z])/.test(password)) {
    return { valid: false, message: 'La contraseña debe contener al menos una letra minúscula' };
  }
  if (!/(?=.*[A-Z])/.test(password)) {
    return { valid: false, message: 'La contraseña debe contener al menos una letra mayúscula' };
  }
  if (!/(?=.*\d)/.test(password)) {
    return { valid: false, message: 'La contraseña debe contener al menos un número' };
  }
  return { valid: true };
};

// =================== RUTAS DE AUTENTICACIÓN ===================

app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    service: 'auth-service-v2',
    timestamp: new Date().toISOString(),
    version: '2.0.0'
  });
});

// LOGIN (existente mejorado)
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

    // Actualizar último login
    await pool.query(
      'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1',
      [user.id]
    );

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
          role: user.role,
          isActive: user.is_active,
          emailVerified: user.email_verified,
          lastLogin: user.last_login,
          createdAt: user.created_at
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

// VERIFICAR TOKEN
app.get('/auth/verify', authMiddleware, (req, res) => {
  res.json({
    success: true,
    data: {
      user: {
        id: req.user.id,
        email: req.user.email,
        firstName: req.user.first_name,
        lastName: req.user.last_name,
        role: req.user.role,
        isActive: req.user.is_active
      }
    }
  });
});

// =================== GESTIÓN DE USUARIOS (EXISTENTES) ===================

// LISTAR USUARIOS (mejorado con más filtros)
app.get('/users', authMiddleware, requireRole(['admin']), async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const offset = (page - 1) * limit;
    const search = req.query.search || '';
    const role = req.query.role || '';
    const status = req.query.status || ''; // 'active', 'inactive'
    const sortBy = req.query.sortBy || 'created_at';
    const sortOrder = req.query.sortOrder || 'DESC';

    let whereClause = 'WHERE 1=1';
    const params = [];

    if (search) {
      whereClause += ` AND (first_name ILIKE $${params.length + 1} OR last_name ILIKE $${params.length + 1} OR email ILIKE $${params.length + 1})`;
      params.push(`%${search}%`);
    }

    if (role) {
      whereClause += ` AND role = $${params.length + 1}`;
      params.push(role);
    }

    if (status === 'active') {
      whereClause += ` AND is_active = true`;
    } else if (status === 'inactive') {
      whereClause += ` AND is_active = false`;
    }

    // Validar columnas de ordenamiento
    const allowedSortColumns = ['created_at', 'updated_at', 'last_login', 'email', 'first_name', 'last_name'];
    const validSortBy = allowedSortColumns.includes(sortBy) ? sortBy : 'created_at';
    const validSortOrder = ['ASC', 'DESC'].includes(sortOrder.toUpperCase()) ? sortOrder.toUpperCase() : 'DESC';

    // Obtener usuarios
    const usersResult = await pool.query(
      `SELECT id, email, first_name, last_name, role, is_active, email_verified, created_at, updated_at, last_login
       FROM users ${whereClause} 
       ORDER BY ${validSortBy} ${validSortOrder}
       LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
      [...params, limit, offset]
    );

    // Contar total
    const countResult = await pool.query(
      `SELECT COUNT(*) FROM users ${whereClause}`,
      params
    );

    const total = parseInt(countResult.rows[0].count);
    const totalPages = Math.ceil(total / limit);

    res.json({
      success: true,
      data: {
        users: usersResult.rows,
        pagination: {
          current: page,
          total: totalPages,
          limit,
          count: total
        },
        filters: {
          search,
          role,
          status,
          sortBy: validSortBy,
          sortOrder: validSortOrder
        }
      }
    });

  } catch (error) {
    console.error('Error al listar usuarios:', error);
    res.status(500).json({
      success: false,
      message: 'Error interno del servidor'
    });
  }
});

// CREAR USUARIO (existente con validaciones mejoradas)
app.post('/users', authMiddleware, requireRole(['admin']), async (req, res) => {
  try {
    const { email, password, firstName, lastName, role = 'user' } = req.body;

    // Validaciones básicas
    if (!email || !password || !firstName || !lastName) {
      return res.status(400).json({
        success: false,
        message: 'Email, contraseña, nombre y apellido son requeridos'
      });
    }

    // Validar formato de email
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({
        success: false,
        message: 'Formato de email inválido'
      });
    }

    // Validar contraseña
    const passwordValidation = validatePassword(password);
    if (!passwordValidation.valid) {
      return res.status(400).json({
        success: false,
        message: passwordValidation.message
      });
    }

    if (!['user', 'admin', 'moderator'].includes(role)) {
      return res.status(400).json({
        success: false,
        message: 'Rol inválido. Debe ser: user, admin o moderator'
      });
    }

    // Verificar si el email ya existe
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE email = $1',
      [email]
    );

    if (existingUser.rows.length > 0) {
      return res.status(409).json({
        success: false,
        message: 'El email ya está en uso'
      });
    }

    // Hashear contraseña
    const saltRounds = 12;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Crear usuario
    const newUserResult = await pool.query(
      `INSERT INTO users (id, email, password_hash, first_name, last_name, role, email_verified, is_active) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8) 
       RETURNING id, email, first_name, last_name, role, is_active, email_verified, created_at`,
      [uuidv4(), email, passwordHash, firstName, lastName, role, true, true]
    );

    const newUser = newUserResult.rows[0];

    console.log('Usuario creado exitosamente:', newUser.email);

    res.status(201).json({
      success: true,
      message: 'Usuario creado exitosamente',
      data: { user: newUser }
    });

  } catch (error) {
    console.error('Error al crear usuario:', error);
    res.status(500).json({
      success: false,
      message: 'Error interno del servidor'
    });
  }
});

// OBTENER USUARIO POR ID (existente)
app.get('/users/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;

    // Solo admins pueden ver cualquier usuario, otros solo a sí mismos
    if (req.user.role !== 'admin' && req.user.id !== id) {
      return res.status(403).json({
        success: false,
        message: 'No tienes permisos para ver este usuario'
      });
    }

    const userResult = await pool.query(
      'SELECT id, email, first_name, last_name, role, is_active, email_verified, created_at, updated_at, last_login FROM users WHERE id = $1',
      [id]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Usuario no encontrado'
      });
    }

    res.json({
      success: true,
      data: { user: userResult.rows[0] }
    });

  } catch (error) {
    console.error('Error al obtener usuario:', error);
    res.status(500).json({
      success: false,
      message: 'Error interno del servidor'
    });
  }
});

// =================== NUEVAS FUNCIONALIDADES ===================

// OBTENER PERFIL PROPIO
app.get('/auth/profile', authMiddleware, async (req, res) => {
  try {
    const userResult = await pool.query(
      `SELECT id, email, first_name, last_name, role, is_active, email_verified, 
              created_at, updated_at, last_login,
              (SELECT COUNT(*) FROM users WHERE created_at >= CURRENT_DATE - INTERVAL '30 days') as recent_users_count
       FROM users WHERE id = $1`,
      [req.user.id]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Usuario no encontrado'
      });
    }

    const user = userResult.rows[0];

    // Estadísticas adicionales del perfil
    const profileStats = {
      daysSinceRegistration: Math.floor((new Date() - new Date(user.created_at)) / (1000 * 60 * 60 * 24)),
      daysSinceLastLogin: user.last_login ? Math.floor((new Date() - new Date(user.last_login)) / (1000 * 60 * 60 * 24)) : null,
      accountStatus: user.is_active ? 'active' : 'inactive',
      emailVerified: user.email_verified
    };

    res.json({
      success: true,
      data: { 
        user,
        stats: profileStats
      }
    });

  } catch (error) {
    console.error('Error al obtener perfil:', error);
    res.status(500).json({
      success: false,
      message: 'Error interno del servidor'
    });
  }
});

// ACTUALIZAR PERFIL PROPIO
app.put('/auth/profile', authMiddleware, async (req, res) => {
  try {
    const { firstName, lastName, email } = req.body;

    // Validaciones
    if (!firstName || !lastName) {
      return res.status(400).json({
        success: false,
        message: 'Nombre y apellido son requeridos'
      });
    }

    if (email) {
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(email)) {
        return res.status(400).json({
          success: false,
          message: 'Formato de email inválido'
        });
      }

      // Verificar si el email ya existe (excepto el usuario actual)
      const existingUser = await pool.query(
        'SELECT id FROM users WHERE email = $1 AND id != $2',
        [email, req.user.id]
      );

      if (existingUser.rows.length > 0) {
        return res.status(409).json({
          success: false,
          message: 'El email ya está en uso por otro usuario'
        });
      }
    }

    // Actualizar usuario
    const updateResult = await pool.query(
      `UPDATE users SET 
         first_name = $1, 
         last_name = $2, 
         ${email ? 'email = $4,' : ''} 
         updated_at = CURRENT_TIMESTAMP 
       WHERE id = $3 
       RETURNING id, email, first_name, last_name, role, is_active, email_verified, updated_at`,
      email ? [firstName, lastName, req.user.id, email] : [firstName, lastName, req.user.id]
    );

    if (updateResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Usuario no encontrado'
      });
    }

    res.json({
      success: true,
      message: 'Perfil actualizado exitosamente',
      data: { user: updateResult.rows[0] }
    });

  } catch (error) {
    console.error('Error al actualizar perfil:', error);
    res.status(500).json({
      success: false,
      message: 'Error interno del servidor'
    });
  }
});

// CAMBIAR CONTRASEÑA PROPIA
app.put('/auth/password', authMiddleware, async (req, res) => {
  try {
    const { currentPassword, newPassword, confirmPassword } = req.body;

    // Validaciones
    if (!currentPassword || !newPassword || !confirmPassword) {
      return res.status(400).json({
        success: false,
        message: 'Todos los campos son requeridos'
      });
    }

    if (newPassword !== confirmPassword) {
      return res.status(400).json({
        success: false,
        message: 'Las contraseñas nuevas no coinciden'
      });
    }

    // Validar nueva contraseña
    const passwordValidation = validatePassword(newPassword);
    if (!passwordValidation.valid) {
      return res.status(400).json({
        success: false,
        message: passwordValidation.message
      });
    }

    // Obtener usuario actual
    const userResult = await pool.query(
      'SELECT id, password_hash FROM users WHERE id = $1',
      [req.user.id]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Usuario no encontrado'
      });
    }

    const user = userResult.rows[0];

    // Verificar contraseña actual
    const passwordMatch = await bcrypt.compare(currentPassword, user.password_hash);
    if (!passwordMatch) {
      return res.status(400).json({
        success: false,
        message: 'Contraseña actual incorrecta'
      });
    }

    // Hashear nueva contraseña
    const saltRounds = 12;
    const newPasswordHash = await bcrypt.hash(newPassword, saltRounds);

    // Actualizar contraseña
    await pool.query(
      'UPDATE users SET password_hash = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2',
      [newPasswordHash, req.user.id]
    );

    console.log('Contraseña actualizada para usuario:', req.user.email);

    res.json({
      success: true,
      message: 'Contraseña actualizada exitosamente'
    });

  } catch (error) {
    console.error('Error al cambiar contraseña:', error);
    res.status(500).json({
      success: false,
      message: 'Error interno del servidor'
    });
  }
});

// CAMBIAR CONTRASEÑA DE OTRO USUARIO (solo admins)
app.put('/users/:id/password', authMiddleware, requireRole(['admin']), async (req, res) => {
  try {
    const { id } = req.params;
    const { newPassword, confirmPassword } = req.body;

    // Validaciones
    if (!newPassword || !confirmPassword) {
      return res.status(400).json({
        success: false,
        message: 'Nueva contraseña y confirmación son requeridas'
      });
    }

    if (newPassword !== confirmPassword) {
      return res.status(400).json({
        success: false,
        message: 'Las contraseñas no coinciden'
      });
    }

    // Validar nueva contraseña
    const passwordValidation = validatePassword(newPassword);
    if (!passwordValidation.valid) {
      return res.status(400).json({
        success: false,
        message: passwordValidation.message
      });
    }

    // Verificar que el usuario existe
    const userResult = await pool.query(
      'SELECT id, email FROM users WHERE id = $1',
      [id]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Usuario no encontrado'
      });
    }

    // Hashear nueva contraseña
    const saltRounds = 12;
    const newPasswordHash = await bcrypt.hash(newPassword, saltRounds);

    // Actualizar contraseña
    await pool.query(
      'UPDATE users SET password_hash = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2',
      [newPasswordHash, id]
    );

    console.log(`Contraseña actualizada por admin ${req.user.email} para usuario:`, userResult.rows[0].email);

    res.json({
      success: true,
      message: 'Contraseña actualizada exitosamente'
    });

  } catch (error) {
    console.error('Error al cambiar contraseña:', error);
    res.status(500).json({
      success: false,
      message: 'Error interno del servidor'
    });
  }
});

// ACTIVAR/DESACTIVAR USUARIO (solo admins)
app.put('/users/:id/status', authMiddleware, requireRole(['admin']), async (req, res) => {
  try {
    const { id } = req.params;
    const { isActive } = req.body;

    if (typeof isActive !== 'boolean') {
      return res.status(400).json({
        success: false,
        message: 'Estado debe ser true o false'
      });
    }

    // No permitir desactivar el propio usuario
    if (req.user.id === id && !isActive) {
      return res.status(400).json({
        success: false,
        message: 'No puedes desactivar tu propio usuario'
      });
    }

    const updateResult = await pool.query(
      `UPDATE users SET is_active = $1, updated_at = CURRENT_TIMESTAMP 
       WHERE id = $2 
       RETURNING id, email, first_name, last_name, is_active`,
      [isActive, id]
    );

    if (updateResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Usuario no encontrado'
      });
    }

    const user = updateResult.rows[0];

    console.log(`Usuario ${user.email} ${isActive ? 'activado' : 'desactivado'} por admin ${req.user.email}`);

    res.json({
      success: true,
      message: `Usuario ${isActive ? 'activado' : 'desactivado'} exitosamente`,
      data: { user }
    });

  } catch (error) {
    console.error('Error al cambiar estado de usuario:', error);
    res.status(500).json({
      success: false,
      message: 'Error interno del servidor'
    });
  }
});

// EXPORTAR USUARIOS A CSV (solo admins)
app.get('/users/export/csv', authMiddleware, requireRole(['admin']), async (req, res) => {
  try {
    const usersResult = await pool.query(
      `SELECT id, email, first_name, last_name, role, is_active, email_verified, 
              created_at, updated_at, last_login 
       FROM users 
       ORDER BY created_at DESC`
    );

    const users = usersResult.rows;

    // Crear CSV
    const csvHeader = 'ID,Email,First Name,Last Name,Role,Active,Email Verified,Created At,Updated At,Last Login\n';
    const csvRows = users.map(user => 
      `"${user.id}","${user.email}","${user.first_name}","${user.last_name}","${user.role}","${user.is_active}","${user.email_verified}","${user.created_at}","${user.updated_at}","${user.last_login || ''}"`
    ).join('\n');

    const csvContent = csvHeader + csvRows;

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="users_export_${new Date().toISOString().split('T')[0]}.csv"`);
    res.send(csvContent);

    console.log(`Exportación CSV realizada por admin ${req.user.email}`);

  } catch (error) {
    console.error('Error al exportar usuarios:', error);
    res.status(500).json({
      success: false,
      message: 'Error interno del servidor'
    });
  }
});

// =================== RUTAS EXISTENTES MANTENIDAS ===================

// ACTUALIZAR USUARIO (existente)
app.put('/users/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { firstName, lastName, role, isActive } = req.body;

    // Solo admins pueden actualizar cualquier usuario, otros solo a sí mismos
    if (req.user.role !== 'admin' && req.user.id !== id) {
      return res.status(403).json({
        success: false,
        message: 'No tienes permisos para actualizar este usuario'
      });
    }

    // Los usuarios normales no pueden cambiar su rol o estado
    const updateData = { firstName, lastName };
    if (req.user.role === 'admin') {
      if (role) updateData.role = role;
      if (typeof isActive === 'boolean') updateData.isActive = isActive;
    }

    const updateFields = [];
    const params = [];
    let paramIndex = 1;

    Object.keys(updateData).forEach(key => {
      if (updateData[key] !== undefined) {
        const dbField = key === 'firstName' ? 'first_name' : 
                       key === 'lastName' ? 'last_name' : 
                       key === 'isActive' ? 'is_active' : key;
        
        updateFields.push(`${dbField} = $${paramIndex}`);
        params.push(updateData[key]);
        paramIndex++;
      }
    });

    if (updateFields.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'No hay campos para actualizar'
      });
    }

    params.push(id);

    const updateResult = await pool.query(
      `UPDATE users SET ${updateFields.join(', ')}, updated_at = CURRENT_TIMESTAMP 
       WHERE id = $${paramIndex} 
       RETURNING id, email, first_name, last_name, role, is_active, email_verified, updated_at`,
      params
    );

    if (updateResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Usuario no encontrado'
      });
    }

    res.json({
      success: true,
      message: 'Usuario actualizado exitosamente',
      data: { user: updateResult.rows[0] }
    });

  } catch (error) {
    console.error('Error al actualizar usuario:', error);
    res.status(500).json({
      success: false,
      message: 'Error interno del servidor'
    });
  }
});

// ELIMINAR USUARIO (existente)
app.delete('/users/:id', authMiddleware, requireRole(['admin']), async (req, res) => {
  try {
    const { id } = req.params;

    // No permitir eliminar el propio usuario
    if (req.user.id === id) {
      return res.status(400).json({
        success: false,
        message: 'No puedes eliminar tu propio usuario'
      });
    }

    const deleteResult = await pool.query(
      'DELETE FROM users WHERE id = $1 RETURNING id, email',
      [id]
    );

    if (deleteResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Usuario no encontrado'
      });
    }

    console.log(`Usuario ${deleteResult.rows[0].email} eliminado por admin ${req.user.email}`);

    res.json({
      success: true,
      message: 'Usuario eliminado exitosamente',
      data: { deletedUser: deleteResult.rows[0] }
    });

  } catch (error) {
    console.error('Error al eliminar usuario:', error);
    res.status(500).json({
      success: false,
      message: 'Error interno del servidor'
    });
  }
});

// ESTADÍSTICAS (existente mejorado)
app.get('/users/stats/overview', authMiddleware, requireRole(['admin']), async (req, res) => {
  try {
    // Total de usuarios
    const totalResult = await pool.query('SELECT COUNT(*) FROM users');
    const total = parseInt(totalResult.rows[0].count);

    // Usuarios activos
    const activeResult = await pool.query('SELECT COUNT(*) FROM users WHERE is_active = true');
    const active = parseInt(activeResult.rows[0].count);

    // Usuarios por rol
    const roleResult = await pool.query(
      'SELECT role, COUNT(*) as count FROM users GROUP BY role ORDER BY count DESC'
    );

    // Usuarios registrados en los últimos 30 días
    const recentResult = await pool.query(
      'SELECT COUNT(*) FROM users WHERE created_at >= CURRENT_DATE - INTERVAL \'30 days\''
    );
    const recent = parseInt(recentResult.rows[0].count);

    // Usuarios que han hecho login en los últimos 7 días
    const activeLoginResult = await pool.query(
      'SELECT COUNT(*) FROM users WHERE last_login >= CURRENT_DATE - INTERVAL \'7 days\''
    );
    const activeLogins = parseInt(activeLoginResult.rows[0].count);

    // Usuarios por mes (últimos 12 meses)
    const monthlyResult = await pool.query(`
      SELECT 
        DATE_TRUNC('month', created_at) as month,
        COUNT(*) as count
      FROM users 
      WHERE created_at >= CURRENT_DATE - INTERVAL '12 months'
      GROUP BY DATE_TRUNC('month', created_at)
      ORDER BY month ASC
    `);

    // Actividad reciente (últimos logins)
    const recentActivityResult = await pool.query(`
      SELECT first_name, last_name, email, last_login
      FROM users 
      WHERE last_login IS NOT NULL
      ORDER BY last_login DESC
      LIMIT 5
    `);

    res.json({
      success: true,
      data: {
        totals: {
          total,
          active,
          inactive: total - active,
          recent,
          activeLogins
        },
        byRole: roleResult.rows,
        monthlyGrowth: monthlyResult.rows,
        recentActivity: recentActivityResult.rows
      }
    });

  } catch (error) {
    console.error('Error al obtener estadísticas:', error);
    res.status(500).json({
      success: false,
      message: 'Error interno del servidor'
    });
  }
});

// ESTADÍSTICAS DETALLADAS (nueva)
app.get('/users/search', authMiddleware, requireRole(['admin']), async (req, res) => {
  try {
    const { query = '', role = '', status = '', page = 1, limit = 10 } = req.query;
    const offset = (parseInt(page) - 1) * parseInt(limit);
    let whereClause = 'WHERE 1=1';
    const params = [];

    if (query) {
      whereClause += ` AND (first_name ILIKE $${params.length + 1} OR last_name ILIKE $${params.length + 1} OR email ILIKE $${params.length + 1})`;
      params.push(`%${query}%`);
    }
    if (role) {
      whereClause += ` AND role = $${params.length + 1}`;
      params.push(role);
    }
    if (status === 'active') whereClause += ` AND is_active = true`;
    else if (status === 'inactive') whereClause += ` AND is_active = false`;

    const searchResult = await pool.query(
      `SELECT id, email, first_name, last_name, role, is_active, created_at, last_login
       FROM users ${whereClause} ORDER BY created_at DESC 
       LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
      [...params, parseInt(limit), offset]
    );

    const countResult = await pool.query(`SELECT COUNT(*) FROM users ${whereClause}`, params);
    const total = parseInt(countResult.rows[0].count);

    res.json({
      success: true,
      data: {
        users: searchResult.rows,
        pagination: { current: parseInt(page), total: Math.ceil(total / parseInt(limit)), limit: parseInt(limit), count: total }
      }
    });
  } catch (error) {
    console.error('Error en búsqueda avanzada:', error);
    res.status(500).json({ success: false, message: 'Error interno del servidor' });
  }
});

// BÚSQUEDA AVANZADA DE USUARIOS (nueva)
app.get('/users/search', authMiddleware, requireRole(['admin']), async (req, res) => {
  try {
    const {
      query = '',
      role = '',
      status = '',
      dateFrom = '',
      dateTo = '',
      lastLoginFrom = '',
      lastLoginTo = '',
      page = 1,
      limit = 10
    } = req.query;

    const offset = (parseInt(page) - 1) * parseInt(limit);
    let whereClause = 'WHERE 1=1';
    const params = [];

    // Búsqueda general
    if (query) {
      whereClause += ` AND (
        first_name ILIKE ${params.length + 1} OR 
        last_name ILIKE ${params.length + 1} OR 
        email ILIKE ${params.length + 1} OR
        CONCAT(first_name, ' ', last_name) ILIKE ${params.length + 1}
      )`;
      params.push(`%${query}%`);
    }

    // Filtro por rol
    if (role) {
      whereClause += ` AND role = ${params.length + 1}`;
      params.push(role);
    }

    // Filtro por estado
    if (status === 'active') {
      whereClause += ` AND is_active = true`;
    } else if (status === 'inactive') {
      whereClause += ` AND is_active = false`;
    }

    // Filtro por fecha de creación
    if (dateFrom) {
      whereClause += ` AND created_at >= ${params.length + 1}`;
      params.push(dateFrom);
    }
    if (dateTo) {
      whereClause += ` AND created_at <= ${params.length + 1}`;
      params.push(dateTo + ' 23:59:59');
    }

    // Filtro por último login
    if (lastLoginFrom) {
      whereClause += ` AND last_login >= ${params.length + 1}`;
      params.push(lastLoginFrom);
    }
    if (lastLoginTo) {
      whereClause += ` AND last_login <= ${params.length + 1}`;
      params.push(lastLoginTo + ' 23:59:59');
    }

    // Ejecutar búsqueda
    const searchResult = await pool.query(`
      SELECT 
        id, email, first_name, last_name, role, is_active, 
        email_verified, created_at, updated_at, last_login,
        EXTRACT(days FROM CURRENT_DATE - created_at) as days_since_registration,
        CASE 
          WHEN last_login IS NULL THEN 'Nunca'
          WHEN last_login >= CURRENT_DATE - INTERVAL '1 day' THEN 'Hoy'
          WHEN last_login >= CURRENT_DATE - INTERVAL '7 days' THEN 'Esta semana'
          WHEN last_login >= CURRENT_DATE - INTERVAL '30 days' THEN 'Este mes'
          ELSE 'Hace tiempo'
        END as login_status
      FROM users ${whereClause}
      ORDER BY created_at DESC
      LIMIT ${params.length + 1} OFFSET ${params.length + 2}
    `, [...params, parseInt(limit), offset]);

    // Contar resultados
    const countResult = await pool.query(`
      SELECT COUNT(*) FROM users ${whereClause}
    `, params);

    const total = parseInt(countResult.rows[0].count);
    const totalPages = Math.ceil(total / parseInt(limit));

    res.json({
      success: true,
      data: {
        users: searchResult.rows,
        pagination: {
          current: parseInt(page),
          total: totalPages,
          limit: parseInt(limit),
          count: total
        },
        searchCriteria: {
          query, role, status, dateFrom, dateTo, 
          lastLoginFrom, lastLoginTo
        }
      }
    });

  } catch (error) {
    console.error('Error en búsqueda avanzada:', error);
    res.status(500).json({
      success: false,
      message: 'Error interno del servidor'
    });
  }
});

app.listen(PORT, () => {
  console.log('🔐 Auth Service V2 EXPANDIDO ejecutándose en puerto ' + PORT);
  console.log('📊 Nuevas funcionalidades disponibles:');
  console.log('   🔐 AUTENTICACIÓN:');
  console.log('     GET    /auth/verify             - Verificar token');
  console.log('     GET    /auth/profile            - Obtener perfil propio');
  console.log('     PUT    /auth/profile            - Actualizar perfil propio');
  console.log('     PUT    /auth/password           - Cambiar contraseña propia');
  console.log('');
  console.log('   👥 GESTIÓN DE USUARIOS:');
  console.log('     GET    /users                   - Listar usuarios (filtros avanzados)');
  console.log('     POST   /users                   - Crear usuario');
  console.log('     GET    /users/:id               - Obtener usuario');
  console.log('     PUT    /users/:id               - Actualizar usuario');
  console.log('     DELETE /users/:id               - Eliminar usuario');
  console.log('     PUT    /users/:id/password      - Cambiar contraseña (admin)');
  console.log('     PUT    /users/:id/status        - Activar/desactivar usuario');
  console.log('     GET    /users/search            - Búsqueda avanzada');
  console.log('     GET    /users/export/csv        - Exportar usuarios a CSV');
  console.log('');
  console.log('   📊 ESTADÍSTICAS:');
  console.log('     GET    /users/stats/overview    - Estadísticas generales');
  console.log('     GET    /users/stats/detailed    - Estadísticas detalladas');
});