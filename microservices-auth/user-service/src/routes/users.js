// microservices-auth/user-service/src/routes/users.js
const express = require('express');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const Joi = require('joi');

const { query } = require('../config/database');
const authMiddleware = require('../middleware/auth');
const { requireRole } = require('../middleware/authorization');

const router = express.Router();

// Esquemas de validación
const createUserSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
  firstName: Joi.string().min(2).max(50).required(),
  lastName: Joi.string().min(2).max(50).required(),
  role: Joi.string().valid('user', 'admin', 'moderator').default('user')
});

const updateUserSchema = Joi.object({
  email: Joi.string().email(),
  firstName: Joi.string().min(2).max(50),
  lastName: Joi.string().min(2).max(50),
  role: Joi.string().valid('user', 'admin', 'moderator'),
  isActive: Joi.boolean(),
  emailVerified: Joi.boolean()
});

const changePasswordSchema = Joi.object({
  currentPassword: Joi.string().min(6).required(),
  newPassword: Joi.string().min(6).required(),
  confirmPassword: Joi.string().min(6).required()
});

// LISTAR USUARIOS (solo admins)
router.get('/', authMiddleware, requireRole(['admin']), async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const offset = (page - 1) * limit;
    const search = req.query.search || '';
    const role = req.query.role || '';

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

    // Obtener usuarios
    const usersResult = await query(
      `SELECT id, email, first_name, last_name, role, is_active, email_verified, created_at, updated_at, last_login
       FROM users ${whereClause} 
       ORDER BY created_at DESC 
       LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
      [...params, limit, offset]
    );

    // Contar total
    const countResult = await query(
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

// OBTENER USUARIO POR ID
router.get('/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;

    // Solo admins pueden ver cualquier usuario, otros solo a sí mismos
    if (req.user.role !== 'admin' && req.user.id !== id) {
      return res.status(403).json({
        success: false,
        message: 'No tienes permisos para ver este usuario'
      });
    }

    const userResult = await query(
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

// CREAR USUARIO (solo admins)
router.post('/', authMiddleware, requireRole(['admin']), async (req, res) => {
  try {
    const { error } = createUserSchema.validate(req.body);
    if (error) {
      return res.status(400).json({
        success: false,
        message: 'Datos inválidos',
        errors: error.details
      });
    }

    const { email, password, firstName, lastName, role = 'user' } = req.body;

    // Verificar si el email ya existe
    const existingUser = await query(
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
    const newUserResult = await query(
      `INSERT INTO users (id, email, password_hash, first_name, last_name, role, email_verified) 
       VALUES ($1, $2, $3, $4, $5, $6, $7) 
       RETURNING id, email, first_name, last_name, role, is_active, email_verified, created_at`,
      [uuidv4(), email, passwordHash, firstName, lastName, role, true]
    );

    const newUser = newUserResult.rows[0];

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

// ACTUALIZAR USUARIO
router.put('/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { error } = updateUserSchema.validate(req.body);
    
    if (error) {
      return res.status(400).json({
        success: false,
        message: 'Datos inválidos',
        errors: error.details
      });
    }

    // Solo admins pueden actualizar cualquier usuario, otros solo a sí mismos
    if (req.user.role !== 'admin' && req.user.id !== id) {
      return res.status(403).json({
        success: false,
        message: 'No tienes permisos para actualizar este usuario'
      });
    }

    // Los usuarios normales no pueden cambiar su rol
    if (req.user.role !== 'admin' && req.body.role) {
      delete req.body.role;
    }

    const updateFields = [];
    const params = [];
    let paramIndex = 1;

    Object.keys(req.body).forEach(key => {
      if (req.body[key] !== undefined) {
        const dbField = key === 'firstName' ? 'first_name' : 
                       key === 'lastName' ? 'last_name' : 
                       key === 'isActive' ? 'is_active' :
                       key === 'emailVerified' ? 'email_verified' : key;
        
        updateFields.push(`${dbField} = $${paramIndex}`);
        params.push(req.body[key]);
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

    const updateResult = await query(
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

// CAMBIAR CONTRASEÑA
router.put('/:id/password', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { error } = changePasswordSchema.validate(req.body);
    
    if (error) {
      return res.status(400).json({
        success: false,
        message: 'Datos inválidos',
        errors: error.details
      });
    }

    const { currentPassword, newPassword, confirmPassword } = req.body;

    // Solo admins pueden cambiar contraseña de otros usuarios
    if (req.user.role !== 'admin' && req.user.id !== id) {
      return res.status(403).json({
        success: false,
        message: 'No tienes permisos para cambiar la contraseña de este usuario'
      });
    }

    // Verificar que las contraseñas coincidan
    if (newPassword !== confirmPassword) {
      return res.status(400).json({
        success: false,
        message: 'Las contraseñas no coinciden'
      });
    }

    // Obtener usuario
    const userResult = await query(
      'SELECT id, password_hash FROM users WHERE id = $1',
      [id]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Usuario no encontrado'
      });
    }

    const user = userResult.rows[0];

    // Verificar contraseña actual (solo si no es admin)
    if (req.user.role !== 'admin') {
      const passwordMatch = await bcrypt.compare(currentPassword, user.password_hash);
      if (!passwordMatch) {
        return res.status(400).json({
          success: false,
          message: 'Contraseña actual incorrecta'
        });
      }
    }

    // Hashear nueva contraseña
    const saltRounds = 12;
    const newPasswordHash = await bcrypt.hash(newPassword, saltRounds);

    // Actualizar contraseña
    await query(
      'UPDATE users SET password_hash = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2',
      [newPasswordHash, id]
    );

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

// ELIMINAR USUARIO (solo admins)
router.delete('/:id', authMiddleware, requireRole(['admin']), async (req, res) => {
  try {
    const { id } = req.params;

    // No permitir eliminar el propio usuario
    if (req.user.id === id) {
      return res.status(400).json({
        success: false,
        message: 'No puedes eliminar tu propio usuario'
      });
    }

    const deleteResult = await query(
      'DELETE FROM users WHERE id = $1 RETURNING id, email',
      [id]
    );

    if (deleteResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Usuario no encontrado'
      });
    }

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

// OBTENER PERFIL ACTUAL
router.get('/profile/me', authMiddleware, async (req, res) => {
  try {
    const userResult = await query(
      'SELECT id, email, first_name, last_name, role, is_active, email_verified, created_at, updated_at, last_login FROM users WHERE id = $1',
      [req.user.id]
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
    console.error('Error al obtener perfil:', error);
    res.status(500).json({
      success: false,
      message: 'Error interno del servidor'
    });
  }
});

// ACTUALIZAR PERFIL ACTUAL
router.put('/profile/me', authMiddleware, async (req, res) => {
  try {
    const updateProfileSchema = Joi.object({
      firstName: Joi.string().min(2).max(50),
      lastName: Joi.string().min(2).max(50)
    });

    const { error } = updateProfileSchema.validate(req.body);
    if (error) {
      return res.status(400).json({
        success: false,
        message: 'Datos inválidos',
        errors: error.details
      });
    }

    const updateFields = [];
    const params = [];
    let paramIndex = 1;

    Object.keys(req.body).forEach(key => {
      if (req.body[key] !== undefined) {
        const dbField = key === 'firstName' ? 'first_name' : 
                       key === 'lastName' ? 'last_name' : key;
        
        updateFields.push(`${dbField} = $${paramIndex}`);
        params.push(req.body[key]);
        paramIndex++;
      }
    });

    if (updateFields.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'No hay campos para actualizar'
      });
    }

    params.push(req.user.id);

    const updateResult = await query(
      `UPDATE users SET ${updateFields.join(', ')}, updated_at = CURRENT_TIMESTAMP 
       WHERE id = $${paramIndex} 
       RETURNING id, email, first_name, last_name, role, is_active, email_verified, updated_at`,
      params
    );

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

// OBTENER ESTADÍSTICAS DE USUARIOS (solo admins)
router.get('/stats/overview', authMiddleware, requireRole(['admin']), async (req, res) => {
  try {
    // Total de usuarios
    const totalResult = await query('SELECT COUNT(*) FROM users');
    const total = parseInt(totalResult.rows[0].count);

    // Usuarios activos
    const activeResult = await query('SELECT COUNT(*) FROM users WHERE is_active = true');
    const active = parseInt(activeResult.rows[0].count);

    // Usuarios por rol
    const roleResult = await query(
      'SELECT role, COUNT(*) as count FROM users GROUP BY role ORDER BY count DESC'
    );

    // Usuarios registrados en los últimos 30 días
    const recentResult = await query(
      'SELECT COUNT(*) FROM users WHERE created_at >= CURRENT_DATE - INTERVAL \'30 days\''
    );
    const recent = parseInt(recentResult.rows[0].count);

    // Usuarios con último login en los últimos 7 días
    const activeLoginResult = await query(
      'SELECT COUNT(*) FROM users WHERE last_login >= CURRENT_DATE - INTERVAL \'7 days\''
    );
    const activeLogins = parseInt(activeLoginResult.rows[0].count);

    res.json({
      success: true,
      data: {
        total,
        active,
        inactive: total - active,
        recent,
        activeLogins,
        byRole: roleResult.rows
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

module.exports = router;