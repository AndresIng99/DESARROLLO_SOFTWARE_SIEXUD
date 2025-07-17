// microservices-auth/auth-service/src/index.js
// AUTH SERVICE COMPLETO CON ROLES Y PERMISOS INTEGRADOS
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
  max: 10,
  idleTimeoutMillis: 10000,
  connectionTimeoutMillis: 10000
});

// Función helper para queries
const query = async (text, params) => {
  const client = await pool.connect();
  try {
    const result = await client.query(text, params);
    return result;
  } finally {
    client.release();
  }
};

// =================== MIDDLEWARE ===================

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
    
    const userResult = await query(
      `SELECT u.id, u.email, u.first_name, u.last_name, u.is_active, u.role_id,
              r.name as role_name, r.display_name as role_display_name, r.color as role_color
       FROM users u
       LEFT JOIN roles r ON u.role_id = r.id
       WHERE u.id = $1 AND u.is_active = true`,
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

const requirePermission = (permission) => {
  return async (req, res, next) => {
    try {
      if (!req.user || !req.user.id) {
        return res.status(401).json({
          success: false,
          message: 'Usuario no autenticado'
        });
      }

      const result = await query(
        'SELECT user_has_permission($1, $2) as has_permission',
        [req.user.id, permission]
      );

      if (!result.rows[0].has_permission) {
        return res.status(403).json({
          success: false,
          message: `No tienes permiso para: ${permission}`,
          requiredPermission: permission
        });
      }

      next();
    } catch (error) {
      console.error('Error verificando permisos:', error);
      res.status(500).json({
        success: false,
        message: 'Error verificando permisos'
      });
    }
  };
};

// =================== RUTAS DE AUTENTICACIÓN ===================

app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    service: 'auth-service-complete',
    timestamp: new Date().toISOString(),
    version: '3.0.0-complete'
  });
});

// LOGIN con verificación de roles
app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    console.log('🔐 LOGIN ATTEMPT:', email);

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Email y contraseña son requeridos'
      });
    }

    const userResult = await query(
      `SELECT u.id, u.email, u.password_hash, u.first_name, u.last_name, u.is_active,
              r.id as role_id, r.name as role_name, r.display_name as role_display_name, r.color as role_color
       FROM users u
       LEFT JOIN roles r ON u.role_id = r.id
       WHERE u.email = $1`,
      [email]
    );

    if (userResult.rows.length === 0) {
      console.log('❌ Usuario no encontrado:', email);
      return res.status(401).json({
        success: false,
        message: 'Credenciales incorrectas'
      });
    }

    const user = userResult.rows[0];
    console.log('👤 Usuario encontrado:', user.email, 'Role:', user.role_name);

    if (!user.is_active) {
      console.log('❌ Usuario inactivo:', email);
      return res.status(401).json({
        success: false,
        message: 'Usuario desactivado'
      });
    }

    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    console.log('🔑 Password comparison result:', passwordMatch);

    if (!passwordMatch) {
      console.log('❌ Contraseña incorrecta para:', email);
      return res.status(401).json({
        success: false,
        message: 'Credenciales incorrectas'
      });
    }

    // Actualizar último login
    await query(
      'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1',
      [user.id]
    );

    // Obtener permisos del usuario
    const permissionsResult = await query(
      'SELECT * FROM get_user_permissions($1)',
      [user.id]
    );

    const token = jwt.sign(
      { 
        id: user.id, 
        email: user.email, 
        role: user.role_name || 'no_role'
      },
      'mi_super_secreto_jwt_2024',
      { expiresIn: '24h' }
    );

    console.log('✅ LOGIN EXITOSO:', email, 'Role:', user.role_name);

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
          role: user.role_name,
          roleDisplayName: user.role_display_name,
          roleColor: user.role_color,
          isActive: user.is_active,
          permissions: permissionsResult.rows.map(p => p.permission_name)
        }
      }
    });

  } catch (error) {
    console.error('💥 ERROR EN LOGIN:', error);
    res.status(500).json({
      success: false,
      message: 'Error interno del servidor'
    });
  }
});

// VERIFICAR TOKEN con roles y permisos
app.get('/auth/verify', authMiddleware, async (req, res) => {
  try {
    // Obtener permisos actuales del usuario
    const permissionsResult = await query(
      'SELECT * FROM get_user_permissions($1)',
      [req.user.id]
    );

    res.json({
      success: true,
      data: {
        user: {
          id: req.user.id,
          email: req.user.email,
          firstName: req.user.first_name,
          lastName: req.user.last_name,
          role: req.user.role_name,
          roleDisplayName: req.user.role_display_name,
          roleColor: req.user.role_color,
          isActive: req.user.is_active,
          permissions: permissionsResult.rows.map(p => p.permission_name)
        }
      }
    });
  } catch (error) {
    console.error('Error en verify:', error);
    res.status(500).json({
      success: false,
      message: 'Error interno del servidor'
    });
  }
});

// OBTENER PERFIL con rol y permisos
app.get('/auth/profile', authMiddleware, async (req, res) => {
  try {
    const userResult = await query(`
      SELECT u.id, u.email, u.first_name, u.last_name, u.is_active, u.email_verified, 
             u.created_at, u.updated_at, u.last_login,
             r.id as role_id, r.name as role_name, r.display_name as role_display_name, 
             r.color as role_color, r.description as role_description
      FROM users u
      LEFT JOIN roles r ON u.role_id = r.id
      WHERE u.id = $1
    `, [req.user.id]);

    if (userResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Usuario no encontrado'
      });
    }

    const user = userResult.rows[0];

    // Obtener permisos
    const permissionsResult = await query(
      'SELECT * FROM get_user_permissions($1)',
      [req.user.id]
    );

    const profileStats = {
      daysSinceRegistration: Math.floor((new Date() - new Date(user.created_at)) / (1000 * 60 * 60 * 24)),
      daysSinceLastLogin: user.last_login ? Math.floor((new Date() - new Date(user.last_login)) / (1000 * 60 * 60 * 24)) : null,
      accountStatus: user.is_active ? 'active' : 'inactive',
      emailVerified: user.email_verified,
      permissionCount: permissionsResult.rows.length
    };

    res.json({
      success: true,
      data: { 
        user,
        stats: profileStats,
        permissions: permissionsResult.rows
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

// ACTUALIZAR PERFIL
app.put('/auth/profile', authMiddleware, async (req, res) => {
  try {
    const { firstName, lastName } = req.body;

    if (!firstName || !lastName) {
      return res.status(400).json({
        success: false,
        message: 'Nombre y apellido son requeridos'
      });
    }

    const updateResult = await query(`
      UPDATE users SET 
        first_name = $1, 
        last_name = $2, 
        updated_at = CURRENT_TIMESTAMP 
      WHERE id = $3 
      RETURNING id, email, first_name, last_name, updated_at
    `, [firstName, lastName, req.user.id]);

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

// CAMBIAR CONTRASEÑA
app.put('/auth/password', authMiddleware, async (req, res) => {
  try {
    const { currentPassword, newPassword, confirmPassword } = req.body;

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

    if (newPassword.length < 6) {
      return res.status(400).json({
        success: false,
        message: 'La nueva contraseña debe tener al menos 6 caracteres'
      });
    }

    const userResult = await query(
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
    const passwordMatch = await bcrypt.compare(currentPassword, user.password_hash);
    
    if (!passwordMatch) {
      return res.status(400).json({
        success: false,
        message: 'Contraseña actual incorrecta'
      });
    }

    const saltRounds = 12;
    const newPasswordHash = await bcrypt.hash(newPassword, saltRounds);

    await query(
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

// =================== GESTIÓN DE USUARIOS ===================

// LISTAR USUARIOS con roles
app.get('/users', authMiddleware, requirePermission('users.read.all'), async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const offset = (page - 1) * limit;
    const search = req.query.search || '';
    const role = req.query.role || '';

    let whereClause = 'WHERE 1=1';
    const params = [];

    if (search) {
      whereClause += ` AND (u.first_name ILIKE $${params.length + 1} OR u.last_name ILIKE $${params.length + 1} OR u.email ILIKE $${params.length + 1})`;
      params.push(`%${search}%`);
    }

    if (role) {
      whereClause += ` AND r.name = $${params.length + 1}`;
      params.push(role);
    }

    const usersResult = await query(`
      SELECT u.id, u.email, u.first_name, u.last_name, u.is_active, u.email_verified, 
             u.created_at, u.updated_at, u.last_login,
             r.id as role_id, r.name as role_name, r.display_name as role_display_name, r.color as role_color
      FROM users u
      LEFT JOIN roles r ON u.role_id = r.id
      ${whereClause} 
      ORDER BY u.created_at DESC 
      LIMIT $${params.length + 1} OFFSET $${params.length + 2}
    `, [...params, limit, offset]);

    const countResult = await query(`
      SELECT COUNT(*) FROM users u
      LEFT JOIN roles r ON u.role_id = r.id
      ${whereClause}
    `, params);

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

// CREAR USUARIO con rol
app.post('/users', authMiddleware, requirePermission('users.create'), async (req, res) => {
  try {
    const { email, password, firstName, lastName, roleId } = req.body;
    console.log('👤 CREANDO USUARIO:', email, 'Role ID:', roleId);

    if (!email || !password || !firstName || !lastName) {
      return res.status(400).json({
        success: false,
        message: 'Email, contraseña, nombre y apellido son requeridos'
      });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({
        success: false,
        message: 'Formato de email inválido'
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: 'La contraseña debe tener al menos 6 caracteres'
      });
    }

    // Verificar que el email no existe
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

    // Verificar que el rol existe (si se proporciona)
    if (roleId) {
      const roleResult = await query('SELECT id FROM roles WHERE id = $1 AND is_active = true', [roleId]);
      if (roleResult.rows.length === 0) {
        return res.status(400).json({
          success: false,
          message: 'Rol no válido'
        });
      }
    }

    console.log('🔑 Hasheando contraseña...');
    const saltRounds = 12;
    const passwordHash = await bcrypt.hash(password, saltRounds);
    console.log('✅ Contraseña hasheada correctamente');

    const newUserResult = await query(`
      INSERT INTO users (id, email, password_hash, first_name, last_name, role_id, email_verified, is_active) 
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8) 
      RETURNING id, email, first_name, last_name, role_id, is_active, email_verified, created_at
    `, [uuidv4(), email, passwordHash, firstName, lastName, roleId || null, true, true]);

    const newUser = newUserResult.rows[0];

    // Obtener información del rol si existe
    if (roleId) {
      const roleResult = await query('SELECT name, display_name, color FROM roles WHERE id = $1', [roleId]);
      if (roleResult.rows.length > 0) {
        newUser.role_name = roleResult.rows[0].name;
        newUser.role_display_name = roleResult.rows[0].display_name;
        newUser.role_color = roleResult.rows[0].color;
      }
    }

    console.log('✅ Usuario creado exitosamente:', newUser.email, 'ID:', newUser.id);

    res.status(201).json({
      success: true,
      message: 'Usuario creado exitosamente',
      data: { user: newUser }
    });

  } catch (error) {
    console.error('💥 Error al crear usuario:', error);
    res.status(500).json({
      success: false,
      message: 'Error interno del servidor'
    });
  }
});

// OBTENER USUARIO POR ID
app.get('/users/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;

    // Solo admins pueden ver cualquier usuario, otros solo a sí mismos
    const hasPermission = await query(
      'SELECT user_has_permission($1, $2) as has_permission',
      [req.user.id, 'users.read.all']
    );

    if (!hasPermission.rows[0].has_permission && req.user.id !== id) {
      return res.status(403).json({
        success: false,
        message: 'No tienes permisos para ver este usuario'
      });
    }

    const userResult = await query(`
      SELECT u.id, u.email, u.first_name, u.last_name, u.is_active, u.email_verified, 
             u.created_at, u.updated_at, u.last_login,
             r.id as role_id, r.name as role_name, r.display_name as role_display_name, r.color as role_color
      FROM users u
      LEFT JOIN roles r ON u.role_id = r.id
      WHERE u.id = $1
    `, [id]);

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

// ESTADÍSTICAS DE USUARIOS
app.get('/users/stats/overview', authMiddleware, requirePermission('users.read.all'), async (req, res) => {
  try {
    const totalResult = await query('SELECT COUNT(*) FROM users');
    const total = parseInt(totalResult.rows[0].count);

    const activeResult = await query('SELECT COUNT(*) FROM users WHERE is_active = true');
    const active = parseInt(activeResult.rows[0].count);

    const roleResult = await query(`
      SELECT r.name, r.display_name, r.color, COUNT(u.id) as count
      FROM roles r
      LEFT JOIN users u ON r.id = u.role_id
      GROUP BY r.id, r.name, r.display_name, r.color
      ORDER BY count DESC
    `);

    const recentResult = await query(
      'SELECT COUNT(*) FROM users WHERE created_at >= CURRENT_DATE - INTERVAL \'30 days\''
    );
    const recent = parseInt(recentResult.rows[0].count);

    const activeLoginResult = await query(
      'SELECT COUNT(*) FROM users WHERE last_login >= CURRENT_DATE - INTERVAL \'7 days\''
    );
    const activeLogins = parseInt(activeLoginResult.rows[0].count);

    const recentActivityResult = await query(`
      SELECT first_name, last_name, email, last_login
      FROM users 
      WHERE last_login IS NOT NULL
      ORDER BY last_login DESC
      LIMIT 5
    `);

    res.json({
      success: true,
      data: {
        total,
        active,
        inactive: total - active,
        recent,
        activeLogins,
        byRole: roleResult.rows,
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

// =================== GESTIÓN DE ROLES ===================

// LISTAR ROLES
app.get('/roles', authMiddleware, requirePermission('roles.read'), async (req, res) => {
  try {
    const { includePermissions = false, includeSystemRoles = true } = req.query;
    
    let whereClause = '';
    if (!includeSystemRoles || includeSystemRoles === 'false') {
      whereClause = 'WHERE is_system = false';
    }

    const rolesResult = await query(`
      SELECT 
        r.id,
        r.name,
        r.display_name,
        r.description,
        r.color,
        r.is_system,
        r.is_active,
        r.created_at,
        r.updated_at,
        (SELECT COUNT(*) FROM users WHERE role_id = r.id) as user_count
      FROM roles r
      ${whereClause}
      ORDER BY r.is_system DESC, r.name ASC
    `);

    let roles = rolesResult.rows;

    if (includePermissions === 'true') {
      for (let role of roles) {
        const permissionsResult = await query(`
          SELECT 
            p.id,
            p.name,
            p.display_name,
            p.description,
            p.module,
            p.action,
            p.resource
          FROM permissions p
          JOIN role_permissions rp ON p.id = rp.permission_id
          WHERE rp.role_id = $1
          ORDER BY p.module, p.action
        `, [role.id]);
        
        role.permissions = permissionsResult.rows;
      }
    }

    res.json({
      success: true,
      data: { roles }
    });

  } catch (error) {
    console.error('Error al listar roles:', error);
    res.status(500).json({
      success: false,
      message: 'Error interno del servidor'
    });
  }
});

// CREAR ROL
app.post('/roles', authMiddleware, requirePermission('roles.create'), async (req, res) => {
  try {
    const { name, displayName, description, color = '#6B7280', permissions = [] } = req.body;

    if (!name || !displayName) {
      return res.status(400).json({
        success: false,
        message: 'Nombre y nombre para mostrar son requeridos'
      });
    }

    const existingRole = await query('SELECT id FROM roles WHERE name = $1', [name]);
    if (existingRole.rows.length > 0) {
      return res.status(409).json({
        success: false,
        message: 'Ya existe un rol con ese nombre'
      });
    }

    const roleId = uuidv4();
    const createRoleResult = await query(`
      INSERT INTO roles (id, name, display_name, description, color, is_system, created_by)
      VALUES ($1, $2, $3, $4, $5, false, $6)
      RETURNING *
    `, [roleId, name, displayName, description, color, req.user.id]);

    const newRole = createRoleResult.rows[0];

    if (permissions.length > 0) {
      for (let permissionId of permissions) {
        await query(`
          INSERT INTO role_permissions (role_id, permission_id, granted_by)
          VALUES ($1, $2, $3)
        `, [roleId, permissionId, req.user.id]);
      }
    }

    const completeRoleResult = await query(`
      SELECT 
        r.*,
        (SELECT COUNT(*) FROM users WHERE role_id = r.id) as user_count
      FROM roles r
      WHERE r.id = $1
    `, [roleId]);

    const completeRole = completeRoleResult.rows[0];

    const rolePermissionsResult = await query(`
      SELECT p.* FROM permissions p
      JOIN role_permissions rp ON p.id = rp.permission_id
      WHERE rp.role_id = $1
    `, [roleId]);

    completeRole.permissions = rolePermissionsResult.rows;

    res.status(201).json({
      success: true,
      message: 'Rol creado exitosamente',
      data: { role: completeRole }
    });

  } catch (error) {
    console.error('Error al crear rol:', error);
    res.status(500).json({
      success: false,
      message: 'Error interno del servidor'
    });
  }
});

// ACTUALIZAR ROL
app.put('/roles/:id', authMiddleware, requirePermission('roles.update'), async (req, res) => {
  try {
    const { id } = req.params;
    const { displayName, description, color, isActive, permissions } = req.body;

    const roleResult = await query('SELECT * FROM roles WHERE id = $1', [id]);
    if (roleResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Rol no encontrado'
      });
    }

    const role = roleResult.rows[0];
    if (role.is_system) {
      return res.status(400).json({
        success: false,
        message: 'No se pueden editar roles del sistema'
      });
    }

    const updateFields = [];
    const params = [];
    let paramIndex = 1;

    if (displayName !== undefined) {
      updateFields.push(`display_name = $${paramIndex}`);
      params.push(displayName);
      paramIndex++;
    }

    if (description !== undefined) {
      updateFields.push(`description = $${paramIndex}`);
      params.push(description);
      paramIndex++;
    }

    if (color !== undefined) {
      updateFields.push(`color = $${paramIndex}`);
      params.push(color);
      paramIndex++;
    }

    if (typeof isActive === 'boolean') {
      updateFields.push(`is_active = $${paramIndex}`);
      params.push(isActive);
      paramIndex++;
    }

    if (updateFields.length > 0) {
      updateFields.push(`updated_at = CURRENT_TIMESTAMP`);
      params.push(id);

      await query(`
        UPDATE roles 
        SET ${updateFields.join(', ')}
        WHERE id = $${paramIndex}
      `, params);
    }

    if (permissions !== undefined) {
      await query('DELETE FROM role_permissions WHERE role_id = $1', [id]);

      for (let permissionId of permissions) {
        await query(`
          INSERT INTO role_permissions (role_id, permission_id, granted_by)
          VALUES ($1, $2, $3)
        `, [id, permissionId, req.user.id]);
      }
    }

    const updatedRoleResult = await query(`
      SELECT 
        r.*,
        (SELECT COUNT(*) FROM users WHERE role_id = r.id) as user_count
      FROM roles r
      WHERE r.id = $1
    `, [id]);

     const updatedRole = updatedRoleResult.rows[0];

    const rolePermissionsResult = await query(`
      SELECT p.* FROM permissions p
      JOIN role_permissions rp ON p.id = rp.permission_id
      WHERE rp.role_id = $1
    `, [id]);

    updatedRole.permissions = rolePermissionsResult.rows;

    res.json({
      success: true,
      message: 'Rol actualizado exitosamente',
      data: { role: updatedRole }
    });

  } catch (error) {
    console.error('Error al actualizar rol:', error);
    res.status(500).json({
      success: false,
      message: 'Error interno del servidor'
    });
  }
});

// ELIMINAR ROL
app.delete('/roles/:id', authMiddleware, requirePermission('roles.delete'), async (req, res) => {
  try {
    const { id } = req.params;

    const roleResult = await query('SELECT * FROM roles WHERE id = $1', [id]);
    if (roleResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Rol no encontrado'
      });
    }

    const role = roleResult.rows[0];

    if (role.is_system) {
      return res.status(400).json({
        success: false,
        message: 'No se pueden eliminar roles del sistema'
      });
    }

    const usersWithRoleResult = await query(
      'SELECT COUNT(*) as count FROM users WHERE role_id = $1',
      [id]
    );

    if (parseInt(usersWithRoleResult.rows[0].count) > 0) {
      return res.status(400).json({
        success: false,
        message: 'No se puede eliminar un rol que tiene usuarios asignados'
      });
    }

    await query('DELETE FROM roles WHERE id = $1', [id]);

    res.json({
      success: true,
      message: 'Rol eliminado exitosamente',
      data: { deletedRole: { id: role.id, name: role.name } }
    });

  } catch (error) {
    console.error('Error al eliminar rol:', error);
    res.status(500).json({
      success: false,
      message: 'Error interno del servidor'
    });
  }
});

// LISTAR PERMISOS
app.get('/roles/permissions/all', authMiddleware, requirePermission('roles.read'), async (req, res) => {
  try {
    const { groupByModule = true } = req.query;

    const permissionsResult = await query(`
      SELECT 
        id,
        name,
        display_name,
        description,
        module,
        action,
        resource,
        is_system
      FROM permissions
      ORDER BY module, action, name
    `);

    let permissions = permissionsResult.rows;

    if (groupByModule === 'true') {
      const groupedPermissions = permissions.reduce((acc, permission) => {
        if (!acc[permission.module]) {
          acc[permission.module] = {
            module: permission.module,
            permissions: []
          };
        }
        acc[permission.module].permissions.push(permission);
        return acc;
      }, {});

      permissions = Object.values(groupedPermissions);
    }

    res.json({
      success: true,
      data: { permissions }
    });

  } catch (error) {
    console.error('Error al listar permisos:', error);
    res.status(500).json({
      success: false,
      message: 'Error interno del servidor'
    });
  }
});

// CREAR PERMISO
app.post('/roles/permissions', authMiddleware, requirePermission('roles.create'), async (req, res) => {
  try {
    const { name, displayName, description, module, action, resource } = req.body;

    if (!name || !displayName || !module || !action) {
      return res.status(400).json({
        success: false,
        message: 'Nombre, nombre para mostrar, módulo y acción son requeridos'
      });
    }

    const existingPermission = await query('SELECT id FROM permissions WHERE name = $1', [name]);
    if (existingPermission.rows.length > 0) {
      return res.status(409).json({
        success: false,
        message: 'Ya existe un permiso con ese nombre'
      });
    }

    const createPermissionResult = await query(`
      INSERT INTO permissions (id, name, display_name, description, module, action, resource, is_system)
      VALUES ($1, $2, $3, $4, $5, $6, $7, false)
      RETURNING *
    `, [uuidv4(), name, displayName, description, module, action, resource || null]);

    const newPermission = createPermissionResult.rows[0];

    res.status(201).json({
      success: true,
      message: 'Permiso creado exitosamente',
      data: { permission: newPermission }
    });

  } catch (error) {
    console.error('Error al crear permiso:', error);
    res.status(500).json({
      success: false,
      message: 'Error interno del servidor'
    });
  }
});

// ASIGNAR ROL A USUARIO
app.post('/roles/assign-user', authMiddleware, requirePermission('roles.assign'), async (req, res) => {
  try {
    const { userId, roleId } = req.body;

    if (!userId || !roleId) {
      return res.status(400).json({
        success: false,
        message: 'ID de usuario y ID de rol son requeridos'
      });
    }

    const userResult = await query('SELECT * FROM users WHERE id = $1', [userId]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Usuario no encontrado'
      });
    }

    const roleResult = await query('SELECT * FROM roles WHERE id = $1 AND is_active = true', [roleId]);
    if (roleResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Rol no encontrado o inactivo'
      });
    }

    await query('UPDATE users SET role_id = $1 WHERE id = $2', [roleId, userId]);

    const updatedUserResult = await query(`
      SELECT 
        u.id,
        u.email,
        u.first_name,
        u.last_name,
        u.is_active,
        r.name as role_name,
        r.display_name as role_display_name,
        r.color as role_color
      FROM users u
      LEFT JOIN roles r ON u.role_id = r.id
      WHERE u.id = $1
    `, [userId]);

    res.json({
      success: true,
      message: 'Rol asignado exitosamente',
      data: { user: updatedUserResult.rows[0] }
    });

  } catch (error) {
    console.error('Error al asignar rol:', error);
    res.status(500).json({
      success: false,
      message: 'Error interno del servidor'
    });
  }
});

// CLONAR ROL
app.post('/roles/:id/clone', authMiddleware, requirePermission('roles.create'), async (req, res) => {
  try {
    const { id } = req.params;
    const { name, displayName } = req.body;

    const originalRoleResult = await query('SELECT * FROM roles WHERE id = $1', [id]);
    if (originalRoleResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Rol original no encontrado'
      });
    }

    const originalRole = originalRoleResult.rows[0];

    const existingRole = await query('SELECT id FROM roles WHERE name = $1', [name]);
    if (existingRole.rows.length > 0) {
      return res.status(409).json({
        success: false,
        message: 'Ya existe un rol con ese nombre'
      });
    }

    const newRoleId = uuidv4();
    await query(`
      INSERT INTO roles (id, name, display_name, description, color, is_system, created_by)
      VALUES ($1, $2, $3, $4, $5, false, $6)
    `, [
      newRoleId, 
      name, 
      displayName, 
      `Copia de ${originalRole.display_name}`,
      originalRole.color,
      req.user.id
    ]);

    await query(`
      INSERT INTO role_permissions (role_id, permission_id, granted_by)
      SELECT $1, permission_id, $2
      FROM role_permissions
      WHERE role_id = $3
    `, [newRoleId, req.user.id, id]);

    const newRoleResult = await query(`
      SELECT 
        r.*,
        (SELECT COUNT(*) FROM users WHERE role_id = r.id) as user_count
      FROM roles r
      WHERE r.id = $1
    `, [newRoleId]);

    res.status(201).json({
      success: true,
      message: 'Rol clonado exitosamente',
      data: { role: newRoleResult.rows[0] }
    });

  } catch (error) {
    console.error('Error al clonar rol:', error);
    res.status(500).json({
      success: false,
      message: 'Error interno del servidor'
    });
  }
});

// ESTADÍSTICAS DE ROLES
app.get('/roles/stats/overview', authMiddleware, requirePermission('roles.read'), async (req, res) => {
  try {
    const rolesStats = await query(`
      SELECT 
        COUNT(*) as total_roles,
        COUNT(CASE WHEN is_system = true THEN 1 END) as system_roles,
        COUNT(CASE WHEN is_system = false THEN 1 END) as custom_roles,
        COUNT(CASE WHEN is_active = true THEN 1 END) as active_roles
      FROM roles
    `);

    const permissionsStats = await query(`
      SELECT 
        COUNT(*) as total_permissions,
        COUNT(CASE WHEN is_system = true THEN 1 END) as system_permissions,
        COUNT(CASE WHEN is_system = false THEN 1 END) as custom_permissions,
        COUNT(DISTINCT module) as modules_count
      FROM permissions
    `);

    const popularRoles = await query(`
      SELECT 
        r.name,
        r.display_name,
        r.color,
        COUNT(u.id) as user_count
      FROM roles r
      LEFT JOIN users u ON r.id = u.role_id
      GROUP BY r.id, r.name, r.display_name, r.color
      ORDER BY user_count DESC
      LIMIT 5
    `);

    const permissionsByModule = await query(`
      SELECT 
        module,
        COUNT(*) as permission_count
      FROM permissions
      GROUP BY module
      ORDER BY permission_count DESC
    `);

    const usersWithoutRole = await query(`
      SELECT COUNT(*) as count
      FROM users
      WHERE role_id IS NULL
    `);

    res.json({
      success: true,
      data: {
        roles: rolesStats.rows[0],
        permissions: permissionsStats.rows[0],
        popularRoles: popularRoles.rows,
        permissionsByModule: permissionsByModule.rows,
        usersWithoutRole: parseInt(usersWithoutRole.rows[0].count)
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

// AUDITORÍA DE ROLES
app.get('/roles/audit/changes', authMiddleware, requirePermission('system.logs'), async (req, res) => {
  try {
    const { startDate, endDate, limit = 50 } = req.query;

    let whereClause = 'WHERE 1=1';
    const params = [];

    if (startDate) {
      whereClause += ` AND created_at >= ${params.length + 1}`;
      params.push(startDate);
    }

    if (endDate) {
      whereClause += ` AND created_at <= ${params.length + 1}`;
      params.push(endDate + ' 23:59:59');
    }

    const roleChanges = await query(`
      SELECT 
        'role_created' as action_type,
        r.name as target_name,
        r.display_name as target_display_name,
        r.created_at as action_date,
        u.email as performed_by
      FROM roles r
      LEFT JOIN users u ON r.created_by = u.id
      ${whereClause}
      
      UNION ALL
      
      SELECT 
        'permission_assigned' as action_type,
        CONCAT(r.display_name, ' → ', p.display_name) as target_name,
        'Asignación de permiso' as target_display_name,
        rp.granted_at as action_date,
        u.email as performed_by
      FROM role_permissions rp
      JOIN roles r ON rp.role_id = r.id
      JOIN permissions p ON rp.permission_id = p.id
      LEFT JOIN users u ON rp.granted_by = u.id
      ${whereClause.replace('created_at', 'granted_at')}
      
      ORDER BY action_date DESC
      LIMIT ${params.length + 1}
    `, [...params, parseInt(limit)]);

    res.json({
      success: true,
      data: { changes: roleChanges.rows }
    });

  } catch (error) {
    console.error('Error al obtener auditoría:', error);
    res.status(500).json({
      success: false,
      message: 'Error interno del servidor'
    });
  }
});

// VERIFICAR PERMISO ESPECÍFICO
app.post('/auth/check-permission', authMiddleware, async (req, res) => {
  try {
    const { userId, permission } = req.body;
    
    const targetUserId = userId || req.user.id;
    console.log(`🔍 Verificando permiso: ${permission} para usuario: ${targetUserId}`);
    
    const result = await query(
      'SELECT user_has_permission($1, $2) as has_permission',
      [targetUserId, permission]
    );

    const hasPermission = result.rows[0].has_permission;
    
    res.json({
      success: true,
      hasPermission,
      userId: targetUserId,
      permission
    });

  } catch (error) {
    console.error('Error verificando permisos:', error);
    res.status(500).json({
      success: false,
      message: 'Error verificando permisos'
    });
  }
});

// HEALTH CHECK PARA MICROSERVICIOS
app.get('/auth/microservice-health', (req, res) => {
  res.json({
    success: true,
    service: 'auth-service-complete',
    status: 'ready-for-production',
    features: [
      'authentication',
      'authorization', 
      'role-management',
      'permission-management',
      'user-management',
      'audit-logging'
    ],
    timestamp: new Date().toISOString()
  });
});

// =================== MANEJO DE ERRORES ===================

app.use((err, req, res, next) => {
  console.error('💥 Error no capturado:', err);
  
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

  if (err.code === '23505') {
    return res.status(409).json({
      success: false,
      message: 'El recurso ya existe'
    });
  }

  if (err.code === '23503') {
    return res.status(400).json({
      success: false,
      message: 'Referencia inválida'
    });
  }

  res.status(500).json({
    success: false,
    message: 'Error interno del servidor'
  });
});

// =================== RUTA 404 ===================
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    message: `Ruta no encontrada: ${req.method} ${req.originalUrl}`,
    availableRoutes: {
      auth: [
        'POST /auth/login',
        'GET /auth/verify',
        'GET /auth/profile',
        'PUT /auth/profile',
        'PUT /auth/password',
        'POST /auth/check-permission'
      ],
      users: [
        'GET /users',
        'POST /users',
        'GET /users/:id',
        'GET /users/stats/overview'
      ],
      roles: [
        'GET /roles',
        'POST /roles',
        'PUT /roles/:id',
        'DELETE /roles/:id',
        'POST /roles/:id/clone',
        'GET /roles/permissions/all',
        'POST /roles/permissions',
        'POST /roles/assign-user',
        'GET /roles/stats/overview',
        'GET /roles/audit/changes'
      ]
    }
  });
});

// =================== INICIAR SERVIDOR ===================

async function startServer() {
  try {
    // Probar conexión a base de datos
    await query('SELECT NOW()');
    console.log('✅ Conexión a PostgreSQL establecida');
    
    app.listen(PORT, () => {
      console.log('🚀 AUTH SERVICE COMPLETO ejecutándose en puerto ' + PORT);
      console.log('');
      console.log('📋 FUNCIONALIDADES INCLUIDAS:');
      console.log('   🔐 Autenticación JWT');
      console.log('   🛡️ Autorización por permisos');
      console.log('   👥 Gestión de usuarios');
      console.log('   🎭 Gestión de roles');
      console.log('   🔑 Gestión de permisos');
      console.log('   📊 Estadísticas y reportes');
      console.log('   📋 Auditoría de cambios');
      console.log('   🔧 APIs completas y funcionales');
      console.log('');
      console.log('🎯 ENDPOINTS PRINCIPALES:');
      console.log('   POST /auth/login               - Login con roles');
      console.log('   GET  /auth/verify              - Verificar token + permisos');
      console.log('   GET  /users                    - Listar usuarios');
      console.log('   POST /users                    - Crear usuario');
      console.log('   GET  /roles                    - Listar roles');
      console.log('   POST /roles                    - Crear rol');
      console.log('   GET  /roles/permissions/all    - Listar permisos');
      console.log('   POST /roles/assign-user        - Asignar rol a usuario');
      console.log('   GET  /roles/stats/overview     - Estadísticas');
      console.log('');
      console.log('✅ SISTEMA LISTO PARA PRODUCCIÓN');
      console.log(`🌍 Ambiente: ${process.env.NODE_ENV || 'development'}`);
    });
  } catch (error) {
    console.error('❌ Error al inicializar el servidor:', error);
    process.exit(1);
  }
}

// Manejo de señales para cierre graceful
process.on('SIGTERM', () => {
  console.log('📴 Cerrando servidor...');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('📴 Cerrando servidor...');
  process.exit(0);
});

startServer();