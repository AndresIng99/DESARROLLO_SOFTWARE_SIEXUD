-- microservices-auth/database/init.sql
-- SCRIPT COMPLETO QUE REEMPLAZA EL ACTUAL
-- Sistema completo con usuarios, roles y permisos desde el primer arranque

-- =================== EXTENSIONES Y LIMPIEZA ===================
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Limpiar datos existentes si existen
DROP TABLE IF EXISTS user_permissions CASCADE;
DROP TABLE IF EXISTS role_permissions CASCADE;
DROP TABLE IF EXISTS permissions CASCADE;
DROP TABLE IF EXISTS roles CASCADE;
DROP TABLE IF EXISTS refresh_tokens CASCADE;
DROP TABLE IF EXISTS users CASCADE;

-- =================== TABLA DE USUARIOS ===================
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    is_active BOOLEAN DEFAULT true,
    email_verified BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    role_id UUID -- Se definirá la FK después de crear roles
);

-- =================== TABLA DE ROLES ===================
CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(50) UNIQUE NOT NULL,
    display_name VARCHAR(100) NOT NULL,
    description TEXT,
    color VARCHAR(7) DEFAULT '#6B7280',
    is_system BOOLEAN DEFAULT false,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by UUID -- Se definirá la FK después
);

-- =================== TABLA DE PERMISOS ===================
CREATE TABLE permissions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) UNIQUE NOT NULL,
    display_name VARCHAR(150) NOT NULL,
    description TEXT,
    module VARCHAR(50) NOT NULL,
    action VARCHAR(50) NOT NULL,
    resource VARCHAR(50),
    is_system BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- =================== TABLA RELACIONAL ROLES-PERMISOS ===================
CREATE TABLE role_permissions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    granted_by UUID,
    UNIQUE(role_id, permission_id)
);

-- =================== PERMISOS DIRECTOS A USUARIOS ===================
CREATE TABLE user_permissions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    is_granted BOOLEAN DEFAULT true,
    granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    granted_by UUID,
    expires_at TIMESTAMP,
    UNIQUE(user_id, permission_id)
);

-- =================== TABLA DE REFRESH TOKENS ===================
CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_revoked BOOLEAN DEFAULT false
);

-- =================== AGREGAR FOREIGN KEYS ===================
ALTER TABLE users ADD CONSTRAINT fk_users_role FOREIGN KEY (role_id) REFERENCES roles(id);
ALTER TABLE roles ADD CONSTRAINT fk_roles_created_by FOREIGN KEY (created_by) REFERENCES users(id);
ALTER TABLE role_permissions ADD CONSTRAINT fk_role_permissions_granted_by FOREIGN KEY (granted_by) REFERENCES users(id);
ALTER TABLE user_permissions ADD CONSTRAINT fk_user_permissions_granted_by FOREIGN KEY (granted_by) REFERENCES users(id);

-- =================== ÍNDICES PARA PERFORMANCE ===================
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_role_id ON users(role_id);
CREATE INDEX idx_roles_name ON roles(name);
CREATE INDEX idx_roles_active ON roles(is_active);
CREATE INDEX idx_permissions_module ON permissions(module);
CREATE INDEX idx_permissions_name ON permissions(name);
CREATE INDEX idx_role_permissions_role ON role_permissions(role_id);
CREATE INDEX idx_role_permissions_permission ON role_permissions(permission_id);
CREATE INDEX idx_user_permissions_user ON user_permissions(user_id);
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_token ON refresh_tokens(token);

-- =================== TRIGGERS ===================
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_roles_updated_at BEFORE UPDATE ON roles
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- =================== INSERTAR DATOS INICIALES ===================

-- 1. INSERTAR ROLES DEL SISTEMA
INSERT INTO roles (id, name, display_name, description, color, is_system, is_active) VALUES
('11111111-1111-1111-1111-111111111111', 'super_admin', 'Super Administrador', 'Acceso total al sistema', '#DC2626', true, true),
('22222222-2222-2222-2222-222222222222', 'admin', 'Administrador', 'Administrador del sistema con gestión completa', '#7C3AED', true, true),
('33333333-3333-3333-3333-333333333333', 'manager', 'Gerente', 'Gestión de equipos y proyectos', '#059669', true, true),
('44444444-4444-4444-4444-444444444444', 'employee', 'Empleado', 'Usuario estándar del sistema', '#2563EB', true, true),
('55555555-5555-5555-5555-555555555555', 'guest', 'Invitado', 'Acceso limitado de solo lectura', '#6B7280', true, true);

-- 2. INSERTAR PERMISOS DEL SISTEMA
INSERT INTO permissions (name, display_name, description, module, action, resource, is_system) VALUES
-- GESTIÓN DE USUARIOS
('users.create', 'Crear Usuarios', 'Crear nuevos usuarios en el sistema', 'users', 'create', 'all', true),
('users.read.all', 'Ver Todos los Usuarios', 'Ver información de todos los usuarios', 'users', 'read', 'all', true),
('users.read.own', 'Ver Perfil Propio', 'Ver y editar su propio perfil', 'users', 'read', 'own', true),
('users.update.all', 'Editar Todos los Usuarios', 'Editar información de cualquier usuario', 'users', 'update', 'all', true),
('users.update.own', 'Editar Perfil Propio', 'Editar su propio perfil', 'users', 'update', 'own', true),
('users.delete', 'Eliminar Usuarios', 'Eliminar usuarios del sistema', 'users', 'delete', 'all', true),
('users.export', 'Exportar Usuarios', 'Exportar datos de usuarios', 'users', 'export', 'all', true),

-- GESTIÓN DE ROLES Y PERMISOS
('roles.create', 'Crear Roles', 'Crear nuevos roles en el sistema', 'roles', 'create', 'all', true),
('roles.read', 'Ver Roles', 'Ver roles y permisos del sistema', 'roles', 'read', 'all', true),
('roles.update', 'Editar Roles', 'Modificar roles y asignar permisos', 'roles', 'update', 'all', true),
('roles.delete', 'Eliminar Roles', 'Eliminar roles del sistema', 'roles', 'delete', 'all', true),
('roles.assign', 'Asignar Roles', 'Asignar roles a usuarios', 'roles', 'assign', 'all', true),

-- GESTIÓN DE PROYECTOS
('projects.create', 'Crear Proyectos', 'Crear nuevos proyectos', 'projects', 'create', 'all', true),
('projects.read.all', 'Ver Todos los Proyectos', 'Ver todos los proyectos', 'projects', 'read', 'all', true),
('projects.read.own', 'Ver Proyectos Propios', 'Ver solo proyectos asignados', 'projects', 'read', 'own', true),
('projects.update.all', 'Editar Todos los Proyectos', 'Editar cualquier proyecto', 'projects', 'update', 'all', true),
('projects.update.own', 'Editar Proyectos Propios', 'Editar solo proyectos asignados', 'projects', 'update', 'own', true),
('projects.delete', 'Eliminar Proyectos', 'Eliminar proyectos', 'projects', 'delete', 'all', true),
('projects.assign', 'Asignar Proyectos', 'Asignar usuarios a proyectos', 'projects', 'assign', 'all', true),

-- GESTIÓN FINANCIERA
('finance.read', 'Ver Finanzas', 'Ver información financiera', 'finance', 'read', 'all', true),
('finance.manage', 'Gestionar Finanzas', 'Gestionar presupuestos y finanzas', 'finance', 'update', 'all', true),
('finance.reports', 'Reportes Financieros', 'Generar reportes financieros', 'finance', 'reports', 'all', true),
('finance.approve', 'Aprobar Gastos', 'Aprobar gastos y presupuestos', 'finance', 'approve', 'all', true),

-- GESTIÓN DE CONTRATOS
('contracts.create', 'Crear Contratos', 'Crear nuevos contratos', 'contracts', 'create', 'all', true),
('contracts.read', 'Ver Contratos', 'Ver contratos del sistema', 'contracts', 'read', 'all', true),
('contracts.update', 'Editar Contratos', 'Modificar contratos existentes', 'contracts', 'update', 'all', true),
('contracts.approve', 'Aprobar Contratos', 'Aprobar y firmar contratos', 'contracts', 'approve', 'all', true),
('contracts.delete', 'Eliminar Contratos', 'Eliminar contratos', 'contracts', 'delete', 'all', true),

-- ADMINISTRACIÓN DEL SISTEMA
('system.settings', 'Configuración del Sistema', 'Acceder a configuración del sistema', 'system', 'settings', 'all', true),
('system.logs', 'Ver Logs del Sistema', 'Ver logs y auditoría del sistema', 'system', 'logs', 'all', true),
('system.backup', 'Respaldos del Sistema', 'Crear y restaurar respaldos', 'system', 'backup', 'all', true),
('system.maintenance', 'Modo Mantenimiento', 'Activar modo mantenimiento', 'system', 'maintenance', 'all', true),

-- REPORTES Y ANALYTICS
('reports.create', 'Crear Reportes', 'Crear reportes personalizados', 'reports', 'create', 'all', true),
('reports.read', 'Ver Reportes', 'Ver reportes del sistema', 'reports', 'read', 'all', true),
('reports.export', 'Exportar Reportes', 'Exportar reportes a diferentes formatos', 'reports', 'export', 'all', true),
('analytics.read', 'Ver Analytics', 'Ver dashboards y métricas', 'analytics', 'read', 'all', true),
('analytics.advanced', 'Analytics Avanzados', 'Acceso a analytics avanzados', 'analytics', 'advanced', 'all', true),

-- COMUNICACIÓN Y NOTIFICACIONES
('notifications.send', 'Enviar Notificaciones', 'Enviar notificaciones a usuarios', 'notifications', 'send', 'all', true),
('notifications.manage', 'Gestionar Notificaciones', 'Configurar sistemas de notificación', 'notifications', 'manage', 'all', true),
('messages.send', 'Enviar Mensajes', 'Enviar mensajes internos', 'messages', 'send', 'all', true),
('messages.broadcast', 'Difundir Mensajes', 'Enviar mensajes masivos', 'messages', 'broadcast', 'all', true);

-- 3. ASIGNAR PERMISOS A ROLES

-- SUPER ADMIN: TODOS LOS PERMISOS
INSERT INTO role_permissions (role_id, permission_id)
SELECT '11111111-1111-1111-1111-111111111111', p.id 
FROM permissions p;

-- ADMIN: GESTIÓN COMPLETA EXCEPTO SISTEMA CRÍTICO
INSERT INTO role_permissions (role_id, permission_id)
SELECT '22222222-2222-2222-2222-222222222222', p.id 
FROM permissions p 
WHERE p.name NOT IN ('system.backup', 'system.maintenance');

-- MANAGER: GESTIÓN DE EQUIPOS Y PROYECTOS
INSERT INTO role_permissions (role_id, permission_id)
SELECT '33333333-3333-3333-3333-333333333333', p.id 
FROM permissions p 
WHERE p.name IN (
    'users.read.all', 'users.update.own',
    'projects.create', 'projects.read.all', 'projects.update.all', 'projects.assign',
    'contracts.create', 'contracts.read', 'contracts.update',
    'finance.read', 'finance.reports',
    'reports.create', 'reports.read', 'reports.export',
    'analytics.read',
    'notifications.send', 'messages.send'
);

-- EMPLOYEE: TRABAJO DIARIO
INSERT INTO role_permissions (role_id, permission_id)
SELECT '44444444-4444-4444-4444-444444444444', p.id 
FROM permissions p 
WHERE p.name IN (
    'users.read.own', 'users.update.own',
    'projects.read.own', 'projects.update.own',
    'contracts.read',
    'reports.read',
    'messages.send'
);

-- GUEST: SOLO LECTURA BÁSICA
INSERT INTO role_permissions (role_id, permission_id)
SELECT '55555555-5555-5555-5555-555555555555', p.id 
FROM permissions p 
WHERE p.name IN (
    'users.read.own',
    'projects.read.own',
    'contracts.read',
    'reports.read'
);

-- 4. INSERTAR USUARIOS CON HASHES CORRECTOS
-- Contraseñas: admin123, test123, mod123, demo123

-- Usuario Super Admin
INSERT INTO users (id, email, password_hash, first_name, last_name, role_id, email_verified, is_active, created_at) 
VALUES (
    'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
    'superadmin@system.com',
    '$2a$12$JBpL6vBJZXix0RC3dI4H7Owhna1LQKEIYWeZ4ghXQiE6W2wiJylMa',
    'Super',
    'Admin',
    '11111111-1111-1111-1111-111111111111',
    true,
    true,
    NOW()
);

-- Usuario Admin Principal
INSERT INTO users (id, email, password_hash, first_name, last_name, role_id, email_verified, is_active, created_at) 
VALUES (
    'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
    'admin@admin.com',
    '$2a$12$JBpL6vBJZXix0RC3dI4H7Owhna1LQKEIYWeZ4ghXQiE6W2wiJylMa',
    'Admin',
    'User',
    '22222222-2222-2222-2222-222222222222',
    true,
    true,
    NOW()
);

-- Usuario Manager
INSERT INTO users (id, email, password_hash, first_name, last_name, role_id, email_verified, is_active, created_at) 
VALUES (
    'cccccccc-cccc-cccc-cccc-cccccccccccc',
    'manager@test.com',
    '$2a$12$V/6LpqIc8GJ3dAF8.jbPsOIkwGKQqJv0c7ZFdDZJKW8Bt6h5Jt9tu',
    'Project',
    'Manager',
    '33333333-3333-3333-3333-333333333333',
    true,
    true,
    NOW()
);

-- Usuario Empleado
INSERT INTO users (id, email, password_hash, first_name, last_name, role_id, email_verified, is_active, created_at) 
VALUES (
    'dddddddd-dddd-dddd-dddd-dddddddddddd',
    'employee@test.com',
    '$2a$12$d4rhSXNBdCiFb4CcpNlTquUBJzcvaC7H.pFESOH/cAeudCxaabOPy',
    'Test',
    'Employee',
    '44444444-4444-4444-4444-444444444444',
    true,
    true,
    NOW()
);

-- Usuario Invitado
INSERT INTO users (id, email, password_hash, first_name, last_name, role_id, email_verified, is_active, created_at) 
VALUES (
    'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee',
    'guest@test.com',
    '$2a$12$8K5DGE.oUJCZR8xPH/Qb.e1JQsHrJI9jDYFwLPtCq6kBo3d7xFGhi',
    'Guest',
    'User',
    '55555555-5555-5555-5555-555555555555',
    true,
    true,
    NOW()
);

-- Usuario demo sin rol para testing
INSERT INTO users (id, email, password_hash, first_name, last_name, role_id, email_verified, is_active, created_at) 
VALUES (
    'ffffffff-ffff-ffff-ffff-ffffffffffff',
    'demo@demo.com',
    '$2a$12$8K5DGE.oUJCZR8xPH/Qb.e1JQsHrJI9jDYFwLPtCq6kBo3d7xFGhi',
    'Demo',
    'User',
    NULL,
    true,
    true,
    NOW()
);

-- =================== FUNCIONES ÚTILES ===================

-- Función para verificar permisos
CREATE OR REPLACE FUNCTION user_has_permission(
    p_user_id UUID,
    p_permission_name VARCHAR
) RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1 
        FROM users u
        JOIN roles r ON u.role_id = r.id
        JOIN role_permissions rp ON r.id = rp.role_id
        JOIN permissions p ON rp.permission_id = p.id
        WHERE u.id = p_user_id 
        AND p.name = p_permission_name
        AND r.is_active = true
        AND u.is_active = true
    );
END;
$$ LANGUAGE plpgsql;

-- Función para obtener permisos de usuario
CREATE OR REPLACE FUNCTION get_user_permissions(p_user_id UUID)
RETURNS TABLE(permission_name VARCHAR, module VARCHAR, action VARCHAR, resource VARCHAR) AS $$
BEGIN
    RETURN QUERY
    SELECT DISTINCT
        p.name,
        p.module,
        p.action,
        p.resource
    FROM users u
    JOIN roles r ON u.role_id = r.id
    JOIN role_permissions rp ON r.id = rp.role_id
    JOIN permissions p ON rp.permission_id = p.id
    WHERE u.id = p_user_id
    AND r.is_active = true
    AND u.is_active = true
    
    UNION
    
    SELECT DISTINCT
        p.name,
        p.module,
        p.action,
        p.resource
    FROM users u
    JOIN user_permissions up ON u.id = up.user_id
    JOIN permissions p ON up.permission_id = p.id
    WHERE u.id = p_user_id
    AND up.is_granted = true
    AND (up.expires_at IS NULL OR up.expires_at > CURRENT_TIMESTAMP)
    AND u.is_active = true;
END;
$$ LANGUAGE plpgsql;

-- Función para obtener rol de usuario
CREATE OR REPLACE FUNCTION get_user_role(p_user_id UUID)
RETURNS TABLE(role_name VARCHAR, role_display_name VARCHAR, role_color VARCHAR) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        r.name,
        r.display_name,
        r.color
    FROM users u
    JOIN roles r ON u.role_id = r.id
    WHERE u.id = p_user_id
    AND u.is_active = true
    AND r.is_active = true;
END;
$$ LANGUAGE plpgsql;

-- =================== VISTAS ÚTILES ===================

-- Vista de usuarios con roles
CREATE VIEW users_with_roles AS
SELECT 
    u.id,
    u.email,
    u.first_name,
    u.last_name,
    u.is_active,
    u.email_verified,
    u.created_at,
    u.updated_at,
    u.last_login,
    r.id as role_id,
    r.name as role_name,
    r.display_name as role_display_name,
    r.color as role_color,
    r.is_system as role_is_system
FROM users u
LEFT JOIN roles r ON u.role_id = r.id;

-- Vista de estadísticas del sistema
CREATE VIEW system_stats AS
SELECT 
    (SELECT COUNT(*) FROM users WHERE is_active = true) as total_active_users,
    (SELECT COUNT(*) FROM users WHERE role_id IS NULL) as users_without_role,
    (SELECT COUNT(*) FROM roles WHERE is_active = true) as total_active_roles,
    (SELECT COUNT(*) FROM roles WHERE is_system = false) as custom_roles,
    (SELECT COUNT(*) FROM permissions) as total_permissions,
    (SELECT COUNT(DISTINCT module) FROM permissions) as total_modules;

-- =================== DATOS DE EJEMPLO ADICIONALES ===================

-- Insertar algunos permisos personalizados de ejemplo
INSERT INTO permissions (name, display_name, description, module, action, resource, is_system) VALUES
('inventory.manage', 'Gestionar Inventario', 'Administrar inventario de productos', 'inventory', 'manage', 'all', false),
('sales.view', 'Ver Ventas', 'Ver reportes de ventas', 'sales', 'view', 'all', false),
('hr.manage', 'Gestionar RRHH', 'Administrar recursos humanos', 'hr', 'manage', 'all', false);

-- =================== MENSAJE FINAL ===================
DO $$
DECLARE
    user_count INTEGER;
    role_count INTEGER;
    permission_count INTEGER;
    assignment_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO user_count FROM users;
    SELECT COUNT(*) INTO role_count FROM roles;
    SELECT COUNT(*) INTO permission_count FROM permissions;
    SELECT COUNT(*) INTO assignment_count FROM role_permissions;
    
    RAISE NOTICE '========================================';
    RAISE NOTICE '🚀 SISTEMA COMPLETO INICIALIZADO';
    RAISE NOTICE '========================================';
    RAISE NOTICE 'Usuarios creados: %', user_count;
    RAISE NOTICE 'Roles creados: %', role_count;
    RAISE NOTICE 'Permisos creados: %', permission_count;
    RAISE NOTICE 'Asignaciones creadas: %', assignment_count;
    RAISE NOTICE '';
    RAISE NOTICE '🔑 CREDENCIALES DISPONIBLES:';
    RAISE NOTICE '   👑 Super Admin: superadmin@system.com / admin123';
    RAISE NOTICE '   🔧 Admin:       admin@admin.com / admin123';
    RAISE NOTICE '   👔 Manager:     manager@test.com / mod123';
    RAISE NOTICE '   👤 Employee:    employee@test.com / test123';
    RAISE NOTICE '   👁️ Guest:       guest@test.com / demo123';
    RAISE NOTICE '   🎮 Demo:        demo@demo.com / demo123 (sin rol)';
    RAISE NOTICE '';
    RAISE NOTICE '🌐 ACCESO COMPLETO:';
    RAISE NOTICE '   📱 Frontend:    http://localhost:3000';
    RAISE NOTICE '   🛡️ Roles:       http://localhost:3000/frontend/roles.html';
    RAISE NOTICE '   📊 Dashboard:   http://localhost:3000/frontend/dashboard.html';
    RAISE NOTICE '   🧪 Demo:        http://localhost:3000/frontend/demo-complete.html';
    RAISE NOTICE '';
    RAISE NOTICE '✅ LISTO PARA USAR - TODO FUNCIONA DESDE EL INICIO';
    RAISE NOTICE '========================================';
END $$;