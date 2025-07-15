-- Extensiones necesarias
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- =================== USUARIOS (Tabla existente mejorada) ===================
DROP TABLE IF EXISTS refresh_tokens CASCADE;
DROP TABLE IF EXISTS users CASCADE;

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    role VARCHAR(50) DEFAULT 'user',
    is_active BOOLEAN DEFAULT true,
    email_verified BOOLEAN DEFAULT false,
    phone VARCHAR(20),
    avatar_url VARCHAR(500),
    last_login TIMESTAMP,
    login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

-- =================== SISTEMA DE ROLES Y PERMISOS ===================

-- Tabla de roles (predefinidos y personalizados)
CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(50) UNIQUE NOT NULL,
    display_name VARCHAR(100) NOT NULL,
    description TEXT,
    is_system_role BOOLEAN DEFAULT false, -- roles del sistema no se pueden eliminar
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabla de permisos
CREATE TABLE permissions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) UNIQUE NOT NULL,
    display_name VARCHAR(150) NOT NULL,
    description TEXT,
    service VARCHAR(50) NOT NULL, -- auth, products, orders, etc.
    resource VARCHAR(50) NOT NULL, -- users, products, orders, etc.
    action VARCHAR(50) NOT NULL, -- create, read, update, delete, manage
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabla de relación roles-permisos (muchos a muchos)
CREATE TABLE role_permissions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(role_id, permission_id)
);

-- Tabla de permisos específicos por usuario (para casos especiales)
CREATE TABLE user_permissions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    granted BOOLEAN DEFAULT true, -- true = otorgar, false = denegar
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by UUID REFERENCES users(id),
    UNIQUE(user_id, permission_id)
);

-- =================== MICROSERVICIOS Y ACCESOS ===================

-- Tabla de microservicios registrados
CREATE TABLE microservices (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) UNIQUE NOT NULL,
    display_name VARCHAR(150) NOT NULL,
    description TEXT,
    url VARCHAR(500) NOT NULL,
    health_check_url VARCHAR(500),
    api_key VARCHAR(255), -- para comunicación entre servicios
    is_active BOOLEAN DEFAULT true,
    version VARCHAR(20),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabla de accesos de usuarios a microservicios
CREATE TABLE user_microservice_access (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    microservice_id UUID NOT NULL REFERENCES microservices(id) ON DELETE CASCADE,
    granted BOOLEAN DEFAULT true,
    granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    granted_by UUID REFERENCES users(id),
    expires_at TIMESTAMP, -- acceso temporal
    notes TEXT,
    UNIQUE(user_id, microservice_id)
);

-- =================== AUDITORÍA ===================

-- Tabla de auditoría de acciones
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    resource VARCHAR(100) NOT NULL,
    resource_id UUID,
    details JSONB,
    ip_address INET,
    user_agent TEXT,
    microservice VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabla de refresh tokens (mejorada)
CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_revoked BOOLEAN DEFAULT false,
    revoked_at TIMESTAMP,
    revoked_by UUID REFERENCES users(id)
);

-- =================== ÍNDICES PARA OPTIMIZACIÓN ===================
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_users_active ON users(is_active);
CREATE INDEX idx_users_created_at ON users(created_at);

CREATE INDEX idx_roles_name ON roles(name);
CREATE INDEX idx_permissions_service_resource_action ON permissions(service, resource, action);
CREATE INDEX idx_role_permissions_role_id ON role_permissions(role_id);
CREATE INDEX idx_role_permissions_permission_id ON role_permissions(permission_id);

CREATE INDEX idx_user_permissions_user_id ON user_permissions(user_id);
CREATE INDEX idx_user_microservice_access_user_id ON user_microservice_access(user_id);
CREATE INDEX idx_user_microservice_access_microservice_id ON user_microservice_access(microservice_id);

CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);

CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_token ON refresh_tokens(token);

-- =================== TRIGGERS ===================

-- Trigger para actualizar updated_at en users
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at 
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_roles_updated_at 
    BEFORE UPDATE ON roles
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_microservices_updated_at 
    BEFORE UPDATE ON microservices
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Trigger para auditoría automática
CREATE OR REPLACE FUNCTION audit_trigger_function()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO audit_logs (user_id, action, resource, resource_id, details)
        VALUES (NEW.created_by, 'CREATE', TG_TABLE_NAME, NEW.id, to_jsonb(NEW));
        RETURN NEW;
    ELSIF TG_OP = 'UPDATE' THEN
        INSERT INTO audit_logs (user_id, action, resource, resource_id, details)
        VALUES (NEW.updated_by, 'UPDATE', TG_TABLE_NAME, NEW.id, jsonb_build_object('old', to_jsonb(OLD), 'new', to_jsonb(NEW)));
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        INSERT INTO audit_logs (action, resource, resource_id, details)
        VALUES ('DELETE', TG_TABLE_NAME, OLD.id, to_jsonb(OLD));
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- =================== DATOS INICIALES ===================

-- Insertar roles del sistema
INSERT INTO roles (name, display_name, description, is_system_role) VALUES
('super_admin', 'Super Administrador', 'Acceso completo a todo el sistema', true),
('admin', 'Administrador', 'Gestión completa de usuarios y configuración', true),
('moderator', 'Moderador', 'Gestión de contenido y usuarios limitada', true),
('user', 'Usuario', 'Usuario estándar con permisos básicos', true),
('viewer', 'Visualizador', 'Solo lectura en la mayoría de recursos', true);

-- Insertar permisos del sistema
INSERT INTO permissions (name, display_name, description, service, resource, action) VALUES
-- Permisos de usuarios
('users.create', 'Crear Usuarios', 'Crear nuevos usuarios en el sistema', 'auth', 'users', 'create'),
('users.read', 'Ver Usuarios', 'Ver información de usuarios', 'auth', 'users', 'read'),
('users.update', 'Editar Usuarios', 'Modificar información de usuarios', 'auth', 'users', 'update'),
('users.delete', 'Eliminar Usuarios', 'Eliminar usuarios del sistema', 'auth', 'users', 'delete'),
('users.manage_roles', 'Gestionar Roles', 'Asignar y cambiar roles de usuarios', 'auth', 'users', 'manage'),

-- Permisos de roles y permisos
('roles.create', 'Crear Roles', 'Crear nuevos roles', 'auth', 'roles', 'create'),
('roles.read', 'Ver Roles', 'Ver roles existentes', 'auth', 'roles', 'read'),
('roles.update', 'Editar Roles', 'Modificar roles existentes', 'auth', 'roles', 'update'),
('roles.delete', 'Eliminar Roles', 'Eliminar roles personalizados', 'auth', 'roles', 'delete'),

-- Permisos de microservicios
('microservices.create', 'Registrar Microservicios', 'Registrar nuevos microservicios', 'auth', 'microservices', 'create'),
('microservices.read', 'Ver Microservicios', 'Ver microservicios registrados', 'auth', 'microservices', 'read'),
('microservices.update', 'Editar Microservicios', 'Modificar configuración de microservicios', 'auth', 'microservices', 'update'),
('microservices.delete', 'Eliminar Microservicios', 'Eliminar microservicios', 'auth', 'microservices', 'delete'),
('microservices.manage_access', 'Gestionar Accesos', 'Controlar acceso de usuarios a microservicios', 'auth', 'microservices', 'manage'),

-- Permisos de auditoría
('audit.read', 'Ver Auditoría', 'Ver logs de auditoría del sistema', 'auth', 'audit', 'read'),

-- Permisos del sistema
('system.admin', 'Administración Sistema', 'Acceso completo a administración del sistema', 'auth', 'system', 'admin');

-- Asignar permisos a roles
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.name = 'super_admin'; -- Super admin tiene todos los permisos

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.name = 'admin' 
AND p.name IN (
    'users.create', 'users.read', 'users.update', 'users.delete', 'users.manage_roles',
    'roles.read', 'microservices.read', 'microservices.manage_access', 'audit.read'
);

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.name = 'moderator' 
AND p.name IN (
    'users.read', 'users.update', 'roles.read', 'microservices.read'
);

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.name = 'user' 
AND p.name IN (
    'users.read'
);

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.name = 'viewer' 
AND p.name IN (
    'users.read', 'roles.read', 'microservices.read'
);

-- Insertar microservicios de ejemplo
INSERT INTO microservices (name, display_name, description, url, health_check_url) VALUES
('auth-service', 'Servicio de Autenticación', 'Servicio principal de autenticación y usuarios', 'http://localhost:3001', 'http://localhost:3001/health'),
('user-service', 'Servicio de Usuarios', 'Gestión avanzada de usuarios', 'http://localhost:3002', 'http://localhost:3002/health');

-- Crear usuario administrador principal
INSERT INTO users (email, password_hash, first_name, last_name, role, email_verified, is_active) 
VALUES (
    'admin@admin.com',
    '$2a$12$H8KzbM4ejJhZjZLgEgtkcuKas0NMP/0moqDtzaZLmW7It81TJHaG2',
    'Admin',
    'User',
    'super_admin',
    true,
    true
);

-- =================== VISTAS ÚTILES ===================

-- Vista de usuarios con sus permisos
CREATE VIEW user_permissions_view AS
SELECT 
    u.id as user_id,
    u.email,
    u.first_name,
    u.last_name,
    u.role,
    p.name as permission,
    p.display_name as permission_display,
    p.service,
    p.resource,
    p.action,
    'role' as source
FROM users u
JOIN roles r ON u.role = r.name
JOIN role_permissions rp ON r.id = rp.role_id
JOIN permissions p ON rp.permission_id = p.id
WHERE u.is_active = true

UNION

SELECT 
    u.id as user_id,
    u.email,
    u.first_name,
    u.last_name,
    u.role,
    p.name as permission,
    p.display_name as permission_display,
    p.service,
    p.resource,
    p.action,
    CASE WHEN up.granted THEN 'granted' ELSE 'denied' END as source
FROM users u
JOIN user_permissions up ON u.id = up.user_id
JOIN permissions p ON up.permission_id = p.id
WHERE u.is_active = true;

-- Vista de accesos a microservicios
CREATE VIEW user_microservice_access_view AS
SELECT 
    u.id as user_id,
    u.email,
    u.first_name,
    u.last_name,
    u.role,
    m.name as microservice,
    m.display_name as microservice_display,
    m.url,
    uma.granted,
    uma.granted_at,
    uma.expires_at,
    uma.notes
FROM users u
LEFT JOIN user_microservice_access uma ON u.id = uma.user_id
LEFT JOIN microservices m ON uma.microservice_id = m.id
WHERE u.is_active = true;

COMMENT ON TABLE users IS 'Tabla principal de usuarios del sistema';
COMMENT ON TABLE roles IS 'Roles disponibles en el sistema';
COMMENT ON TABLE permissions IS 'Permisos granulares del sistema';
COMMENT ON TABLE microservices IS 'Microservicios registrados en el ecosistema';
COMMENT ON TABLE audit_logs IS 'Registro de auditoría de todas las acciones';