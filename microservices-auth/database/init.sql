-- Extensiones necesarias
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Limpiar datos existentes si existen
DROP TABLE IF EXISTS refresh_tokens CASCADE;
DROP TABLE IF EXISTS users CASCADE;

-- Tabla de usuarios
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    role VARCHAR(50) DEFAULT 'user',
    is_active BOOLEAN DEFAULT true,
    email_verified BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
);

-- Tabla de tokens de refresh
CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_revoked BOOLEAN DEFAULT false
);

-- Índices para optimización
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_token ON refresh_tokens(token);

-- Trigger para actualizar updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- =================== USUARIOS CON HASHES QUE FUNCIONAN ===================

-- Usuario admin (email: admin@admin.com, password: admin123)
-- Hash generado y probado: $2a$10$JBpL6vBJZXix0RC3dI4H7Owhna1LQKEIYWeZ4ghXQiE6W2wiJylMa
INSERT INTO users (id, email, password_hash, first_name, last_name, role, email_verified, is_active, created_at) 
VALUES (
    uuid_generate_v4(),
    'admin@admin.com',
    '$2a$10$JBpL6vBJZXix0RC3dI4H7Owhna1LQKEIYWeZ4ghXQiE6W2wiJylMa',
    'Admin',
    'User',
    'admin',
    true,
    true,
    NOW()
);

-- Usuario test (email: test@test.com, password: test123)
-- Hash generado y probado: $2a$10$d4rhSXNBdCiFb4CcpNlTquUBJzcvaC7H.pFESOH/cAeudCxaabOPy
INSERT INTO users (id, email, password_hash, first_name, last_name, role, email_verified, is_active, created_at) 
VALUES (
    uuid_generate_v4(),
    'test@test.com',
    '$2a$10$d4rhSXNBdCiFb4CcpNlTquUBJzcvaC7H.pFESOH/cAeudCxaabOPy',
    'Test',
    'User',
    'user',
    true,
    true,
    NOW()
);

-- Usuario moderator (email: moderator@test.com, password: mod123)
-- Hash para mod123: $2a$10$V/6LpqIc8GJ3dAF8.jbPsOIkwGKQqJv0c7ZFdDZJKW8Bt6h5Jt9tu
INSERT INTO users (id, email, password_hash, first_name, last_name, role, email_verified, is_active, created_at) 
VALUES (
    uuid_generate_v4(),
    'moderator@test.com',
    '$2a$10$V/6LpqIc8GJ3dAF8.jbPsOIkwGKQqJv0c7ZFdDZJKW8Bt6h5Jt9tu',
    'Moderator',
    'User',
    'moderator',
    true,
    true,
    NOW()
);

-- Usuario demo (email: demo@demo.com, password: demo123)
-- Hash para demo123: $2a$10$8K5DGE.oUJCZR8xPH/Qb.e1JQsHrJI9jDYFwLPtCq6kBo3d7xFGhi
INSERT INTO users (id, email, password_hash, first_name, last_name, role, email_verified, is_active, created_at) 
VALUES (
    uuid_generate_v4(),
    'demo@demo.com',
    '$2a$10$8K5DGE.oUJCZR8xPH/Qb.e1JQsHrJI9jDYFwLPtCq6kBo3d7xFGhi',
    'Demo',
    'User',
    'user',
    true,
    true,
    NOW()
);

-- Mensaje de confirmación
DO $$
DECLARE
    user_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO user_count FROM users;
    RAISE NOTICE '========================================';
    RAISE NOTICE '✅ SISTEMA LISTO - USUARIOS CREADOS EXITOSAMENTE';
    RAISE NOTICE '========================================';
    RAISE NOTICE 'Total de usuarios: %', user_count;
    RAISE NOTICE '';
    RAISE NOTICE '🔑 CREDENCIALES PARA LOGIN:';
    RAISE NOTICE '   👑 Admin:     admin@admin.com / admin123';
    RAISE NOTICE '   👤 Test:      test@test.com / test123';
    RAISE NOTICE '   🛡️ Moderador: moderator@test.com / mod123';
    RAISE NOTICE '   🎮 Demo:      demo@demo.com / demo123';
    RAISE NOTICE '';
    RAISE NOTICE '🌐 ACCESO DIRECTO:';
    RAISE NOTICE '   http://localhost:3000';
    RAISE NOTICE '   Usar: admin@admin.com / admin123';
    RAISE NOTICE '========================================';
END $$;