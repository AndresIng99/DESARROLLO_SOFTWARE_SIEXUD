# 🚀 Sistema de Microservicios - Funciona de UNA

## ⚡ Instalación Ultra Rápida

```bash
# 1. Clonar proyecto
git clone <tu-repositorio>
cd microservices-auth

# 2. Levantar (TODO automático)
docker-compose up --build -d

# 3. Esperar 3 minutos y listo!
```

## 🔑 Credenciales que SÍ funcionan

| Usuario | Email | Contraseña | Rol |
|---------|-------|------------|-----|
| **Admin** | `admin@admin.com` | `admin123` | admin |
| **Test** | `test@test.com` | `test123` | user |
| **Moderador** | `moderator@test.com` | `mod123` | moderator |
| **Demo** | `demo@demo.com` | `demo123` | user |

## 🌐 URLs que funcionan

- **🏠 Inicio:** http://localhost:3000
- **📊 Dashboard:** http://localhost:3000/frontend/dashboard.html
- **🧪 Demo:** http://localhost:3000/frontend/demo-complete.html
- **🔧 pgAdmin:** http://localhost:5050 (admin@admin.com / admin)

## ✅ Test Rápido

```bash
# Verificar que funciona
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@admin.com","password":"admin123"}'

# Debería devolver: {"success":true, ...}
```

## 🎯 Flujo de Uso

1. **Ir a:** http://localhost:3000
2. **Login:** admin@admin.com / admin123
3. **¡Listo!** Ya puedes usar todo el sistema

## 🚨 Si no funciona

```bash
# Limpiar todo y empezar de cero
docker-compose down -v
docker-compose up --build -d

# Esperar 3 minutos y probar de nuevo
```

## 📱 Servicios Incluidos

- ✅ **API Gateway** (Puerto 3000) - Frontend + APIs
- ✅ **Auth Service** (Puerto 3001) - Autenticación
- ✅ **User Service** (Puerto 3002) - Gestión usuarios
- ✅ **Hello Service** (Puerto 3010) - Demo microservicio
- ✅ **PostgreSQL** (Puerto 5432) - Base de datos
- ✅ **Redis** (Puerto 6379) - Cache
- ✅ **pgAdmin** (Puerto 5050) - Admin BD

## 🎉 ¡Todo configurado y listo!

**Tiempo total:** 5 minutos desde cero hasta funcionando completamente.