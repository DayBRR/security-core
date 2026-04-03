# 🔐 security-core

**security-core** es una librería modular de seguridad basada en Spring
Security diseñada para ser **reutilizable, desacoplada y lista para
producción**.

Proporciona un sistema completo de autenticación y gestión de sesiones
basado en JWT con capacidades avanzadas de seguridad.

## 📦 Version

Current version: **v0.2.0**

------------------------------------------------------------------------

## ✨ Features

-   🔐 Autenticación JWT (access + refresh)
-   🔄 Refresh token rotation
-   🚫 Reuse detection (detección de robo de token)
-   📱 Gestión de sesiones por dispositivo
-   🧠 Fingerprinting (IP + User-Agent)
-   🚨 Detección de sesiones sospechosas
-   🔒 Logout individual y global
-   📋 Listado de sesiones activas
-   🧪 Tests de integración incluidos

------------------------------------------------------------------------

## 🧱 Arquitectura

    com.davidrr.security
     ├─ config
     ├─ jwt
     ├─ auth
     ├─ session
     └─ common

### 🔸 Componentes clave

-   `JwtService` → generación y validación de tokens\
-   `AuthService` → lógica de autenticación\
-   `RefreshTokenService` → gestión de refresh tokens\
-   `SessionService` → gestión de sesiones\
-   `SecurityConfig` → configuración Spring Security

------------------------------------------------------------------------

## 🚀 Tech Stack

-   ☕ Java 17\
-   🌱 Spring Boot 3\
-   🔐 Spring Security\
-   🧩 Spring Data JPA\
-   🧠 JWT (io.jsonwebtoken)\
-   🧪 JUnit 5

------------------------------------------------------------------------

## 📦 Instalación

### Maven

``` xml
<dependency>
  <groupId>com.davidrr</groupId>
  <artifactId>security-core</artifactId>
  <version>0.0.1-SNAPSHOT</version>
</dependency>
```

------------------------------------------------------------------------

## ⚙️ Configuración

``` yaml
security:
  jwt:
    secret-key: your-secret-key
    expiration: 900000
  cookie:
    refresh-name: refreshToken
    secure: false
    same-site: Lax
    path: /auth/refresh
    max-age-days: 14
```

------------------------------------------------------------------------

## 🔑 Endpoints

Endpoint                Descripción
  ----------------------- -----------------
POST /auth/login        Login
POST /auth/refresh      Refresh token
POST /auth/logout       Logout
POST /auth/logout-all   Logout global
GET /auth/sessions      Listar sesiones

------------------------------------------------------------------------

## 🧩 Integración

Para usar esta librería, tu aplicación debe proporcionar:

-   👤 Entidad `User`
-   📦 Repositorio de usuarios
-   🔌 Implementación de `UserDetailsService`
-   🧠 Adaptadores de persistencia (ej: sesiones)

------------------------------------------------------------------------

## 🧠 Filosofía

Este módulo está diseñado bajo principios de:

-   🔌 Desacoplamiento total
-   ♻️ Reutilización
-   🧱 Arquitectura modular
-   🔒 Seguridad por defecto

------------------------------------------------------------------------

## 🔮 Roadmap

-   🛡️ Rate limiting
-   🔐 Bloqueo progresivo anti brute force
-   🧠 Fingerprint avanzado
-   📊 Logging de seguridad
-   ⚙️ Conversión a Spring Boot Starter
-   📦 Publicación en Maven Central

------------------------------------------------------------------------

## 🧩 Git Workflow --- Commit & Branch Conventions

Este proyecto usa **Conventional Commits**.

### 📌 Tipos de commit

| Type       | Meaning                                            |
|------------|----------------------------------------------------|
| **feat**   | Nueva funcionalidad                                |
| **fix**    | Corrección de bug                                  |
| **refactor** | Mejora interna                                     |
| **chore**  | Mantenimiento                                      |
| **docs**   | Documentación                                      |
| **style**  | Estilo                                             |
| **test**   | Incluir o modificar tests                          |
| **build**  | Construcción cambios del sistema (Maven, plugins…) |


------------------------------------------------------------------------

### 📌 Formato de commit

    <type>: <short description>

------------------------------------------------------------------------

## 👨‍💻 Author

David Ruiz\
https://www.davidrr.com

------------------------------------------------------------------------

> Secure once. Reuse everywhere.
