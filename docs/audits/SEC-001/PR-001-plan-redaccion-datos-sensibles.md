# SEC-001-01 — Plan de redacción de datos sensibles

Estado: plan histórico del cambio implementado y validado. La preparación de publicación permanece pendiente de revisión humana y no autoriza commit, push ni publicación de artefactos. Véase el [resultado de implementación](PR-001-resultado-implementacion.md).

## Objetivo y alcance

Evitar que los objetos de autenticación y sesión expongan credenciales o datos personales al convertirse a texto. El cambio se limita a siete implementaciones de toString: seis tipos de datos y el builder de sesión.

Todas las rutas de este documento son relativas a la raíz del repositorio. No se modifican autenticación, endpoints, cookies, persistencia, configuración, dependencias o contratos JSON. Tampoco se alteran campos, constructores, getters, setters, componentes de records, métodos fluidos, build, equals o hashCode.

## Archivos y representaciones

Base productiva: `src/main/java/com/davidrr/security/`.

| Archivo | Datos excluidos de la representación | Salida constante |
|---|---|---|
| `auth/dto/AuthRequest.java` | Nombre de usuario y contraseña | `AuthRequest[REDACTED]` |
| `auth/dto/RegisterRequest.java` | Nombre de usuario, correo y contraseña | `RegisterRequest[REDACTED]` |
| `auth/dto/AuthResponse.java` | Access token | `AuthResponse[REDACTED]` |
| `auth/dto/AuthTokens.java` | Access token y refresh token | `AuthTokens[REDACTED]` |
| `auth/dto/RefreshRotationResult.java` | Nombre de usuario y refresh token | `RefreshRotationResult[REDACTED]` |
| `auth/session/model/RefreshSession.java` | Identidad, verificadores de token, vínculo al sucesor y metadatos de sesión | `RefreshSession[REDACTED]` |
| Builder anidado en el archivo anterior | Los mismos valores que almacena durante la construcción | `RefreshSession.RefreshSessionBuilder[REDACTED]` |

Los overrides retornan únicamente constantes: no leen campos ni getters, ni muestran fragmentos, longitudes o derivados de secretos. En los records se conserva el modificador final del método. Las anotaciones Lombok se mantienen; el builder parcial declara solo su toString y Lombok continúa generando su API y constructor con la visibilidad anterior.

No se emplean anotaciones Jackson para ocultar datos: los valores necesarios deben seguir disponibles mediante accesores y transporte. La redacción protege esta representación textual, no impide el acceso deliberado a los datos por otros mecanismos.

## Pruebas previstas y realizadas

| Archivo | Cobertura | Casos validados |
|---|---|---:|
| `src/test/java/com/davidrr/security/auth/SensitiveRepresentationsTest.java` | Siete tipos, null/vacíos/Unicode, texto con saltos de línea, conversiones implícitas, builder vacío/parcial/completo/reutilizado e integridad de datos | 8 |
| `src/test/java/com/davidrr/security/auth/AuthenticationJsonContractTest.java` | JSON de requests, respuesta con token, round-trip de records y transporte HTTP aislado | 4 |
| `src/test/java/com/davidrr/security/auth/PublicSurfaceCompatibilityTest.java` | Constructores, componentes, accesores, métodos del builder, igualdad y hashCode | 3 |
| `src/test/compat/LegacySensitiveDtoConsumer.java` | Cliente compilado contra 0.4.0 y ejecutado con las clases candidatas | Programa independiente |

Resultado documentado de JUnit: **15 pruebas ejecutadas, 0 fallos, 0 errores y 0 skips**. El programa legacy no se suma a ese contador. Todos los datos de prueba son sintéticos.

El caso HTTP usa MockMvc standalone con un controlador exclusivamente de prueba. Comprueba access token íntegro en la propiedad token de AuthResponse y refresh token solo en cookie. No ejecuta un backend consumidor real ni sus filtros y no crea endpoints productivos.

## Compatibilidad y criterios de aceptación

Se conserva la API/ABI del alcance frente a 0.4.0: nombres de tipos, declaraciones, modificadores y descriptores, incluidos los constructores de paquete y los componentes de records. La comparación normaliza únicamente espacios y orden de declaraciones, no diferencias de firma.

El cliente legacy se compila contra el JAR 0.4.0 y se ejecuta con las clases nuevas. Esa evidencia se complementa con la compilación y los tests; no certifica todos los consumidores externos.

Los criterios son: siete salidas constantes, datos originales intactos, API/ABI preservada y transporte sin redacción accidental. El texto anterior de toString cambia deliberadamente y puede afectar a consumidores que lo parseen. No se promete proteger serializers personalizados, logging directo de campos, subclases externas o dumps.

## Comprobaciones reproducibles

Requisitos: JDK 17 y Maven disponibles en PATH, y acceso autorizado a las dependencias declaradas. No es necesario editar el POM. Los siguientes comandos son instrucciones; no se ejecutan al preparar esta edición pública.

```powershell
mvn -B test-compile
mvn -B org.apache.maven.plugins:maven-surefire-plugin:3.2.5:test '-Dtest=SensitiveRepresentationsTest,AuthenticationJsonContractTest,PublicSurfaceCompatibilityTest' '-DfailIfNoTests=true' '-Dsurefire.failIfNoSpecifiedTests=true'
```

Leer los tres XML nuevos de `target/surefire-reports`, comprobando nombres de clase, número de casos y contadores. BUILD SUCCESS por sí solo no demuestra que se hayan ejecutado las pruebas esperadas.

Para revisar firmas, usar javap -p -s sobre los siete tipos, comparando el JAR baseline con target/classes de la compilación nueva. Definir MAVEN_REPO como la ubicación del repositorio Maven local; no sustituir el baseline ni ejecutar install/deploy para esta comprobación.

## Preparación de publicación

La selección pública se limita a diez archivos Java y estos dos documentos. No incorpora informes privados de auditoría. Antes del futuro commit se deben revisar el contenido seleccionado y la identidad pública de autor/committer. La preferencia es una identidad de GitHub con correo noreply confirmado por su titular; no se presupone ni se inventa esa dirección.
