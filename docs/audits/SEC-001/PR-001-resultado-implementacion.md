# SEC-001-01 — Resultado de implementación

Estado: implementación y validación focalizada completadas; preparación de publicación pendiente de revisión humana. Este documento no constituye aprobación de commit, push, merge ni release Maven.

## Resultado final

La validación del 21 de noviembre de 2026 terminó con compilación Maven satisfactoria y **15 pruebas JUnit ejecutadas, 0 fallos, 0 errores y 0 skips**. La API/ABI de los siete tipos del alcance se mantuvo frente a 0.4.0 y el cliente legacy terminó correctamente.

Estos resultados corresponden al código previamente validado. Los diez archivos Java se trasladan sin cambios a la preparación pública. Esta preparación no ejecuta una compilación o suite nueva; la igualdad de contenido se verifica mediante Git. El [plan público](PR-001-plan-redaccion-datos-sensibles.md) describe alcance y límites.

## Cambios productivos

Base: `src/main/java/com/davidrr/security/`.

- `auth/dto/AuthRequest.java`.
- `auth/dto/RegisterRequest.java`.
- `auth/dto/AuthResponse.java`.
- `auth/dto/AuthTokens.java`.
- `auth/dto/RefreshRotationResult.java`.
- `auth/session/model/RefreshSession.java`, incluido RefreshSessionBuilder.

Se añadieron siete overrides con constantes que contienen [REDACTED], sin leer los valores originales. El builder sigue generado por Lombok, con una declaración parcial que personaliza únicamente toString.

Se conservan campos, anotaciones, constructores, accesores, setters, componentes de records, métodos fluidos, build, equals y hashCode. No se modificaron endpoints, contratos JSON, cookies, lógica de autenticación, persistencia, POM o dependencias. El diff productivo consta de seis archivos, 37 inserciones y dos eliminaciones; incluye la incorporación de salto de línea final en dos archivos.

## Compilación y pruebas

Entorno de validación: JDK 17, Maven 3.9.6, compiler 3.13.0 y Surefire 3.2.5. Se recompilaron 47 fuentes productivos y tres fuentes JUnit, con target Java 17. Los datos de prueba son exclusivamente sintéticos.

Comandos equivalentes portables de la validación realizada, con JAVA_HOME y PATH preparados para JDK 17 y Maven:

```powershell
mvn -B test-compile
mvn -B org.apache.maven.plugins:maven-surefire-plugin:3.2.5:test '-Dtest=SensitiveRepresentationsTest,AuthenticationJsonContractTest,PublicSurfaceCompatibilityTest' '-DfailIfNoTests=true' '-Dsurefire.failIfNoSpecifiedTests=true'
```

La compilación y Surefire finalizaron con BUILD SUCCESS y código de salida 0. Se leyeron los tres informes XML nuevos, contrastando los atributos de suite y el número de elementos testcase. No se dedujo el resultado únicamente del mensaje de Maven.

| Clase, bajo com.davidrr.security.auth | Tests | Fallos | Errores | Skips |
|---|---:|---:|---:|---:|
| SensitiveRepresentationsTest | 8 | 0 | 0 | 0 |
| AuthenticationJsonContractTest | 4 | 0 | 0 | 0 |
| PublicSurfaceCompatibilityTest | 3 | 0 | 0 | 0 |
| **Total** | **15** | **0** | **0** | **0** |

Los informes de ejecución se generaron el 2026-11-21 en `target/surefire-reports`. Son artefactos de validación, no archivos incluidos en esta preparación pública. El contador coincide con lo previsto: seis entradas parametrizadas y dos casos simples de representación, cuatro casos JSON/HTTP y tres de superficie pública.

## Resultado JSON y HTTP

Los cuatro casos de AuthenticationJsonContractTest comprobaron:

- Nombres y valores JSON de los requests, incluida su deserialización.
- AuthResponse con la única propiedad token, íntegra, y compatibilidad del valor null.
- Componentes y round-trip JSON de los dos records.
- Un fixture HTTP con access token en el body y refresh token solo en Set-Cookie, sin [REDACTED] en el transporte.

El fixture usa MockMvc standalone y un controlador definido únicamente en tests. No se ejecutó un backend consumidor real, su cadena de seguridad o una prueba integral de despliegue. No se añadieron endpoints productivos.

## Compatibilidad fuente y binaria

Se compararon con javap -p -s los siete tipos frente al JAR 0.4.0, tanto para el candidato aislado como para las clases de la compilación Maven. Resultado: siete de siete sin diferencias en declaraciones, modificadores y descriptores, normalizando espacios y orden de declaraciones. Se conservan los constructores de paquete y el public final de los métodos de los records.

El fixture `src/test/compat/LegacySensitiveDtoConsumer.java` se compiló contra el JAR antiguo y se ejecutó con las clases candidatas nuevas, sin usar el baseline como implementación en runtime. Terminó con código 0 y resultado PASS. También pasó al ejecutarse con las clases generadas por Maven. Es un programa independiente y no se suma a las 15 pruebas JUnit.

Para reproducirlo, definir MAVEN_REPO como repositorio Maven local y crear un directorio de salida nuevo bajo target. Usar javac --release 17 -proc:none con el JAR 0.4.0 como classpath de compilación; ejecutar después con el directorio del fixture y target/classes como classpath. No instalar ni sustituir el baseline para realizar esta comparación.

## Incidencias y límites

Una primera ejecución offline no pudo resolver las dependencias necesarias. La validación online posterior completó compilación y pruebas sin cambiar POM, versiones o código. Ese bloqueo es histórico y no representa el estado final. Se mantuvo sin cambios una advertencia de codificación dependiente de plataforma, ajena al alcance.

El formato textual de toString cambia deliberadamente. Los consumidores que lo utilicen como formato de intercambio pueden necesitar adaptación. Esta protección no cubre accesos explícitos mediante getters, serializers personalizados, logging de campos, subclases externas, debugger o dumps. No constituye una certificación global de seguridad ni de todos los consumidores de la librería.

## Estado de publicación

La preparación pública contiene los diez archivos Java del cambio y las dos ediciones públicas de plan y resultado. No incorpora documentos privados de auditoría ni artefactos de target. El nuevo commit aún no se ha creado y la identidad pública de autor/committer debe confirmarse antes: se prefiere un correo noreply de GitHub facilitado por su titular.

La implementación y validación no publicaron artefactos Maven ni sustituyeron el baseline 0.4.0. Esta preparación no realiza commits, pushes, merges, tags, install, deploy ni creación de Pull Requests remotos. La autorización de cualquier acción posterior se solicita por separado.
