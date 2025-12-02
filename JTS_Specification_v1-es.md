
# Documento de Archivo del Proyecto: Sistema de Tokens Janus (JTS)

**Título:** Sistema de Tokens Janus (JTS): Una Arquitectura de Dos Componentes para Autenticación de API Segura, Revocable y Confidencial

**Estado:** Borrador de Estándar, Versión 1.1

**Autor/Pionero:** ukungzulfah

**Fecha de Publicación:** 30 de noviembre de 2025

> **Resumen:**
> Este documento define el **Sistema de Tokens Janus (JTS)**, un nuevo estándar de autenticación diseñado para abordar los desafíos de seguridad y escalabilidad en los ecosistemas de aplicaciones distribuidas modernas (por ejemplo, arquitectura de microservicios). JTS introduce una arquitectura de dos componentes que separa fundamentalmente la **prueba de acceso a corto plazo (`BearerPass`)** de la **prueba de sesión a largo plazo (`StateProof`)**. Este enfoque permite una verificación de acceso extremadamente rápida y *sin estado* (stateless) mientras se retiene la capacidad vital para la gestión de sesiones *con estado* (stateful), incluida la revocación instantánea de sesiones. Este documento define tres perfiles operativos: **JTS-S (Estándar)** para una integridad total con características de seguridad completas, **JTS-L (Ligero)** para una implementación ligera con una complejidad mínima, y **JTS-C (Confidencialidad)** para una confidencialidad total de la carga útil. Esta especificación también introduce una nueva terminología de reclamaciones para reemplazar términos heredados menos intuitivos.

---

### **Licencia de Derechos de Autor**
> Copyright © 2025, ukungzulfah. Todos los Derechos Reservados.
>
> Por la presente se concede permiso, de forma gratuita, a cualquier persona que obtenga una copia de esta especificación y la documentación asociada ("el Software"), para usar, copiar, modificar, fusionar, publicar, distribuir y/o vender copias del Software, sujeto a las siguientes condiciones:
>
> El aviso de derechos de autor anterior y este aviso de permiso se incluirán en todas las copias o partes sustanciales del Software. EL SOFTWARE SE PROPORCIONA "TAL CUAL", SIN GARANTÍA DE NINGÚN TIPO, EXPRESA O IMPLÍCITA.

---

### **1. Introducción**

#### **1.1. Desafíos de la Autenticación Moderna**
En la arquitectura de software moderna, las aplicaciones se dividen en servicios pequeños e independientes (microservicios). Este modelo exige un sistema de autenticación que sea ligero, descentralizado y que no dependa de una única sesión centralizada y monolítica.

#### **1.2. Limitaciones de los Modelos de Tokens sin Estado de Primera Generación**
Los modelos de autenticación basados en tokens sin estado de primera generación proporcionaron una solución parcial pero introdujeron debilidades significativas:
1.  **Vulnerabilidad de Revocación de Sesión:** Los tokens emitidos no pueden ser invalidados forzosamente desde el lado del servidor antes de su tiempo de expiración.
2.  **Exposición de Información:** La carga útil del token a menudo está simplemente codificada, no cifrada, por lo que los datos internos pueden ser leídos por cualquier parte que posea el token.
3.  **Complejidad en la Gestión de Claves:** El uso de una clave simétrica compartida crea un punto único de fallo de alto riesgo en un entorno distribuido.

#### **1.3. Un Nuevo Paradigma: Sistema de Tokens Janus (JTS)**
JTS se propone como una evolución para abordar estas debilidades. Con su principio de dualidad, JTS combina la eficiencia *sin estado* con la seguridad *con estado*.

### **2. Conceptos Centrales de JTS**

#### **2.1. Principio de Dualidad**
JTS separa el rol de un token en dos:
1.  **Acceso:** Otorgar permiso para acceder a recursos por una duración muy corta.
2.  **Sesión:** Probar la validez de la sesión de autenticación general del usuario.

#### **2.2. Los Dos Componentes de JTS**
1.  **`BearerPass`:** Un token de acceso de corta duración, firmado criptográficamente. Se utiliza en cada solicitud de API y se verifica sin estado.
2.  **`StateProof`:** Un token de sesión de larga duración, opaco y con estado. Se utiliza exclusivamente para obtener un nuevo `BearerPass` y se almacena de forma segura en el lado del cliente. Su existencia en la base de datos del servidor determina la validez de una sesión.

### **3. Terminología y Reclamaciones de JTS**

Como refinamiento, JTS introduce una terminología de reclamaciones más explícita e intuitiva, alejándose de términos heredados ambiguos.

| Reclamación JTS | Nombre Completo | Descripción | Reemplaza |
| :--- | :--- | :--- | :--- |
| **`prn`** | **Principal** | Identificador único para el principal autenticado (generalmente un usuario). | `sub` |
| **`aid`** | **Anchor ID** | Un ID único que "ancla" el `BearerPass` al registro de sesión en el servidor. | `sid` |
| **`tkn_id`**| **Token ID** | Un identificador único для cada `BearerPass`, previniendo ataques de repetición. | `jti` |
| `exp` | Expiration Time | Tiempo de expiración del token (retenido de RFC 7519). | - |
| `aud` | Audience | El destinatario previsto para este token (retenido de RFC 7519). | - |
| `iat` | Issued At | El momento en que se emitió el token (retenido de RFC 7519). | - |

#### **3.2. Reclamaciones Extendidas**

JTS define reclamaciones adicionales para una seguridad y funcionalidad más robustas:

| Reclamación JTS | Nombre Completo | Descripción | Requerido |
| :--- | :--- | :--- | :--- |
| **`dfp`** | **Device Fingerprint** | Hash de las características del dispositivo para vincular el token a un dispositivo específico. | No |
| **`perm`**| **Permissions** | Un arreglo de cadenas que definen los permisos/ámbitos que posee el token. | No |
| **`grc`** | **Grace Period** | Tolerancia de tiempo (en segundos) después de `exp` para solicitudes en tránsito. | No |
| **`org`** | **Organization** | Identificador de inquilino/organización para sistemas multi-inquilino. | No |
| **`atm`** | **Auth Method** | Método de autenticación utilizado (p. ej., `pwd`, `mfa:totp`, `sso`). | No |
| **`ath`** | **Auth Time** | Marca de tiempo Unix de cuándo el usuario realizó una autenticación activa por última vez. | No |
| **`spl`** | **Session Policy** | La política de sesión concurrente en vigor (`allow_all`, `single`, `max:n`). | No |

**Ejemplo de Carga Útil con Reclamaciones Extendidas:**
```json
{
  "prn": "user-12345",
  "aid": "session-anchor-abcdef",
  "tkn_id": "token-instance-98765",
  "aud": "https://api.example.com/billing",
  "exp": 1764515700,
  "iat": 1764515400,
  "dfp": "sha256:a1b2c3d4e5f6...",
  "perm": ["read:profile", "write:posts", "billing:view"],
  "grc": 30,
  "org": "tenant-acme-corp",
  "atm": "mfa:totp",
  "ath": 1764512000
}
```

### **4. Perfil Estándar: JTS-S (Integridad)**

Este perfil se centra en la velocidad, la integridad y las capacidades de revocación de sesión.

#### **4.1. Estructura de `BearerPass` (Formato JWS)**
El `BearerPass` en el perfil JTS-S es una **Firma Web JSON (JWS)** firmada con **criptografía asimétrica (p. ej., RS256)**.

**Ejemplo de Encabezado:**
```json
{
  "alg": "RS256",
  "typ": "JTS-S/v1",
  "kid": "auth-server-key-2025-001"
}
```

**Nota:** La reclamación `kid` (ID de Clave) es OBLIGATORIA para admitir la rotación de claves (ver Sección 7).

**Ejemplo de Carga Útil:**
```json
{
  "prn": "user-12345",
  "aid": "session-anchor-abcdef",
  "tkn_id": "token-instance-98765",
  "aud": "https://api.example.com/billing",
  "exp": 1764515700,
  "iat": 1764515400
}
```

#### **4.2. Flujo de Trabajo**
1.  **Autenticación:** El usuario inicia sesión -> El servidor crea un registro de sesión en la BD, generando un `StateProof` (almacenado en la BD) y un `BearerPass` (JWS). El `StateProof` se envía a través de una cookie `HttpOnly`, el `BearerPass` a través del cuerpo JSON.
2.  **Acceso a Recursos:** El cliente envía el `BearerPass` en el encabezado -> El servidor verifica la firma JWS usando la clave pública.
3.  **Renovación:** El `BearerPass` expira -> El cliente llama al endpoint `/renew` con el `StateProof` en la cookie -> El servidor valida el `StateProof` en la BD; si es válido, emite un nuevo `BearerPass`.
4.  **Revocación (Cierre de sesión):** El cliente llama a `/logout` -> El servidor elimina el registro de sesión asociado con el `StateProof` de la BD. La sesión se vuelve inválida inmediatamente.

#### **4.3. Requisitos de Cookies y Protección CSRF**

El `StateProof` almacenado en una cookie DEBE cumplir con los siguientes requisitos de seguridad:

**Atributos de Cookie OBLIGATORIOS:**
```
Set-Cookie: jts_state_proof=<token>; 
  HttpOnly; 
  Secure; 
  SameSite=Strict; 
  Path=/jts; 
  Max-Age=604800
```

| Atributo | Valor | Descripción |
| :--- | :--- | :--- |
| `HttpOnly` | OBLIGATORIO | Previene el acceso desde JavaScript (mitiga XSS). |
| `Secure` | OBLIGATORIO | La cookie solo se envía a través de HTTPS. |
| `SameSite` | `Strict` | Previene el envío de la cookie en solicitudes de sitios cruzados (mitiga CSRF). |
| `Path` | `/jts` | Limita la cookie para ser enviada solo a los endpoints de JTS. |
| `Max-Age` | Según política | Vida útil de la cookie según la política de sesión. |

**Protección CSRF Adicional:**

Para los endpoints `/renew` y `/logout`, el servidor DEBE validar al menos UNO de los siguientes mecanismos:

1.  **Validación del Encabezado Origin:** Asegurar que el encabezado `Origin` o `Referer` provenga de un dominio permitido.
2.  **Requisito de Encabezado Personalizado:** Requerir un encabezado personalizado que no pueda ser establecido por un envío de formulario estándar:
    ```
    X-JTS-Request: 1
    ```
3.  **Patrón de Doble Envío de Cookie:** Enviar un valor de token CSRF tanto en una cookie COMO en el cuerpo/encabezado de la solicitud, y luego validar que coincidan.

#### **4.4. Rotación de StateProof**

Para mejorar la seguridad y detectar el robo de tokens, JTS REQUIERE la rotación de `StateProof` en cada operación de renovación.

**Mecanismo:**
1.  El cliente llama a `/renew` con el `StateProof` antiguo.
2.  El servidor valida el `StateProof` antiguo en la base de datos.
3.  Si es válido:
    a.  El servidor ELIMINA o MARCA el `StateProof` antiguo como *consumido*.
    b.  El servidor emite un NUEVO `StateProof` y un nuevo `BearerPass`.
    c.  El nuevo `StateProof` se envía a través de un encabezado `Set-Cookie`.
4.  Si el `StateProof` antiguo ya está marcado como *consumido* (repetición detectada):
    a.  El servidor DEBE revocar inmediatamente TODAS las sesiones asociadas con ese `aid`.
    b.  El servidor DEBE devolver un error `JTS-401-05` (Sesión Comprometida).
    c.  El servidor DEBERÍA enviar una notificación de seguridad al usuario.

**Diagrama de Rotación:**
```
[Cliente]                              [Servidor de Autenticación]     [Base de Datos]
    |                                       |                               |
    |-- POST /renew (StateProof_v1) ------->|                               |
    |                                       |-- Validar StateProof_v1 ---->|
    |                                       |<-- Válido, marcar como consumido ---|
    |                                       |                               |
    |                                       |-- Generar StateProof_v2 ---->|
    |                                       |<-- Almacenado --------------------|
    |                                       |                               |
    |<-- 200 OK (BearerPass_nuevo) ---------|                               |
    |<-- Set-Cookie: StateProof_v2 ---------|                               |
    |                                       |                               |
```

**Detección de Anomalías (Ataque de Repetición):**
```
[Atacante]                            [Servidor de Autenticación]     [Base de Datos]
    |                                       |                               |
    |-- POST /renew (StateProof_v1) ------->|  (token robado)               |
    |                                       |-- Validar StateProof_v1 ---->|
    |                                       |<-- ¡CONSUMIDO! Repetición detectada -|
    |                                       |                               |
    |                                       |-- REVOCAR todas las sesiones (aid) ->|
    |                                       |<-- Hecho ----------------------|
    |                                       |                               |
    |<-- 401 JTS-401-05 (Comprometido) ------|
    |                                       |                               |
```

#### **4.5. Manejo de Condiciones de Carrera en Renovaciones Concurrentes**

En escenarios donde un usuario tiene múltiples pestañas/ventanas o las solicitudes de renovación ocurren casi simultáneamente, existe el riesgo de una detección de repetición *falsa positiva*. JTS define un mecanismo de **Ventana de Gracia de Rotación** para manejar esta condición.

**Problema:**
```
[Pestaña A]                               [Servidor de Autenticación]     [Base de Datos]
    |-- POST /renew (SP_v1) ------------->|                               |
    |                                     |-- Marcar SP_v1 consumido -------->|
    |                                     |                               |
[Pestaña B]  (ligeramente retrasada)     |                               |
    |-- POST /renew (SP_v1) ------------->|                               |
    |                                     |-- Comprobar SP_v1 --------------->|
    |                                     |<-- ¡CONSUMIDO! (falso positivo) |
    |<-- 401 JTS-401-05 ??? --------------|  (¡usuario no comprometido!)      |
```

**Solución: Ventana de Gracia de Rotación**

El servidor DEBE implementar una **ventana de gracia de rotación** con las siguientes especificaciones:

1.  **Duración de la Ventana de Gracia:** El servidor DEBE almacenar el `previous_state_proof` durante **5-10 segundos** después de una rotación.
2.  **Validación Dual:** Durante la ventana de gracia, el servidor DEBE aceptar TANTO el `current_state_proof` COMO el `previous_state_proof`.
3.  **Respuesta para el Token Anterior:** Si una solicitud utiliza un `previous_state_proof` que todavía está dentro de la ventana de gracia:
    -   El servidor DEBE devolver el MISMO `StateProof` y `BearerPass` que ya se generaron para el `current_state_proof`.
    -   El servidor NO DEBE generar nuevos tokens (previene la divergencia de tokens).
4.  **Después de la Ventana de Gracia:** Una solicitud con un `previous_state_proof` que ha pasado la ventana de gracia DEBE ser tratada como un ataque de repetición.

**Implementación de Base de Datos:**
```sql
CREATE TABLE jts_sessions (
    aid                   VARCHAR(64) PRIMARY KEY,
    prn                   VARCHAR(128) NOT NULL,
    current_state_proof   VARCHAR(256) NOT NULL,
    previous_state_proof  VARCHAR(256),           -- Token anterior
    rotation_timestamp    TIMESTAMP,              -- Cuándo ocurrió la última rotación
    -- ... otras columnas
);
```

**Lógica de Validación:**
```
function validate_state_proof(incoming_sp):
    session = db.find_by_current_sp(incoming_sp)
    if session:
        return VALID, session
    
    session = db.find_by_previous_sp(incoming_sp)
    if session:
        grace_window = 10 seconds
        if now() - session.rotation_timestamp < grace_window:
            return VALID_WITHIN_GRACE, session  // Devolver tokens existentes
        else:
            trigger_replay_detection(session.aid)
            return REPLAY_DETECTED, null
    
    return INVALID, null
```

**Diagrama de Renovación Concurrente (Manejado):**
```
[Pestaña A]                               [Servidor de Autenticación]     [Base de Datos]
    |-- POST /renew (SP_v1) ------------->|                               |
    |                                     |-- Rotar: SP_v1 -> SP_v2 ---->|
    |                                     |   (almacenar previous=SP_v1)      |
    |<-- 200 OK (BP_nuevo, SP_v2) ---------|                               |
    |                                     |                               |
[Pestaña B]  (dentro de 10 segundos)     |                               |
    |-- POST /renew (SP_v1) ------------->|                               |
    |                                     |-- Comprobar SP_v1 --------------->|
    |                                     |<-- Encontrado en previous_sp,      |
    |                                     |    dentro de la ventana de gracia -------|
    |<-- 200 OK (BP_nuevo, SP_v2) ---------|  (mismos tokens que la Pestaña A)       |
    |                                     |                               |
```

> **Nota:** Ambas pestañas ahora tienen el mismo `StateProof` (SP_v2), permaneciendo así sincronizadas.

#### **4.6. Período de Gracia para Solicitudes en Tránsito**

Para manejar condiciones de carrera donde un `BearerPass` expira mientras una solicitud está en tránsito:

**Especificación:**
-   Un Servidor de Recursos PUEDE proporcionar una tolerancia de tiempo (*período de gracia*) después del tiempo `exp`.
-   El período de gracia NO DEBE exceder los **60 segundos**.
-   Si la reclamación `grc` está presente en la carga útil, su valor define el período de gracia en segundos.
-   Si la reclamación `grc` no está presente, el período de gracia predeterminado es de **0 segundos** (sin tolerancia).

**Lógica de Validación:**
```
current_time = now()
effective_expiry = token.exp + token.grc (or 0 if grc is not present)

if current_time > effective_expiry:
    return ERROR_TOKEN_EXPIRED
else:
    return VALID
```

**Nota:** El período de gracia NO extiende la vida útil del token para fines de auditoría. El tiempo `exp` original todavía se utiliza para el registro.

### **5. Perfil Ligero: JTS-L (Lite)**

Este perfil está diseñado para casos de uso de baja complejidad que requieren facilidad de implementación sin sacrificar los principios de seguridad básicos de JTS.

#### **5.1. Cuándo Usar JTS-L**

JTS-L es adecuado para los siguientes escenarios:

| Escenario | Recomendación | Razón |
| :--- | :--- | :--- |
| MVP de Startup / Prototipo | ✅ JTS-L | Rápido de implementar, se puede actualizar a JTS-S más tarde. |
| Herramientas Internas / Panel de Admin | ✅ JTS-L | Pequeña base de usuarios, menor riesgo. |
| Aplicación de Página Única Simple | ✅ JTS-L | No necesita detección de repetición compleja. |
| API Pública con datos sensibles | ❌ Usar JTS-S | Necesita protección contra repetición y vinculación de dispositivos. |
| Fintech / Salud | ❌ Usar JTS-S/C | Se requiere máxima conformidad y seguridad. |
| SaaS Multi-inquilino | ❌ Usar JTS-S | Necesita aislamiento y registros de auditoría completos. |

#### **5.2. Diferencias Clave con JTS-S**

| Característica | JTS-S (Estándar) | JTS-L (Ligero) |
| :--- | :--- | :--- |
| Rotación de StateProof | ✅ OBLIGATORIA en cada `/renew` | ❌ OPCIONAL |
| Detección de Repetición | ✅ Incorporada mediante marcado de consumido | ⚠️ Manual / ninguna |
| Huella Digital del Dispositivo (`dfp`) | ✅ Recomendado | ❌ No requerido |
| Período de Gracia (`grc`) | ✅ Soportado | ✅ Soportado |
| Reclamaciones Extendidas | ✅ Completo | ⚠️ Subconjunto mínimo |
| Política de Sesión Concurrente | ✅ Completa | ⚠️ Solo `allow_all` |
| Complejidad de la Base de Datos | Alta (seguimiento de tokens consumidos) | Baja (tabla de sesión simple) |
| Códigos de Error | Completo (todos los códigos) | Subconjunto esencial |

#### **5.3. Estructura de `BearerPass` en JTS-L**

El `BearerPass` en JTS-L todavía utiliza **JWS con criptografía asimétrica**, pero con una carga útil más minimalista.

**Encabezado:**
```json
{
  "alg": "RS256",
  "typ": "JTS-L/v1",
  "kid": "auth-server-key-2025-001"
}
```

**Carga Útil Mínima:**
```json
{
  "prn": "user-12345",
  "aid": "session-anchor-abcdef",
  "exp": 1764515700,
  "iat": 1764515400
}
```

**Nota:** La reclamación `tkn_id` es **OPCIONAL** en JTS-L porque no se requiere detección de repetición.

#### **5.4. Flujo de Trabajo de JTS-L (Simplificado)**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        FLUJO SIMPLIFICADO DE JTS-L                           │
└─────────────────────────────────────────────────────────────────────────────┘

[Cliente]                              [Servidor de Autenticación]     [Base de Datos]
    │                                       │                               │
    │── POST /login (credenciales) ─────────>│                               │
    │                                       │── Crear Sesión ────────────>│
    │                                       │<── ID de Sesión ────────────────│
    │<── 200 OK ────────────────────────────│                               │
    │    BearerPass (cuerpo)                  │                               │
    │    StateProof (cookie)                │                               │
    │                                       │                               │
    │   ... BearerPass expira ...          │                               │
    │                                       │                               │
    │── POST /renew (StateProof) ──────────>│                               │
    │                                       │── Comprobar si la Sesión Existe ──>│
    │                                       │<── Válido ─────────────────────│
    │                                       │   (SIN rotación, SIN consumido)  │
    │<── 200 OK ────────────────────────────│                               │
    │    BearerPass_nuevo (cuerpo)              │                               │
    │    (StateProof sin cambios)             │                               │
    │                                       │                               │
```

**Diferencias Clave:**
-   El `StateProof` **NO se rota** en cada `/renew`—el mismo token se puede usar múltiples veces mientras la sesión esté activa.
-   El servidor solo necesita comprobar si el registro de sesión **existe** en la base de datos, sin necesidad de rastrear un estado "consumido".
-   La complejidad de la base de datos se reduce significativamente.

#### **5.5. Esquema de Base de Datos de JTS-L**

La base de datos para JTS-L es mucho más simple:

```sql
-- JTS-L: Tabla de Sesión Simple
CREATE TABLE jts_sessions (
    aid             VARCHAR(64) PRIMARY KEY,  -- Anchor ID (StateProof)
    prn             VARCHAR(128) NOT NULL,    -- Principal (ID de Usuario)
    created_at      TIMESTAMP DEFAULT NOW(),
    expires_at      TIMESTAMP NOT NULL,
    last_active     TIMESTAMP DEFAULT NOW(),
    user_agent      TEXT,                     -- Opcional: para lista de sesiones
    ip_address      VARCHAR(45)               -- Opcional: para auditoría
);

-- Índice para consulta por usuario
CREATE INDEX idx_sessions_prn ON jts_sessions(prn);
```

**Comparar con JTS-S que requiere:**
```sql
-- JTS-S: Tabla de Sesión Completa con Seguimiento de Rotación
CREATE TABLE jts_sessions (
    aid                  VARCHAR(64) PRIMARY KEY,
    prn                  VARCHAR(128) NOT NULL,
    current_state_proof  VARCHAR(256) NOT NULL,
    previous_state_proof VARCHAR(256),        -- Para ventana de gracia
    state_proof_version  INTEGER DEFAULT 1,
    consumed_at          TIMESTAMP,             -- Detección de repetición
    device_fingerprint   VARCHAR(128),
    created_at           TIMESTAMP DEFAULT NOW(),
    expires_at           TIMESTAMP NOT NULL,
    last_active          TIMESTAMP DEFAULT NOW(),
    -- ... más columnas
);

-- Tabla adicional para rastrear tokens consumidos
CREATE TABLE jts_consumed_tokens (
    tkn_id          VARCHAR(64) PRIMARY KEY,
    aid             VARCHAR(64) REFERENCES jts_sessions(aid),
    consumed_at     TIMESTAMP DEFAULT NOW()
);
```

#### **5.6. Subconjunto de Códigos de Error para JTS-L**

JTS-L solo está OBLIGADO a implementar el siguiente subconjunto de códigos de error:

| Código de Error | Clave de Error | Descripción |
| :--- | :--- | :--- |
| `JTS-400-01` | `malformed_token` | No se pudo analizar el token. |
| `JTS-401-01` | `bearer_expired` | El BearerPass ha expirado. |
| `JTS-401-02` | `signature_invalid` | La firma no es válida. |
| `JTS-401-03` | `stateproof_invalid` | El StateProof no es válido. |
| `JTS-401-04` | `session_terminated` | La sesión ha sido terminada. |

**Los siguientes códigos de error NO son requeridos en JTS-L:**
-   `JTS-401-05` (session_compromised) — sin detección de repetición
-   `JTS-401-06` (device_mismatch) — sin vinculación de dispositivos
-   `JTS-403-03` (org_mismatch) — sin soporte multi-inquilino

#### **5.7. Migración de JTS-L a JTS-S**

JTS-L está diseñado para ser fácilmente actualizable a JTS-S a medida que aumentan las necesidades de seguridad:

**Pasos de Migración:**

1.  **Actualizar Tipo de Encabezado:**
    ```json
    // Antes
    { "typ": "JTS-L/v1" }
    // Después
    { "typ": "JTS-S/v1" }
    ```

2.  **Añadir Columnas a la Base de Datos:**
    ```sql
    ALTER TABLE jts_sessions 
    ADD COLUMN current_state_proof VARCHAR(256),
    ADD COLUMN state_proof_version INTEGER DEFAULT 1,
    ADD COLUMN consumed_at TIMESTAMP,
    ADD COLUMN device_fingerprint VARCHAR(128);
    ```

3.  **Implementar Rotación de StateProof:** Actualizar la lógica de `/renew` para generar un nuevo StateProof.

4.  **Añadir `tkn_id` a la Carga Útil:** Comenzar a generar un ID de token único para cada BearerPass.

5.  **Despliegue Gradual:**
    -   Fase 1: El servidor acepta tokens JTS-L y JTS-S
    -   Fase 2: Todos los nuevos tokens son JTS-S
    -   Fase 3: Rechazar tokens JTS-L después del tiempo de vida máximo de la sesión

#### **5.8. Limitaciones y Riesgos de JTS-L**

> ⚠️ **ADVERTENCIA:** Los implementadores DEBEN entender los siguientes riesgos antes de elegir JTS-L:

| Riesgo | Impacto | Mitigación |
| :--- | :--- | :--- |
| **Sin detección de repetición** | Un StateProof robado puede ser usado múltiples veces sin ser detectado. | Usar una `exp` más corta para la sesión. |
| **Sin vinculación de dispositivos** | El token puede ser usado desde un dispositivo diferente. | Implementar limitación de tasa basada en IP. |
| **El robo no se detecta** | El usuario no será notificado si su token es robado. | Monitorear patrones de inicio de sesión, notificar sobre nueva IP. |

**Recomendaciones de Mitigación para JTS-L:**
-   Establecer una expiración de `StateProof` más corta (máx. 24 horas vs. 7 días en JTS-S)
-   Implementar limitación de tasa en el endpoint `/renew`
-   Registrar toda la actividad de renovación para auditoría manual
-   Considerar notificaciones por correo electrónico para inicios de sesión desde una nueva IP/ubicación

---

### **6. Perfil de Confidencialidad: JTS-C (Confidentiality)**

Este perfil añade una capa de cifrado para la confidencialidad total de la carga útil.

#### **6.1. Estructura de `BearerPass` (Formato JWE)**
El `BearerPass` en el perfil JTS-C es un **Cifrado Web JSON (JWE)**. El token JWS del perfil estándar es "envuelto" o cifrado en un JWE.

#### **6.2. Flujo de Trabajo**
*   **Creación de Token ("Firmado y luego Cifrado"):**
    1.  Crear un JWS como en el perfil JTS-S.
    2.  Cifrar todo el JWS usando la **clave pública del Servidor de Recursos de destino**. El resultado es un JWE.
*   **Verificación de Token ("Descifrado y luego Verificado"):**
    1.  El Servidor de Recursos recibe el JWE.
    2.  El servidor descifra el JWE usando su **propia clave privada**. El resultado es el JWS original.
    3.  El servidor verifica el JWS usando la **clave pública del Servidor de Autenticación**.

### **7. Análisis de Seguridad y Manejo de Errores**

#### **7.1. Análisis de Seguridad**

*   **Revocación de Sesión:** Totalmente resuelto mediante la gestión de `StateProof` en la base de datos del servidor.
*   **Fuga de Credenciales:** Minimizado por el uso obligatorio de criptografía asimétrica y la protección del `StateProof` en una cookie `HttpOnly`.
*   **Fuga de Información:** Minimizado en JTS-S/JTS-L con una carga útil minimalista y totalmente resuelto en JTS-C a través del cifrado JWE.
*   **Ataques de Repetición:** Mitigado con un `tkn_id` único y la **rotación de StateProof** en JTS-S. **Nota:** JTS-L no proporciona protección automática contra repetición.
*   **Ataques XSS:** El riesgo de robo del token de sesión `StateProof` se reduce significativamente debido a la bandera `HttpOnly` en la cookie.
*   **Ataques CSRF:** Mitigado por una combinación de `SameSite=Strict` y validación de encabezado adicional.
*   **Robo de Token:** Mitigado con **Huella Digital del Dispositivo (`dfp`)** en JTS-S. **Nota:** JTS-L no soporta la vinculación de dispositivos.

#### **7.2. Códigos de Error Estándar**

JTS define códigos de error estándar para la consistencia de la implementación y la facilidad de depuración:

**Formato de Respuesta de Error:**
```json
{
  "error": "bearer_expired",
  "error_code": "JTS-401-01",
  "message": "BearerPass has expired",
  "action": "renew",
  "retry_after": 0,
  "timestamp": 1764515800
}
```

**Lista de Códigos de Error:**

| Código de Error | Estado HTTP | Clave de Error | Descripción | Acción |
| :--- | :--- | :--- | :--- | :--- |
| `JTS-400-01` | 400 | `malformed_token` | El token no pudo ser analizado o tiene un formato inválido. | `reauth` |
| `JTS-400-02` | 400 | `missing_claims` | Faltan reclamaciones requeridas en el token. | `reauth` |
| `JTS-401-01` | 401 | `bearer_expired` | El BearerPass ha expirado. | `renew` |
| `JTS-401-02` | 401 | `signature_invalid` | La firma del BearerPass no es válida. | `reauth` |
| `JTS-401-03` | 401 | `stateproof_invalid` | El StateProof no es válido o no se encontró en la BD. | `reauth` |
| `JTS-401-04` | 401 | `session_terminated` | La sesión fue terminada (cierre de sesión o política concurrente). | `reauth` |
| `JTS-401-05` | 401 | `session_compromised` | Se detectó un ataque de repetición; todas las sesiones son revocadas. | `reauth` |
| `JTS-401-06` | 401 | `device_mismatch` | La huella digital del dispositivo no coincide. | `reauth` |
| `JTS-403-01` | 403 | `audience_mismatch` | El token no está destinado a este recurso. | `none` |
| `JTS-403-02` | 403 | `permission_denied` | El token no tiene los permisos requeridos. | `none` |
| `JTS-403-03` | 403 | `org_mismatch` | El token pertenece a una organización/inquilino diferente. | `none` |
| `JTS-500-01` | 500 | `key_unavailable` | La clave pública para la verificación no está disponible. | `retry` |

**Valores de Acción:**
-   `renew`: El cliente debe llamar al endpoint `/renew` para obtener un nuevo BearerPass.
-   `reauth`: El usuario debe volver a autenticarse (iniciar sesión).
-   `retry`: La solicitud puede ser reintentada después de `retry_after` segundos.
-   `none`: Ninguna acción puede solucionar esta condición.

### **8. Gestión de Claves**

#### **8.1. Requisito de ID de Clave**

Cada `BearerPass` DEBE incluir una reclamación `kid` (ID de Clave) en el encabezado para identificar la clave utilizada para firmar.

**Formato de Encabezado con kid:**
```json
{
  "alg": "RS256",
  "typ": "JTS-S/v1",
  "kid": "auth-server-key-2025-001"
}
```

#### **8.2. Procedimiento de Rotación de Claves**

Para reemplazar una clave de firma sin invalidar los tokens ya emitidos:

**Pasos:**
1.  **Generar Nuevo Par de Claves:** Crear un nuevo par de claves con un `kid` único.
2.  **Publicar Clave Pública:** Añadir la nueva clave pública al endpoint JWKS. El servidor DEBE soportar múltiples claves públicas activas.
3.  **Comenzar a Firmar con la Nueva Clave:** Todos los nuevos tokens `BearerPass` se firman con la nueva clave.
4.  **Retirar Clave Antigua:** Después de `max_bearer_lifetime` + búfer (recomendación: 15 minutos), eliminar la clave pública antigua del JWKS.

**Respuesta del Endpoint JWKS:**
```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "auth-server-key-2025-002",
      "use": "sig",
      "alg": "RS256",
      "n": "...",
      "e": "AQAB"
    },
    {
      "kty": "RSA",
      "kid": "auth-server-key-2025-001",
      "use": "sig",
      "alg": "RS256",
      "n": "...",
      "e": "AQAB",
      "exp": 1764520000
    }
  ]
}
```

**Nota:** El campo `exp` en una entrada de clave indica cuándo se retirará la clave (opcional, para información del cliente).

#### **8.3. Endpoint JWKS Estándar**

JTS define una ruta estándar para el endpoint JWKS (Conjunto de Claves Web JSON) para que los Servidores de Recursos puedan encontrar consistentemente las claves públicas.

**Ruta Estándar:**
```
GET /.well-known/jts-jwks
```

**Requisitos:**

| Aspecto | Especificación |
| :--- | :--- |
| **Ruta** | `/.well-known/jts-jwks` (OBLIGATORIO) |
| **Método** | `GET` |
| **Autenticación** | No requerida (endpoint público) |
| **Content-Type** | `application/json` |
| **CORS** | DEBE permitir solicitudes de origen cruzado desde dominios válidos |

**Almacenamiento en Caché:**

El servidor DEBE incluir encabezados de caché apropiados:

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: public, max-age=3600, stale-while-revalidate=60
ETag: "jwks-v2-abc123"
```

| Encabezado | Valor Recomendado | Descripción |
| :--- | :--- | :--- |
| `Cache-Control` | `max-age=3600` | Almacenar en caché por 1 hora. |
| `stale-while-revalidate` | `60` | Permitir una respuesta obsoleta por 60 segundos mientras se revalida. |
| `ETag` | Hash del contenido de JWKS | Para solicitudes condicionales. |

**Descubrimiento (Opcional):**

Para soportar el auto-descubrimiento, el Servidor de Autenticación PUEDE proporcionar un endpoint de metadatos:

```
GET /.well-known/jts-configuration
```

**Respuesta:**
```json
{
  "issuer": "https://auth.example.com",
  "jwks_uri": "https://auth.example.com/.well-known/jts-jwks",
  "token_endpoint": "https://auth.example.com/jts/login",
  "renewal_endpoint": "https://auth.example.com/jts/renew",
  "revocation_endpoint": "https://auth.example.com/jts/logout",
  "supported_profiles": ["JTS-L/v1", "JTS-S/v1", "JTS-C/v1"],
  "supported_algorithms": ["RS256", "ES256"]
}
```

#### **8.4. Algoritmos Soportados**

JTS recomienda los siguientes algoritmos:

| Algoritmo | Tipo | Recomendación | Notas |
| :--- | :--- | :--- | :--- |
| `RS256` | Asimétrico | RECOMENDADO | RSA con SHA-256, ampliamente soportado. |
| `RS384` | Asimétrico | SOPORTADO | RSA con SHA-384. |
| `RS512` | Asimétrico | SOPORTADO | RSA con SHA-512. |
| `ES256` | Asimétrico | RECOMENDADO | ECDSA con P-256, más eficiente. |
| `ES384` | Asimétrico | SOPORTADO | ECDSA con P-384. |
| `ES512` | Asimétrico | SOPORTADO | ECDSA con P-521. |
| `PS256` | Asimétrico | SOPORTADO | RSASSA-PSS con SHA-256. |
| `HS256` | Simétrico | **NO PERMITIDO** | No se alinea con los principios de JTS. |
| `HS384` | Simétrico | **NO PERMITIDO** | No se alinea con los principios de JTS. |
| `HS512` | Simétrico | **NO PERMITIDO** | No se alinea con los principios de JTS. |
| `none` | - | **PROHIBIDO** | Sin firma, altamente inseguro. |

### **9. Política de Sesión Concurrente**

JTS define políticas para manejar situaciones en las que un solo usuario tiene múltiples sesiones activas.

> **Nota:** Las políticas de sesión concurrente solo se aplican a **JTS-S** y **JTS-C**. El perfil **JTS-L** solo admite la política `allow_all` por defecto.

#### **9.1. Opciones de Política**

| Política | Reclamación `spl` | Comportamiento |
| :--- | :--- | :--- |
| **Permitir Todas** | `allow_all` | Todas las sesiones son válidas simultáneamente sin límites. |
| **Única** | `single` | Solo una sesión activa. Un nuevo inicio de sesión invalida el antiguo. |
| **Máx N** | `max:3` | Máximo de N sesiones activas. La más antigua es expulsada si se excede. |
| **Notificar** | `notify` | Todas las sesiones son válidas, pero se notifica al usuario de las demás. |

#### **9.2. Implementación**

Cuando un usuario inicia sesión y la política limita el número de sesiones:
```
1. El usuario inicia sesión -> El servidor comprueba el número de sesiones activas para este `prn`
2. Si el conteo >= límite:
   a. Política "single": Revocar todas las sesiones antiguas, crear una nueva
   b. Política "max:n": Revocar la sesión más antigua (FIFO), crear una nueva
3. Crear un nuevo registro de sesión en la BD
4. Devolver StateProof y BearerPass
```

#### **9.3. Notificación de Sesión**

Para la política `notify`, el servidor DEBERÍA proporcionar un endpoint para ver las sesiones activas:

```
GET /jts/sessions
Authorization: Bearer <BearerPass>

Respuesta:
{
  "sessions": [
    {
      "aid": "session-anchor-abc",
      "device": "Chrome on Windows",
      "ip_prefix": "192.168.1.x",
      "created_at": 1764500000,
      "last_active": 1764515000,
      "current": true
    },
    {
      "aid": "session-anchor-def",
      "device": "Safari on iPhone",
      "ip_prefix": "10.0.0.x",
      "created_at": 1764400000,
      "last_active": 1764510000,
      "current": false
    }
  ]
}
```

### **10. Soporte Multiplataforma**

#### **10.1. Plataforma Web (Predeterminada)**

Para aplicaciones web, `StateProof` se almacena en una cookie `HttpOnly` según la Sección 4.3.

#### **10.2. Plataformas Móviles/Nativas**

Para aplicaciones móviles y de escritorio nativas donde las cookies no son prácticas:

**Almacenamiento:**
-   **iOS:** Keychain Services con `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
-   **Android:** EncryptedSharedPreferences o Keystore System
-   **Escritorio:** Administrador de Credenciales del SO (Bóveda de Credenciales de Windows, Llavero de macOS)

**Envío de StateProof:**
```
POST /jts/renew
X-JTS-StateProof: <encrypted_state_proof>
Content-Type: application/json
```

**Requisitos Adicionales para No-Cookie:**
-   El `StateProof` DEBE ser cifrado cuando se almacena en el cliente.
-   Las solicitudes con el encabezado `X-JTS-StateProof` DEBEN incluir un `X-JTS-Device-ID` para la validación.
-   El servidor DEBE validar que el `Device-ID` coincida con el registrado durante la autenticación inicial.

#### **10.3. Servidor a Servidor (M2M)**

Para la comunicación de máquina a máquina:

-   NO se utiliza `StateProof` (no hay concepto de "sesión de usuario").
-   El `BearerPass` se emite con una `exp` más larga (recomendación: 1 hora).
-   La reclamación `prn` contiene un identificador de servicio/máquina, no un usuario.
-   La reclamación `atm` se establece en `client_credentials`.

**Ejemplo de Carga Útil M2M:**
```json
{
  "prn": "service:payment-processor",
  "aid": "m2m-static-anchor",
  "tkn_id": "token-m2m-12345",
  "aud": "https://api.example.com/internal",
  "exp": 1764519000,
  "iat": 1764515400,
  "atm": "client_credentials",
  "perm": ["internal:process_payment", "internal:read_accounts"]
}
```

### **11. Conclusión**

El Sistema de Tokens Janus (JTS) ofrece un marco de autenticación equilibrado, combinando el alto rendimiento de la verificación sin estado con los estrictos controles de seguridad de la gestión de sesiones con estado. Con su arquitectura de dos componentes, terminología clara y perfiles operativos flexibles, JTS está diseñado para ser un estándar de autenticación robusto y seguro para la próxima generación de aplicaciones.

**Tres Perfiles para Diversas Necesidades:**

| Perfil | Caso de Uso | Complejidad | Seguridad |
| :--- | :--- | :--- | :--- |
| **JTS-L (Ligero)** | MVP, Herramientas Internas, Apps Simples | ⭐ Baja | ⭐⭐ Básica |
| **JTS-S (Estándar)** | Apps de Producción, APIs Públicas | ⭐⭐ Media | ⭐⭐⭐⭐ Alta |
| **JTS-C (Confidencialidad)**| Fintech, Salud, Alta Seguridad | ⭐⭐⭐ Alta | ⭐⭐⭐⭐⭐ Máxima |

**Ventajas de JTS sobre los sistemas de tokens de generaciones anteriores:**
1.  **Revocación Instantánea:** A través de la gestión de `StateProof` y la rotación de tokens (JTS-S/C).
2.  **Detección de Robo de Token:** A través de un mecanismo de rotación que detecta la repetición (JTS-S/C).
3.  **Protección por Capas:** Protección CSRF, vinculación de dispositivos y cifrado opcional.
4.  **Estandarización de Errores:** Códigos de error consistentes para depuración y manejo.
5.  **Flexibilidad de Plataforma:** Soporte para web, móvil y servidor a servidor.
6.  **Gestión de Claves:** Procedimiento claro de rotación de claves sin tiempo de inactividad.
7.  **Mejora Progresiva:** Una ruta de migración clara de JTS-L → JTS-S → JTS-C a medida que crece una aplicación.

---

### **Apéndice A: Lista de Verificación de Implementación**

Los implementadores DEBEN cumplir la siguiente lista de verificación para la conformidad con JTS:

#### **Lista de Verificación de JTS-L (Ligero):**

**Requerido (DEBE):**
- [ ] Usar criptografía asimétrica (RS256, ES256, etc.)
- [ ] Incluir `kid` en el encabezado de cada BearerPass
- [ ] Almacenar StateProof en una cookie HttpOnly con SameSite=Strict
- [ ] Validar CSRF en los endpoints `/renew` y `/logout`
- [ ] Devolver respuestas de error según el formato estándar (subconjunto)

**Recomendado (DEBERÍA):**
- [ ] Establecer la expiración de StateProof a un máximo de 24 horas
- [ ] Implementar limitación de tasa en `/renew`
- [ ] Registrar todas las actividades de renovación

---

#### **Lista de Verificación de JTS-S (Estándar):**

**Requerido (DEBE):**
- [ ] Usar criptografía asimétrica (RS256, ES256, etc.)
- [ ] Incluir `kid` en el encabezado de cada BearerPass
- [ ] Almacenar StateProof en una cookie HttpOnly con SameSite=Strict
- [ ] Implementar la rotación de StateProof en cada `/renew`
- [ ] Detectar la repetición y revocar sesiones cuando se detecte
- [ ] Validar CSRF en los endpoints `/renew` y `/logout`
- [ ] Devolver respuestas de error según el formato estándar (completo)

**Recomendado (DEBERÍA):**
- [ ] Implementar huella digital del dispositivo (`dfp`)
- [ ] Soportar períodos de gracia para solicitudes en tránsito
- [ ] Proporcionar un endpoint `/sessions` para visibilidad
- [ ] Implementar políticas de sesión concurrente
- [ ] Enviar notificaciones de seguridad cuando se detecten anomalías

**Opcional (PUEDE):**
- [ ] Implementar un endpoint de introspección
- [ ] Soportar multi-tenencia con la reclamación `org`

---

#### **Lista de Verificación de JTS-C (Confidencialidad):**

**Requerido (DEBE):**
- [ ] Todos los requisitos de JTS-S
- [ ] Implementar cifrado JWE (firmado y luego cifrado)
- [ ] Gestionar las claves de cifrado por separado de las claves de firma

**Opcional (PUEDE):**
- [ ] Soportar múltiples claves de cifrado del Servidor de Recursos
- [ ] Implementar un protocolo de intercambio de claves para las claves de cifrado

---

### **Apéndice B: Ejemplo de Flujo Completo**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        FLUJO DE AUTENTICACIÓN JTS                            │
└─────────────────────────────────────────────────────────────────────────────┘

[Usuario]       [App Cliente]        [Servidor Auth]      [Servidor Recurso]
   │                 │                     │                      │
   │─── Iniciar Sesión>│                     │                      │
   │                 │─── POST /login ────>│                      │
   │                 │    (credenciales)    │                      │
   │                 │                     │── Crear Sesión ────>│ [BD]
   │                 │                     │<─ Registro Sesión ───│
   │                 │                     │                      │
   │                 │<── 200 OK ─────────│                      │
   │                 │    BearerPass (cuerpo)│                      │
   │                 │    StateProof (cookie)                     │
   │                 │                     │                      │
   │                 │─────────── GET /api/resource ─────────────>│
   │                 │            Authorization: Bearer <BP>      │
   │                 │                     │                      │
   │                 │                     │    Verificar firma  │
   │                 │                     │    (sin estado)       │
   │                 │<────────── 200 OK ─────────────────────────│
   │<── Datos ───────│                     │                      │
   │                 │                     │                      │
   │    ... BearerPass expira ...        │                      │
   │                 │                     │                      │
   │                 │─── POST /renew ────>│                      │
   │                 │    (cookie StateProof)                     │
   │                 │                     │── Validar SP_v1 ───>│ [BD]
   │                 │                     │<─ Válido, consumido ───│
   │                 │                     │── Almacenar SP_v2 ──>│
   │                 │                     │                      │
   │                 │<── 200 OK ─────────│                      │
   │                 │    BearerPass_nuevo   │                      │
   │                 │    StateProof_v2 (cookie)                  │
   │                 │                     │                      │
   │─── Cerrar Sesión>│                     │                      │
   │                 │─── POST /logout ───>│                      │
   │                 │    (cookie StateProof)                     │
   │                 │                     │── Eliminar Sesión ───>│ [BD]
   │                 │<── 200 OK ─────────│                      │
   │<── Sesión Cerrada─│                     │                      │
   │                 │                     │                      │
```

---

### **Apéndice C: Referencias**

-   RFC 7519 - JSON Web Token (JWT)
-   RFC 7515 - JSON Web Signature (JWS)
-   RFC 7516 - JSON Web Encryption (JWE)
-   RFC 7517 - JSON Web Key (JWK)
-   RFC 6749 - The OAuth 2.0 Authorization Framework
-   OWASP Session Management Cheat Sheet
-   OWASP Cross-Site Request Forgery Prevention Cheat Sheet
