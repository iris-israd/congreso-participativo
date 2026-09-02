# Plataforma de Votación Parlamentaria

Aplicación web (HTML/JS, sin build) conectada a Supabase para votar proyectos de ley.

## Archivos

- `schema.sql` — todo el backend: tablas, seguridad (RLS) y funciones de gestión/votación.
- `index.html` — la aplicación completa (login, votación, resultados, administración).

## Puesta en marcha (10 minutos)

1. **Crea un proyecto en Supabase** (https://supabase.com) si no tienes uno.
2. **Ejecuta el esquema**: en el Dashboard de Supabase, ve a *SQL Editor → New query*, pega todo el contenido de `schema.sql` y dale **Run**. Esto crea las tablas, activa la seguridad a nivel de fila y crea un usuario inicial `admin` / `admin123`.
3. **Copia tus credenciales**: en *Project Settings → API*, copia la **Project URL** y la **anon public key**.
4. **Configura `index.html`**: ábrelo con un editor de texto y en las primeras líneas del `<script>` reemplaza:
   ```js
   const SUPABASE_URL = "https://TU-PROYECTO.supabase.co";
   const SUPABASE_ANON_KEY = "TU-ANON-KEY";
   ```
5. **Ábrelo en el navegador** (doble clic sobre `index.html`, o súbelo a cualquier hosting estático). Inicia sesión con `admin` / `admin123` y **cambia esa contraseña de inmediato** creando un nuevo usuario admin y eliminando el original, o usando la función `fn_usuario_resetear_password`.

## Cómo funciona

- **Partidos**: se gestionan en el panel Administración → Partidos (nombre, siglas, color).
- **Congresistas**: se gestionan en Administración → Congresistas, y se asignan a un partido.
- **Usuarios**: cada congresista necesita una cuenta (usuario + contraseña) para poder votar; se crea en Administración → Usuarios y se vincula a un congresista. También puedes crear usuarios administradores sin congresista asociado.
- **Proyectos de ley**: se crean en Administración → Gestionar proyectos, eligiendo el tipo de voto:
  - **Estándar**: sí / no.
  - **Nominal**: sí / no / me abstengo.
  Un proyecto nace en *borrador*, el admin lo **abre** para votación, los congresistas votan (y pueden cambiar su voto mientras esté abierto), y el admin lo **cierra** cuando termina.
- **Resultados**: se actualizan en vivo con el conteo total y el desglose por partido.

## Notas de seguridad

- Las contraseñas se guardan con hash `bcrypt` (vía `pgcrypto`), nunca en texto plano.
- La tabla `usuarios` está completamente bloqueada a nivel de base de datos (RLS): ni siquiera con la clave `anon` se puede leer o escribir directamente; todo pasa por funciones controladas (`fn_login`, `fn_usuario_crear`, etc.) que validan las credenciales en el servidor.
- Las tablas de `partidos`, `congresistas`, `proyectos_ley` y `votos` son de **lectura pública** (transparencia del registro de votación), pero su escritura está bloqueada salvo a través de las funciones de administración, que exigen usuario y contraseña de un admin.
- Esta app usa un esquema de autenticación propio (usuario + contraseña, no Supabase Auth/email) porque así se pidió explícitamente. Es adecuado para un uso interno/institucional; si se necesita en el futuro MFA, expiración de sesión por servidor o auditoría más fina, se puede migrar a Supabase Auth con este mismo modelo de datos.
