-- ============================================================================
-- PLATAFORMA DE VOTACIÓN PARLAMENTARIA — ESQUEMA SUPABASE
-- ============================================================================
-- Ejecutar completo en: Supabase Dashboard > SQL Editor > New query > Run
-- Requiere extensión pgcrypto para el hash de contraseñas.
-- ============================================================================

create extension if not exists pgcrypto;

-- ----------------------------------------------------------------------------
-- TABLAS
-- ----------------------------------------------------------------------------

create table if not exists partidos (
  id uuid primary key default gen_random_uuid(),
  nombre text not null unique,
  siglas text,
  color text not null default '#8A6D3B',
  created_at timestamptz not null default now()
);

create table if not exists congresistas (
  id uuid primary key default gen_random_uuid(),
  nombre text not null,
  partido_id uuid references partidos(id) on delete set null,
  activo boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists usuarios (
  id uuid primary key default gen_random_uuid(),
  username text not null unique,
  password_hash text not null,
  rol text not null check (rol in ('admin','congresista')) default 'congresista',
  congresista_id uuid unique references congresistas(id) on delete set null,
  created_at timestamptz not null default now()
);

create table if not exists proyectos_ley (
  id uuid primary key default gen_random_uuid(),
  codigo text,
  titulo text not null,
  descripcion text,
  tipo_voto text not null check (tipo_voto in ('estandar','nominal')) default 'estandar',
  estado text not null check (estado in ('borrador','abierto','cerrado')) default 'borrador',
  created_at timestamptz not null default now(),
  abierto_at timestamptz,
  cerrado_at timestamptz
);

create table if not exists votos (
  id uuid primary key default gen_random_uuid(),
  proyecto_id uuid not null references proyectos_ley(id) on delete cascade,
  congresista_id uuid not null references congresistas(id) on delete cascade,
  voto text not null check (voto in ('si','no','abstencion')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (proyecto_id, congresista_id)
);

-- ----------------------------------------------------------------------------
-- ROW LEVEL SECURITY
-- Lectura pública (transparencia parlamentaria) para partidos, congresistas,
-- proyectos y votos. La tabla usuarios NUNCA se expone directamente (contiene
-- el hash de la contraseña); todo acceso a usuarios pasa por funciones RPC.
-- Toda escritura pasa exclusivamente por funciones RPC "security definer"
-- que validan credenciales de admin antes de modificar nada.
-- ----------------------------------------------------------------------------

alter table partidos enable row level security;
alter table congresistas enable row level security;
alter table usuarios enable row level security;
alter table proyectos_ley enable row level security;
alter table votos enable row level security;

create policy partidos_lectura_publica on partidos for select using (true);
create policy congresistas_lectura_publica on congresistas for select using (true);
create policy proyectos_lectura_publica on proyectos_ley for select using (true);
create policy votos_lectura_publica on votos for select using (true);
-- usuarios: sin políticas de select/insert/update/delete para anon -> tabla bloqueada por completo.

-- ----------------------------------------------------------------------------
-- HELPER INTERNO: valida username + password contra usuarios, devuelve la fila
-- ----------------------------------------------------------------------------

create or replace function _auth_check(p_username text, p_password text)
returns usuarios
language plpgsql
security definer
set search_path = public
as $$
declare
  u usuarios;
begin
  select * into u from usuarios where username = p_username;
  if u.id is null then
    raise exception 'Credenciales inválidas';
  end if;
  if u.password_hash <> crypt(p_password, u.password_hash) then
    raise exception 'Credenciales inválidas';
  end if;
  return u;
end;
$$;

create or replace function _require_admin(p_username text, p_password text)
returns usuarios
language plpgsql
security definer
set search_path = public
as $$
declare
  u usuarios;
begin
  u := _auth_check(p_username, p_password);
  if u.rol <> 'admin' then
    raise exception 'Se requieren permisos de administrador';
  end if;
  return u;
end;
$$;

-- ----------------------------------------------------------------------------
-- LOGIN
-- ----------------------------------------------------------------------------

create or replace function fn_login(p_username text, p_password text)
returns table (
  id uuid, username text, rol text,
  congresista_id uuid, congresista_nombre text,
  partido_id uuid, partido_nombre text, partido_color text
)
language plpgsql
security definer
set search_path = public
as $$
declare
  u usuarios;
begin
  u := _auth_check(p_username, p_password);
  return query
    select u.id, u.username, u.rol,
           c.id, c.nombre,
           p.id, p.nombre, p.color
    from usuarios u2
    left join congresistas c on c.id = u.congresista_id
    left join partidos p on p.id = c.partido_id
    where u2.id = u.id;
end;
$$;

-- ----------------------------------------------------------------------------
-- GESTIÓN DE PARTIDOS (solo admin)
-- ----------------------------------------------------------------------------

create or replace function fn_partido_crear(p_username text, p_password text, p_nombre text, p_siglas text, p_color text)
returns partidos language plpgsql security definer set search_path = public as $$
declare r partidos;
begin
  perform _require_admin(p_username, p_password);
  insert into partidos (nombre, siglas, color) values (p_nombre, p_siglas, coalesce(p_color, '#8A6D3B'))
  returning * into r;
  return r;
end; $$;

create or replace function fn_partido_editar(p_username text, p_password text, p_id uuid, p_nombre text, p_siglas text, p_color text)
returns partidos language plpgsql security definer set search_path = public as $$
declare r partidos;
begin
  perform _require_admin(p_username, p_password);
  update partidos set nombre = p_nombre, siglas = p_siglas, color = p_color where id = p_id
  returning * into r;
  return r;
end; $$;

create or replace function fn_partido_eliminar(p_username text, p_password text, p_id uuid)
returns void language plpgsql security definer set search_path = public as $$
begin
  perform _require_admin(p_username, p_password);
  delete from partidos where id = p_id;
end; $$;

-- ----------------------------------------------------------------------------
-- GESTIÓN DE CONGRESISTAS (solo admin)
-- ----------------------------------------------------------------------------

create or replace function fn_congresista_crear(p_username text, p_password text, p_nombre text, p_partido_id uuid)
returns congresistas language plpgsql security definer set search_path = public as $$
declare r congresistas;
begin
  perform _require_admin(p_username, p_password);
  insert into congresistas (nombre, partido_id) values (p_nombre, p_partido_id)
  returning * into r;
  return r;
end; $$;

create or replace function fn_congresista_editar(p_username text, p_password text, p_id uuid, p_nombre text, p_partido_id uuid, p_activo boolean)
returns congresistas language plpgsql security definer set search_path = public as $$
declare r congresistas;
begin
  perform _require_admin(p_username, p_password);
  update congresistas set nombre = p_nombre, partido_id = p_partido_id, activo = p_activo where id = p_id
  returning * into r;
  return r;
end; $$;

create or replace function fn_congresista_eliminar(p_username text, p_password text, p_id uuid)
returns void language plpgsql security definer set search_path = public as $$
begin
  perform _require_admin(p_username, p_password);
  delete from congresistas where id = p_id;
end; $$;

-- ----------------------------------------------------------------------------
-- GESTIÓN DE USUARIOS (solo admin) — username + contraseña
-- ----------------------------------------------------------------------------

create or replace function fn_usuarios_listar(p_username text, p_password text)
returns table (id uuid, username text, rol text, congresista_id uuid, congresista_nombre text)
language plpgsql security definer set search_path = public as $$
begin
  perform _require_admin(p_username, p_password);
  return query
    select u.id, u.username, u.rol, u.congresista_id, c.nombre
    from usuarios u left join congresistas c on c.id = u.congresista_id
    order by u.created_at;
end; $$;

create or replace function fn_usuario_crear(p_username text, p_password text, p_new_username text, p_new_password text, p_congresista_id uuid, p_rol text)
returns table (id uuid, username text, rol text, congresista_id uuid)
language plpgsql security definer set search_path = public as $$
declare new_id uuid;
begin
  perform _require_admin(p_username, p_password);
  if p_rol not in ('admin','congresista') then
    raise exception 'Rol inválido';
  end if;
  insert into usuarios (username, password_hash, rol, congresista_id)
  values (p_new_username, crypt(p_new_password, gen_salt('bf')), p_rol, p_congresista_id)
  returning usuarios.id into new_id;
  return query select u.id, u.username, u.rol, u.congresista_id from usuarios u where u.id = new_id;
end; $$;

create or replace function fn_usuario_eliminar(p_username text, p_password text, p_id uuid)
returns void language plpgsql security definer set search_path = public as $$
begin
  perform _require_admin(p_username, p_password);
  delete from usuarios where id = p_id;
end; $$;

create or replace function fn_usuario_resetear_password(p_username text, p_password text, p_id uuid, p_new_password text)
returns void language plpgsql security definer set search_path = public as $$
begin
  perform _require_admin(p_username, p_password);
  update usuarios set password_hash = crypt(p_new_password, gen_salt('bf')) where id = p_id;
end; $$;

-- ----------------------------------------------------------------------------
-- GESTIÓN DE PROYECTOS DE LEY (solo admin crea/abre/cierra)
-- ----------------------------------------------------------------------------

create or replace function fn_proyecto_crear(p_username text, p_password text, p_codigo text, p_titulo text, p_descripcion text, p_tipo_voto text)
returns proyectos_ley language plpgsql security definer set search_path = public as $$
declare r proyectos_ley;
begin
  perform _require_admin(p_username, p_password);
  if p_tipo_voto not in ('estandar','nominal') then
    raise exception 'Tipo de voto inválido';
  end if;
  insert into proyectos_ley (codigo, titulo, descripcion, tipo_voto)
  values (p_codigo, p_titulo, p_descripcion, p_tipo_voto)
  returning * into r;
  return r;
end; $$;

create or replace function fn_proyecto_abrir(p_username text, p_password text, p_id uuid)
returns proyectos_ley language plpgsql security definer set search_path = public as $$
declare r proyectos_ley;
begin
  perform _require_admin(p_username, p_password);
  update proyectos_ley set estado = 'abierto', abierto_at = now() where id = p_id and estado <> 'cerrado'
  returning * into r;
  if r.id is null then raise exception 'No se pudo abrir el proyecto (¿ya está cerrado?)'; end if;
  return r;
end; $$;

create or replace function fn_proyecto_cerrar(p_username text, p_password text, p_id uuid)
returns proyectos_ley language plpgsql security definer set search_path = public as $$
declare r proyectos_ley;
begin
  perform _require_admin(p_username, p_password);
  update proyectos_ley set estado = 'cerrado', cerrado_at = now() where id = p_id
  returning * into r;
  return r;
end; $$;

create or replace function fn_proyecto_eliminar(p_username text, p_password text, p_id uuid)
returns void language plpgsql security definer set search_path = public as $$
begin
  perform _require_admin(p_username, p_password);
  delete from proyectos_ley where id = p_id;
end; $$;

-- ----------------------------------------------------------------------------
-- VOTACIÓN — cualquier usuario autenticado (congresista) vota por sí mismo
-- ----------------------------------------------------------------------------

create or replace function fn_voto_emitir(p_username text, p_password text, p_proyecto_id uuid, p_voto text)
returns votos language plpgsql security definer set search_path = public as $$
declare
  u usuarios;
  proy proyectos_ley;
  r votos;
begin
  u := _auth_check(p_username, p_password);
  if u.congresista_id is null then
    raise exception 'Este usuario no está asociado a un congresista';
  end if;

  select * into proy from proyectos_ley where id = p_proyecto_id;
  if proy.id is null then raise exception 'Proyecto no encontrado'; end if;
  if proy.estado <> 'abierto' then raise exception 'La votación de este proyecto no está abierta'; end if;

  if proy.tipo_voto = 'estandar' and p_voto not in ('si','no') then
    raise exception 'Voto inválido: este proyecto solo admite sí / no';
  end if;
  if proy.tipo_voto = 'nominal' and p_voto not in ('si','no','abstencion') then
    raise exception 'Voto inválido';
  end if;

  insert into votos (proyecto_id, congresista_id, voto)
  values (p_proyecto_id, u.congresista_id, p_voto)
  on conflict (proyecto_id, congresista_id)
  do update set voto = excluded.voto, updated_at = now()
  returning * into r;

  return r;
end; $$;

-- ----------------------------------------------------------------------------
-- GRANTS — solo se exponen las funciones RPC públicas al rol anon/authenticated
-- ----------------------------------------------------------------------------

grant execute on function fn_login(text, text) to anon, authenticated;
grant execute on function fn_partido_crear(text, text, text, text, text) to anon, authenticated;
grant execute on function fn_partido_editar(text, text, uuid, text, text, text) to anon, authenticated;
grant execute on function fn_partido_eliminar(text, text, uuid) to anon, authenticated;
grant execute on function fn_congresista_crear(text, text, text, uuid) to anon, authenticated;
grant execute on function fn_congresista_editar(text, text, uuid, text, uuid, boolean) to anon, authenticated;
grant execute on function fn_congresista_eliminar(text, text, uuid) to anon, authenticated;
grant execute on function fn_usuarios_listar(text, text) to anon, authenticated;
grant execute on function fn_usuario_crear(text, text, text, text, uuid, text) to anon, authenticated;
grant execute on function fn_usuario_eliminar(text, text, uuid) to anon, authenticated;
grant execute on function fn_usuario_resetear_password(text, text, uuid, text) to anon, authenticated;
grant execute on function fn_proyecto_crear(text, text, text, text, text, text) to anon, authenticated;
grant execute on function fn_proyecto_abrir(text, text, uuid) to anon, authenticated;
grant execute on function fn_proyecto_cerrar(text, text, uuid) to anon, authenticated;
grant execute on function fn_proyecto_eliminar(text, text, uuid) to anon, authenticated;
grant execute on function fn_voto_emitir(text, text, uuid, text) to anon, authenticated;

-- ----------------------------------------------------------------------------
-- DATOS INICIALES DE EJEMPLO
-- Crea un partido "Independiente", un congresista "Administrador General" y
-- el usuario admin/admin123. CAMBIA ESTA CONTRASEÑA INMEDIATAMENTE.
-- ----------------------------------------------------------------------------

do $$
declare
  v_partido_id uuid;
  v_congresista_id uuid;
begin
  if not exists (select 1 from usuarios where username = 'admin') then
    insert into partidos (nombre, siglas, color) values ('Independiente', 'IND', '#8A6D3B')
    returning id into v_partido_id;

    insert into congresistas (nombre, partido_id) values ('Administrador General', v_partido_id)
    returning id into v_congresista_id;

    insert into usuarios (username, password_hash, rol, congresista_id)
    values ('admin', crypt('admin123', gen_salt('bf')), 'admin', v_congresista_id);
  end if;
end $$;
