# WEB-RomaTweet

Pequeña red social temátizada en la Antigua Roma — proyecto para la asignatura de Programación WEB I.

## Autores
- Joaquín Gutiérrez Díaz — 22300907
- David Israel Gómez Méndez — 22300926

Docente: Mtra. Paola Fernández Ponce Villazo
Programa: Tecnólogo en Desarrollo de Software — 7E1

## Descripción
Backend en Node.js + Express con base de datos SQLite (better-sqlite3). Interfaz estática en `views/` y assets en `public/`. Soporta registro, inicio de sesión (cookies cifradas), creación de edictos (posts), perfil de usuario y un feed.

Características destacadas:
- Almacenamiento en SQLite (`database.sql`).
- Sesiones gestionadas mediante cookie cifrada (AES-256-GCM) y firmada.
- Contraseñas hasheadas con `bcrypt`.
- API REST mínima para perfiles, feed, posts, likes y replies.
- CSS/JS organizados por página bajo `public/`.

## Archivos importantes
- `server.js` — servidor Express y definición del esquema de base de datos.
- `database.sql` — archivo de base de datos SQLite (creado automáticamente al iniciar el servidor).
- `views/` — HTML públicos: `home.html`, `login.html`, `register.html`, `post.html`, `profile.html`.
- `public/` — CSS y JS compartidos y por página (`styles.css`, `home.css`, `profile.css`, `post.css`, etc.).

## Variables de entorno
Crea un archivo `.env` en la raíz con al menos:

```
JWTSECRET=una_frase_secreta_y_larga
```

Ese valor se usa para derivar la clave de cifrado de las cookies. Reinicia el servidor después de crear/modificar `.env`.

## Instalación y ejecución
1. Instala dependencias:

```
npm install
```

2. Ejecuta el servidor:

```
node server.js
```

El servidor escucha por defecto en el puerto `3030`. Abre `http://localhost:3030/`.

## Endpoints principales (resumen)
- `GET /` — pantalla de login.
- `POST /register` — registro.
- `POST /login` — inicio de sesión.
- `GET /logout` — cierra sesión.
- `GET /home` — página principal (feed).
- `GET /post`, `GET /profile` — páginas protegidas.

APIs JSON (protegidas):
- `GET /api/me` — perfil actual.
- `GET /api/feed` — posts recientes con autor.
- `GET /api/me/posts` — posts del usuario.
- `POST /api/me/posts` — crear post (JSON body { content }).
- `GET /api/users/top` — usuarios destacados.
- `GET /api/me/following` — cuentas que sigues.
- `GET /api/me/likes` — posts que te gustaron.
- `GET /api/me/replies` — tus respuestas (comments).

## Notas y consejos
- Si quieres reiniciar la base de datos borra `database.sql` y reinicia el servidor (se recreará el esquema).
- Me estoy volviendo loco