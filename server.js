// server.js - Express backend
// modules
const express = require('express');
const cookieParser = require('cookie-parser');
const database = require("better-sqlite3")("database.sql")
const path = require('path');

// env
require('dotenv').config();
const bcrypt = require('bcrypt');
const crypto = require('crypto');

// derive key from secret
const SECRET_KEY_SOURCE = process.env.JWTSECRET || process.env.COOKIE_SECRET || 'please_change_this_secret';
const COOKIE_KEY = crypto.createHash('sha256').update(String(SECRET_KEY_SOURCE)).digest();

// bcrypt helpers
async function hashPassword(password) {
  return await bcrypt.hash(password, 12);
}

async function verifyPassword(password, hash) {
  return await bcrypt.compare(password, hash);
}

// cookie encryption helpers (AES-256-GCM)
function encryptCookie(value) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', COOKIE_KEY, iv);
  const ciphertext = Buffer.concat([cipher.update(String(value), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, ciphertext]).toString('base64');
}

function decryptCookie(encrypted) {
  try {
    const data = Buffer.from(encrypted, 'base64');
    const iv = data.subarray(0, 12);
    const tag = data.subarray(12, 28);
    const ciphertext = data.subarray(28);
    const decipher = crypto.createDecipheriv('aes-256-gcm', COOKIE_KEY, iv);
    decipher.setAuthTag(tag);
    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return decrypted.toString('utf8');
  } catch (err) {
    return null;
  }
}

// DB pragmas & schema
try {
    database.pragma('journal_mode = WAL');
    database.pragma('foreign_keys = ON');
} catch (err) {
    console.error('SQLite pragma error:', err);
}

const initSql = `
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  full_name TEXT NOT NULL,
  username TEXT NOT NULL UNIQUE,
  email TEXT UNIQUE,
  password_hash TEXT NOT NULL,
  bio TEXT DEFAULT '',
  avatar TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS posts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  content TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  edited_at DATETIME,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS followers (
  follower_id INTEGER NOT NULL,
  followed_id INTEGER NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (follower_id, followed_id),
  FOREIGN KEY(follower_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY(followed_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS likes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  post_id INTEGER NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user_id, post_id),
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS comments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  post_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  content TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
`;

try {
    database.exec(initSql);
    database.exec(`
      CREATE INDEX IF NOT EXISTS idx_posts_user ON posts(user_id);
      CREATE INDEX IF NOT EXISTS idx_posts_created ON posts(created_at);
      CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
    `);
} catch (err) {
    console.error('Failed to initialize database schema:', err);
}

// express config
const app = express();
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser(process.env.COOKIE_SECRET || 'please_change_this_secret'));

// attach helpers to req
app.use((req, res, next) => {
  req.hashPassword = hashPassword;
  req.verifyPassword = verifyPassword;
  req.encryptCookie = encryptCookie;
  req.decryptCookie = decryptCookie;
  next();
});

// auth middleware
function requireAuth(req, res, next) {
  const publicPaths = ['/', '/register', '/login'];
  if (publicPaths.includes(req.path)) return next();
  const encrypted = (req.signedCookies && req.signedCookies.session) || (req.cookies && req.cookies.session);
  if (!encrypted) return res.redirect('/');
  const decrypted = req.decryptCookie(encrypted);
  if (!decrypted) return res.redirect('/');
  try {
    const payload = JSON.parse(decrypted);
    if (payload.expires_at) {
      const expires = typeof payload.expires_at === 'number' ? payload.expires_at : Date.parse(payload.expires_at);
      if (isNaN(expires) || Date.now() > expires) return res.redirect('/');
    }
    req.session = payload;
    return next();
  } catch (err) {
    return res.redirect('/');
  }
}

app.use(express.static("public"));

// routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'login.html'));
});

app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'register.html'));
});

app.get('/home', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'home.html'));
});

app.get('/post', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'post.html'));
});

app.get('/profile', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'profile.html'));
});

// API: current user profile
app.get('/api/me', requireAuth, (req, res) => {
  try {
    const userId = req.session && req.session.user_id;
    if (!userId) return res.status(401).json({ error: 'unauthorized' });
    const user = database.prepare('SELECT id, full_name, username, email, bio, avatar, created_at FROM users WHERE id = ?').get(userId);
    if (!user) return res.status(404).json({ error: 'not_found' });
    const postsCount = database.prepare('SELECT COUNT(*) as cnt FROM posts WHERE user_id = ?').get(userId).cnt || 0;
    const followersCount = database.prepare('SELECT COUNT(*) as cnt FROM followers WHERE followed_id = ?').get(userId).cnt || 0;
    const followingCount = database.prepare('SELECT COUNT(*) as cnt FROM followers WHERE follower_id = ?').get(userId).cnt || 0;
    res.json({ user, counts: { posts: postsCount, followers: followersCount, following: followingCount } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

// API: current user posts
app.get('/api/me/posts', requireAuth, (req, res) => {
  try {
    const userId = req.session && req.session.user_id;
    if (!userId) return res.status(401).json({ error: 'unauthorized' });
    const posts = database.prepare('SELECT id, content, created_at, edited_at FROM posts WHERE user_id = ? ORDER BY created_at DESC LIMIT 100').all(userId);
    res.json({ posts });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

// API: simple user lookup by username
app.get('/api/users/:username', requireAuth, (req, res) => {
  try {
    const username = req.params.username;
    const user = database.prepare('SELECT id, full_name, username, bio, avatar, created_at FROM users WHERE username = ?').get(username);
    if (!user) return res.status(404).json({ error: 'not_found' });
    res.json({ user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

// API: top 3 accounts current user follows (by follower count)
app.get('/api/me/following', requireAuth, (req, res) => {
  try {
    const userId = req.session && req.session.user_id;
    if (!userId) return res.status(401).json({ error: 'unauthorized' });
    const stmt = database.prepare(`
      SELECT u.id, u.full_name, u.username, u.avatar, u.bio, COUNT(f2.follower_id) AS followers_count
      FROM followers f
      JOIN users u ON f.followed_id = u.id
      LEFT JOIN followers f2 ON f2.followed_id = u.id
      WHERE f.follower_id = ?
      GROUP BY u.id
      ORDER BY followers_count DESC
      LIMIT 3
    `);
    const rows = stmt.all(userId) || [];
    res.json({ following: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

// register
app.post('/register', async (req, res) => {
  try {
    const { 
        'register-name': full_name, 
        'register-username': username, 
        'register-email': email, 
        'register-password': password 
    } = req.body;

    if (!full_name || !username || !password) 
        return res.status(400).send('Missing fields');

    // check existing
    const exists = database.prepare('SELECT id FROM users WHERE username = ? OR email = ?').get(username, email || null);
    if (exists) 
        return res.status(409).send('User already exists');

    const password_hash = await hashPassword(password);
    const info = database.prepare('INSERT INTO users (full_name, username, email, password_hash) VALUES (?, ?, ?, ?)').run(full_name, username, email || null, password_hash);
    const user_id = info.lastInsertRowid || info.lastID || null;

    // create session payload
    const expiresMs = Date.now() + 30 * 60 * 1000; // 30 minutes
    const payload = { user_id, username, expires_at: expiresMs };
    const encrypted = encryptCookie(JSON.stringify(payload));
    res.cookie('session', encrypted, { httpOnly: true, signed: true, maxAge: 30 * 60 * 1000, sameSite: 'lax' });

    return res.redirect('/home');
  } catch (err) {
    console.error(err);
    return res.status(500).send('Server error');
  }
});

// login
app.post('/login', async (req, res) => {
  try {
    const { 'login-email': username, 'login-password': password } = req.body;
    if (!username || !password)
         return res.status(400).send('Missing fields');

    const user = database.prepare('SELECT id, username, password_hash FROM users WHERE username = ?').get(username);
    if (!user) 
        return res.status(401).send('Invalid credentials');

    const ok = await verifyPassword(password, user.password_hash);
    if (!ok) 
        return res.status(401).send('Invalid credentials');

    const expiresMs = Date.now() + 30 * 60 * 1000;
    const payload = { user_id: user.id, username: user.username, expires_at: expiresMs };
    const encrypted = encryptCookie(JSON.stringify(payload));
    res.cookie('session', encrypted, { httpOnly: true, signed: true, maxAge: 30 * 60 * 1000, sameSite: 'lax' });

    return res.redirect('/home');
  } catch (err) {
    console.error(err);
    return res.status(500).send('Server error');
  }
});

// logout
app.get('/logout', (req, res) => {
  res.clearCookie('session');
  res.redirect('/');
});

// listen
app.listen(3030);