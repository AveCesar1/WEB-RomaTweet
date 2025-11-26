// server.js - Express backend
// modules
const express = require('express');
const cookieParser = require('cookie-parser');
const database = require("better-sqlite3")("database.sql")

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
app.get('/', (req, res) => { app.render('login.html'); });
app.get('/register', (req, res) => { app.render('register.html'); });
app.get('/home', requireAuth, (req, res) => { app.render('home.html'); });
app.get('/post', requireAuth, (req, res) => { app.render('post.html'); });
app.get('/profile', requireAuth, (req, res) => { app.render('profile.html'); });

// listen
app.listen(3030);