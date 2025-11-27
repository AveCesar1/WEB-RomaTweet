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
app.use(express.json());
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

// helper: normalize sqlite datetime strings ("YYYY-MM-DD HH:MM:SS") to ISO 8601 (UTC)
function toIsoUtc(ts) {
  try {
    if (!ts) return ts;
    let s = String(ts).trim();
    // if already ISO-like with T or timezone, try to parse and return toISOString
    if (s.includes('T') || s.includes('Z') || s.includes('+')) {
      const d = new Date(s);
      if (!isNaN(d.getTime())) return d.toISOString();
    }
    // convert space to T and append Z to indicate UTC
    s = s.replace(' ', 'T');
    if (!s.endsWith('Z')) s = s + 'Z';
    const d = new Date(s);
    if (isNaN(d.getTime())) return ts;
    return d.toISOString();
  } catch (e) {
    return ts;
  }
}

function normalizeRowDates(row, fields) {
  if (!row) return row;
  for (const f of fields) {
    if (row[f]) {
      row[f] = toIsoUtc(row[f]);
    }
  }
  return row;
}

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
    user.created_at = toIsoUtc(user.created_at);
    const postsCount = database.prepare('SELECT COUNT(*) as cnt FROM posts WHERE user_id = ?').get(userId).cnt || 0;
    const followersCount = database.prepare('SELECT COUNT(*) as cnt FROM followers WHERE followed_id = ?').get(userId).cnt || 0;
    const followingCount = database.prepare('SELECT COUNT(*) as cnt FROM followers WHERE follower_id = ?').get(userId).cnt || 0;
    res.json({ user, counts: { posts: postsCount, followers: followersCount, following: followingCount } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

// API: current user posts (include counts)
app.get('/api/me/posts', requireAuth, (req, res) => {
  try {
    const userId = req.session && req.session.user_id;
    if (!userId) return res.status(401).json({ error: 'unauthorized' });
    const posts = database.prepare(`
      SELECT p.id, p.content, p.created_at, p.edited_at,
        (SELECT COUNT(*) FROM likes WHERE post_id = p.id) AS likes_count,
        (SELECT COUNT(*) FROM comments WHERE post_id = p.id) AS comments_count
      FROM posts p
      WHERE p.user_id = ?
      ORDER BY p.created_at DESC
      LIMIT 100
    `).all(userId);
    posts.forEach(p => normalizeRowDates(p, ['created_at', 'edited_at']));
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

// API: feed - recent posts with author info and counts
app.get('/api/feed', requireAuth, (req, res) => {
  try {
    const rows = database.prepare(`
      SELECT p.id, p.content, p.created_at, p.edited_at,
             u.id AS user_id, u.full_name, u.username, u.avatar,
             (SELECT COUNT(*) FROM likes WHERE post_id = p.id) AS likes_count,
             (SELECT COUNT(*) FROM comments WHERE post_id = p.id) AS comments_count
      FROM posts p
      JOIN users u ON p.user_id = u.id
      ORDER BY likes_count DESC, p.created_at DESC
      LIMIT 100
    `).all();
    rows.forEach(r => normalizeRowDates(r, ['created_at', 'edited_at']));
    res.json({ posts: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

// API: top users by follower count (for sidebar suggestions)
app.get('/api/users/top', requireAuth, (req, res) => {
  try {
    const rows = database.prepare(`
      SELECT u.id, u.full_name, u.username, u.avatar, u.bio, COUNT(f.follower_id) AS followers_count
      FROM users u
      LEFT JOIN followers f ON f.followed_id = u.id
      GROUP BY u.id
      ORDER BY followers_count DESC
      LIMIT 5
    `).all();
    res.json({ users: rows });
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

// maestra si ve esto, soy su fan :D

// logout
app.get('/logout', (req, res) => {
  res.clearCookie('session');
  res.redirect('/');
});

// API: create a new post for current user
app.post('/api/me/posts', requireAuth, (req, res) => {
  try {
    const userId = req.session && req.session.user_id;
    if (!userId) return res.status(401).json({ error: 'unauthorized' });
    const content = (req.body && (req.body.content || req.body.post_content)) || '';
    if (!content || String(content).trim().length === 0) return res.status(400).json({ error: 'empty' });
    if (String(content).length > 1000) return res.status(400).json({ error: 'too_long' });
    const info = database.prepare('INSERT INTO posts (user_id, content) VALUES (?, ?)').run(userId, String(content).trim());
    const postId = info && (info.lastInsertRowid || info.lastInsertRowId || info.lastInsertRowid);
    const post = database.prepare('SELECT id, content, created_at, edited_at FROM posts WHERE id = ?').get(postId);
    normalizeRowDates(post, ['created_at', 'edited_at']);
    return res.json({ ok: true, post });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'server_error' });
  }
});

// API: posts liked by current user
app.get('/api/me/likes', requireAuth, (req, res) => {
  try {
    const userId = req.session && req.session.user_id;
    if (!userId) return res.status(401).json({ error: 'unauthorized' });
    const rows = database.prepare(`
      SELECT p.id, p.content, p.created_at, u.id AS user_id, u.full_name, u.username, u.avatar, l.created_at AS liked_at
      FROM likes l
      JOIN posts p ON l.post_id = p.id
      JOIN users u ON p.user_id = u.id
      WHERE l.user_id = ?
      ORDER BY l.created_at DESC
      LIMIT 100
    `).all(userId) || [];
    rows.forEach(r => normalizeRowDates(r, ['created_at', 'liked_at']));
    res.json({ posts: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

// API: comments/replies authored by current user (with parent post preview)
app.get('/api/me/replies', requireAuth, (req, res) => {
  try {
    const userId = req.session && req.session.user_id;
    if (!userId) return res.status(401).json({ error: 'unauthorized' });
    const rows = database.prepare(`
      SELECT c.id AS comment_id, c.content AS comment, c.created_at AS commented_at,
             p.id AS post_id, p.content AS post_content, pu.id AS post_owner_id, pu.username AS post_owner_username, pu.full_name AS post_owner_full_name
      FROM comments c
      JOIN posts p ON c.post_id = p.id
      JOIN users pu ON p.user_id = pu.id
      WHERE c.user_id = ?
      ORDER BY c.created_at DESC
      LIMIT 100
    `).all(userId) || [];
    rows.forEach(r => normalizeRowDates(r, ['commented_at']));
    res.json({ replies: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

// API: toggle like for a post
app.post('/api/posts/:id/like', requireAuth, (req, res) => {
  try {
    const userId = req.session && req.session.user_id;
    const postId = Number(req.params.id);
    if (!userId) return res.status(401).json({ error: 'unauthorized' });
    const post = database.prepare('SELECT id FROM posts WHERE id = ?').get(postId);
    if (!post) return res.status(404).json({ error: 'post_not_found' });

    const exists = database.prepare('SELECT id FROM likes WHERE user_id = ? AND post_id = ?').get(userId, postId);
    let liked = false;
    if (exists) {
      database.prepare('DELETE FROM likes WHERE id = ?').run(exists.id);
      liked = false;
    } else {
      database.prepare('INSERT INTO likes (user_id, post_id) VALUES (?, ?)').run(userId, postId);
      liked = true;
    }
    const likesCount = database.prepare('SELECT COUNT(*) as cnt FROM likes WHERE post_id = ?').get(postId).cnt || 0;
    res.json({ liked, likes_count: likesCount });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

// API: get comments for a post
app.get('/api/posts/:id/comments', requireAuth, (req, res) => {
  try {
    const postId = Number(req.params.id);
    const rows = database.prepare(`
      SELECT c.id, c.content, c.created_at, u.id AS user_id, u.full_name, u.username
      FROM comments c
      JOIN users u ON c.user_id = u.id
      WHERE c.post_id = ?
      ORDER BY c.created_at ASC
      LIMIT 500
    `).all(postId) || [];
    rows.forEach(r => { if (r.created_at) r.created_at = toIsoUtc(r.created_at); });
    res.json({ comments: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

// API: create comment for a post
app.post('/api/posts/:id/comments', requireAuth, (req, res) => {
  try {
    const userId = req.session && req.session.user_id;
    const postId = Number(req.params.id);
    if (!userId) 
      return res.status(401).json({ error: 'unauthorized' });
    const { content } = req.body || {};
    if (!content || !String(content).trim()) 
      return res.status(400).json({ error: 'empty' });
    const post = database.prepare('SELECT id FROM posts WHERE id = ?').get(postId);
    if (!post) 
      return res.status(404).json({ error: 'post_not_found' });
    const info = database.prepare('INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)').run(postId, userId, String(content).trim());
    const commentId = info && (info.lastInsertRowid || info.lastInsertRowId || info.lastInsertRowid);
    const comment = database.prepare('SELECT c.id, c.content, c.created_at, u.id AS user_id, u.full_name, u.username FROM comments c JOIN users u ON c.user_id = u.id WHERE c.id = ?').get(commentId);
    if (comment && comment.created_at) 
      comment.created_at = toIsoUtc(comment.created_at);
    const commentsCount = database.prepare('SELECT COUNT(*) as cnt FROM comments WHERE post_id = ?').get(postId).cnt || 0;
    res.json({ ok: true, comment, comments_count: commentsCount });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

// listen
app.listen(3030);