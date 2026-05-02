const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const router = express.Router();

// In-memory user store (replace with a database in production)
const users = [];

/**
 * POST /auth/register
 * Register a new user
 */
router.post('/register', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  const exists = users.find(u => u.username === username);
  if (exists) {
    return res.status(409).json({ error: 'Username already taken' });
  }

  const hashed = await bcrypt.hash(password, 10);
  const user = { id: Date.now(), username, password: hashed };
  users.push(user);

  res.status(201).json({ message: 'User registered successfully', userId: user.id });
});

/**
 * POST /auth/login
 * Authenticate and receive a JWT token
 */
router.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  const user = users.find(u => u.username === username);
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = jwt.sign(
    { userId: user.id, username: user.username },
    process.env.JWT_SECRET || 'changeme',
    { expiresIn: '24h' }
  );

  res.json({ token });
});

/**
 * GET /auth/me
 * Get the current authenticated user (protected route)
 */
router.get('/me', authenticateToken, (req, res) => {
  res.json({ userId: req.user.userId, username: req.user.username });
});

/**
 * Middleware to verify JWT token
 */
function authenticateToken(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET || 'changeme');
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

module.exports = { router, authenticateToken };
