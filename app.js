const express = require('express');
const validator = require('validator');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const winston = require('winston');

const JWT_SECRET = 'my-secret-key';

const app = express();
app.use(express.json());
app.use(helmet());

// -------------------- LOGGER --------------------

const logger = winston.createLogger({
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'security.log' })
  ]
});

logger.info('Server started');

// -------------------- IN-MEMORY DATABASE --------------------

const users = [];

// -------------------- MIDDLEWARE --------------------

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // expects: Bearer <token>

  if (!token) {
    return res.status(401).send('Access denied: no token provided');
  }

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    logger.warn('Invalid token used');
    return res.status(403).send('Invalid or expired token');
  }
}

// -------------------- SIGNUP --------------------

app.post('/signup', async (req, res) => {
  const { email, password } = req.body;
  logger.info(`Signup attempt: ${email}`);

  if (!validator.isEmail(email)) {
    logger.warn(`Invalid email: ${email}`);
    return res.status(400).send('Invalid email address');
  }

  if (!validator.isLength(password, { min: 6 })) {
    logger.warn(`Weak password for: ${email}`);
    return res.status(400).send('Password must be at least 6 characters');
  }

  const existing = users.find(u => u.email === email);
  if (existing) {
    logger.warn(`Duplicate signup: ${email}`);
    return res.status(400).send('Email already registered');
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const user = {
    id: users.length + 1,
    email,
    password: hashedPassword
  };
  users.push(user);
  logger.info(`New user registered: ${email}`);

  const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '1h' });

  res.status(201).json({
    message: 'Account created successfully',
    token
  });
});

// -------------------- LOGIN --------------------

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  logger.info(`Login attempt: ${email}`);

  const user = users.find(u => u.email === email);
  if (!user) {
    logger.warn(`Login failed (user not found): ${email}`);
    return res.status(401).send('Invalid email or password');
  }

  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    logger.warn(`Login failed (wrong password): ${email}`);
    return res.status(401).send('Invalid email or password');
  }

  logger.info(`Login successful: ${email}`);
  const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '1h' });

  res.json({ message: 'Logged in successfully', token });
});

// -------------------- PROTECTED ROUTE --------------------

app.get('/profile', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).send('User not found');

  res.json({ id: user.id, email: user.email });
});

// -------------------- ADMIN: LIST USERS --------------------
// NOTE: for development/testing only — remove in production

app.get('/show-users', (req, res) => {
  const safeUsers = users.map(({ password, ...rest }) => rest);
  res.json(safeUsers);
});

// -------------------- START --------------------

app.listen(4000, () => {
  console.log('App running on http://localhost:4000');
});