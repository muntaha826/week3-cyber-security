const express = require('express');
const validator = require('validator');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');


const app = express();
app.use(helmet());
app.use(express.json());

const users = [];

app.post('/signup', async (req, res) => {
  const { email, password } = req.body;

  // Validate email
  if (!validator.isEmail(email)) {
    return res.status(400).send('Invalid email');
  }

  // Validate password length
  if (!validator.isLength(password, { min: 6 })) {
    return res.status(400).send('Password must be at least 6 characters');
  }

  // Hash the password
  const hashedPassword = await bcrypt.hash(password, 10);

 const user = {
  id: users.length + 1,
  email,
  password: hashedPassword
};

users.push(user);

// Generate JWT token
const token = jwt.sign(
  { id: user.id },
  'your-secret-key',
  { expiresIn: '1h' }
);

res.status(201).json({
  message: 'User created successfully',
  token:token
});
});

app.get('/show-users', (req, res) => { res.json(users); });

app.listen(4000, () => {
  console.log('App running on http://localhost:4000');
});