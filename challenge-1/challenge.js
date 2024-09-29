const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const mongoose = require('mongoose');
const crypto = require('crypto');
const winston = require('winston');

const app = express();

// Using bodyParser to parse POST request data
app.use(bodyParser.urlencoded({ extended: false }));

// Using express-session for session management
app.use(session({
  secret: 'secureKey',
  resave: false,
  saveUninitialized: true
}));

// Winston logger configuration
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'app.log' })
  ]
});

// MongoDB database connection 
const dbURL = 'mongodb://localhost:27017/sampledb'; // Dummy URL

// MongoDB schema for user credentials and reset tokens
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  resetToken: { type: String, default: null },
  resetTokenExpires: { type: Date, default: null }
});

const User = mongoose.model('User', userSchema);

// Connect to the database
mongoose.connect(dbURL, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => logger.info('Connected to MongoDB'))
  .catch(err => logger.error(`MongoDB connection error: ${err.message}`));

// Error handler middleware
app.use((err, req, res, next) => {
  logger.error(`Error: ${err.message}`);
  res.status(500).send('Internal Server Error');
});

// Route to request password reset
app.post('/request-reset', async (req, res, next) => {
  try {
    const { username, redirectTo } = req.body;

    const user = await User.findOne({ username });
    if (!user) {
      logger.warn(`Password reset requested for non-existent user: ${username}`);
      return res.status(404).send('User not found');
    }

    const resetToken = crypto.randomBytes(32).toString('hex');
    user.resetToken = resetToken;
    user.resetTokenExpires = Date.now() + 3600000; // 1 hour expiration
    await user.save();

    logger.info(`Password reset requested for user: ${username}`);

    const resetLink = `http://localhost:3000/reset-password?token=${resetToken}&redirectTo=${encodeURIComponent(redirectTo)}`;

    // In a real app, send the reset link via email
    logger.info(`Password reset link generated: ${resetLink}`);

    res.send(`Password reset link: ${resetLink}`);
  } catch (err) {
    next(err);
  }
});

// Route to handle password reset
app.post('/reset-password', async (req, res, next) => {
  try {
    const { token, newPassword, redirectTo } = req.body;

    // Find the user by reset token
    const user = await User.findOne({ resetToken: token, resetTokenExpires: { $gt: Date.now() } });
    if (!user) {
      logger.warn(`Invalid or expired reset token: ${token}`);
      return res.status(400).send('Invalid or expired reset token');
    }

    // Update the user's password and clear the reset token
    user.password = newPassword;
    user.resetToken = null;
    user.resetTokenExpires = null;
    await user.save();

    logger.info(`Password successfully reset for user: ${user.username}`);

    if (redirectTo) {
      logger.info(`User redirected to: ${redirectTo} after password reset`);
      return res.redirect(redirectTo); 
    }

    res.send('Password successfully reset!');
  } catch (err) {
    next(err);
  }
});

// Start the server
app.listen(3000, () => {
  console.log('Server running on port 3000');
});
