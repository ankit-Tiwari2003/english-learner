import express, { Request, Response } from 'express';
import { body, validationResult } from 'express-validator';
import { UserModel } from './models/user.model';
import { hashPassword, comparePassword } from '../../utils/hashPassword';
import { generateToken } from '../../utils/generateToken';
import { generateAndSendOtp } from '../../utils/sendOtp';
import rateLimit from 'express-rate-limit';
import morgan from 'morgan';

const router = express.Router();

// Morgan logging middleware
router.use(morgan('combined'));

// Rate limiting for all routes
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requests per IP
  message: { message: 'Too many requests from this IP, please try again later.' },
});
router.use(limiter);

// Register
router.post(
  '/register',
  [
    body('username').notEmpty().withMessage('Username is required').trim().escape(),
    body('email').isEmail().withMessage('Invalid email').normalizeEmail(),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
  ],
  async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
      return;
    }

    const { username, email, password } = req.body;

    try {
      const existingUser = await UserModel.findOne({ $or: [{ email }, { username }] });
      if (existingUser) {
        res.status(400).json({ message: 'User with this email or username already exists' });
        return;
      }

      const hashedPassword = await hashPassword(password);
      const hashedOtp = await generateAndSendOtp(email);
      const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

      const newUser = new UserModel({
        username,
        email,
        password: hashedPassword,
        otp: hashedOtp,
        otpExpires,
      });
      await newUser.save();

      res.status(201).json({ message: 'OTP sent to your email. Please verify.' });
    } catch (error: unknown) {
      console.error('Registration error:', error);
      res.status(500).json({ message: 'Server error', error: error instanceof Error ? error.message : 'Unknown error' });
    }
  }
);

// Verify OTP
router.post(
  '/verify-otp',
  [
    body('email').isEmail().withMessage('Invalid email').normalizeEmail(),
    body('otp').notEmpty().withMessage('OTP is required').isLength({ min: 6, max: 6 }).withMessage('OTP must be 6 digits'),
  ],
  async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
      return;
    }

    const { email, otp } = req.body;

    try {
      const user = await UserModel.findOne({ email });
      if (!user) {
        res.status(404).json({ message: 'User not found' });
        return;
      }
      if (user.isEmailVerified) {
        res.status(400).json({ message: 'Email already verified' });
        return;
      }
      if (!user.otp || !user.otpExpires || user.otpExpires < new Date()) {
        res.status(400).json({ message: 'OTP expired or invalid' });
        return;
      }

      const isMatch = await comparePassword(otp, user.otp);
      if (!isMatch) {
        res.status(400).json({ message: 'Invalid OTP' });
        return;
      }

      user.isEmailVerified = true;
      user.otp = null;
      user.otpExpires = null;
      await user.save();

      const token = generateToken(user._id.toString());
      res.json({ message: 'Email verified', token });
    } catch (error: unknown) {
      console.error('OTP verification error:', error);
      res.status(500).json({ message: 'Server error', error: error instanceof Error ? error.message : 'Unknown error' });
    }
  }
);

// Login
router.post(
  '/login',
  [
    body('email').isEmail().withMessage('Invalid email').normalizeEmail(),
    body('password').notEmpty().withMessage('Password is required'),
  ],
  async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
      return;
    }

    const { email, password } = req.body;

    try {
      const user = await UserModel.findOne({ email });
      if (!user) {
        res.status(401).json({ message: 'Invalid credentials' });
        return;
      }
      if (!user.isEmailVerified) {
        res.status(403).json({ message: 'Email not verified' });
        return;
      }

      const isMatch = await comparePassword(password, user.password);
      if (!isMatch) {
        res.status(401).json({ message: 'Invalid credentials' });
        return;
      }

      const token = generateToken(user._id.toString());
      res.json({ token });
    } catch (error: unknown) {
      console.error('Login error:', error);
      res.status(500).json({ message: 'Server error', error: error instanceof Error ? error.message : 'Unknown error' });
    }
  }
);

export default router;