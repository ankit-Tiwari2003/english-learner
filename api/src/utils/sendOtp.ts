import nodemailer from 'nodemailer';
import crypto from 'crypto';
import { hashPassword } from './hashPassword';

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

export const generateAndSendOtp = async (email: string): Promise<string> => {
  const otp = crypto.randomInt(100000, 999999).toString(); // 6-digit OTP
  const hashedOtp = await hashPassword(otp);

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: 'Email Verification OTP',
    text: `Your OTP is ${otp}. It expires in 10 minutes.`,
  };

  await transporter.sendMail(mailOptions);
  return hashedOtp;
};