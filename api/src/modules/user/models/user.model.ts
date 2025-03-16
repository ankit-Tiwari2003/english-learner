import { Schema, model } from 'mongoose';

interface IUser {
  username: string;
  email: string;
  password: string;
  isEmailVerified: boolean;
  otp: string | null;
  otpExpires: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

const userSchema = new Schema<IUser>({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  isEmailVerified: { type: Boolean, default: false },
  otp: { type: String, default: null },
  otpExpires: { type: Date, default: null },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

// No need for explicit index calls; unique: true handles it
export const UserModel = model<IUser>('User', userSchema);