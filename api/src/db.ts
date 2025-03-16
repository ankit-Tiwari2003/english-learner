import mongoose from 'mongoose';
import dotenv from 'dotenv';

dotenv.config();

const connectDB = async () => {
  try {
    const mongoUrl = process.env.MONGODB_URL || 'mongodb://admin:secure_password@localhost:27017/myappdb';
    if (!mongoUrl) throw new Error('MONGODB_URL is not defined');
    await mongoose.connect(mongoUrl, {
      autoIndex: true,
      maxPoolSize: 10,
    });
    console.log('MongoDB connected');
  } catch (err) {
    console.error('MongoDB connection error:', err);
    process.exit(1);
  }
};

export default connectDB;