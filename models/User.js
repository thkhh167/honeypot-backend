import mongoose from 'mongoose';

const userSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  name: { type: String, required: true },
  email: { type: String, required: true },
  phone: { type: String, required: true },
  birthday: { type: String, required: true },
  balance: { type: Number, default: 1000 }
});

export default mongoose.model('User', userSchema);