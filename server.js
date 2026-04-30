import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import dotenv from 'dotenv';
import rateLimit from 'express-rate-limit';
import User from './models/User.js';
import Transaction from './models/Transaction.js';
import Detection from './middlewareModels/detector.js';

dotenv.config();

const app = express();


app.set('trust proxy', 1);

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  validate: { trustProxy: false },
});

app.use(limiter);
app.use(cors());
app.use(express.json());
app.use(Detection);

const url = process.env.MONGO_URL;
const port = process.env.PORT || 3000;

const mongoUri = process.env.MONGO_URL; // או השם שבחרת

if (!mongoUri) {
  console.error("❌ ERROR: MONGO_URL is not defined in environment variables!");
} else {
  mongoose.connect(mongoUri)
    .then(() => console.log("✅ Connected to MongoDB Atlas"))
    .catch(err => console.error("❌ MongoDB connection error:", err));
}

mongoose.connect(url)
  .then(() => console.log('DB Connected'))
  .catch(err => console.log(err));

app.post('/register', async (req, res) => {
  const { id, name, email, birthday, phone, password } = req.body;
  if (!id || !name || !email || !birthday || !phone || !password) return res.status(400).send();
  try {
    const existingUser = await User.findOne({ id });
    if (existingUser) return res.status(409).send();
    const newUser = new User(req.body);
    await newUser.save();
    res.status(201).send();
  } catch (err) {
    res.status(500).send();
  }
});

app.get('/login', async (req, res) => {
  const { id, pass } = req.query;
  if (!id || !pass) return res.status(400).send();
  try {
    const user = await User.findOne({ id });
    if (!user || user.password !== pass) return res.status(404).send();
    res.status(200).json(user);
  } catch (err) {
    res.status(500).send();
  }
});

app.get('/users', async (req, res) => {
  try {
    const users = await User.find({});
    res.status(200).json(users);
  } catch (err) {
    res.status(500).send();
  }
});

app.patch('/user/:id', async (req, res) => {
  const { id } = req.params;
  const updates = req.body;
  if (Object.keys(updates).length === 0 || updates.id) return res.status(400).send();
  try {
    const user = await User.findOneAndUpdate({ id }, updates, { new: true });
    if (!user) return res.status(400).send();
    res.status(200).json(user);
  } catch (err) {
    res.status(500).send();
  }
});

app.delete('/user/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const user = await User.findOneAndDelete({ id });
    if (!user) return res.status(404).send();
    res.status(200).send();
  } catch (err) {
    res.status(500).send();
  }
});

app.get('/user/:id', async (req, res) => {
  try {
    const user = await User.findOne({ id: req.params.id });
    if (!user) return res.status(404).send();
    const actions = await Transaction.find({ $or: [{ senderId: req.params.id }, { receiverId: req.params.id }] }).sort({ date: -1 });
    const history = await Promise.all(actions.map(async (item) => {
      const otherId = item.senderId === req.params.id ? item.receiverId : item.senderId;
      const otherUser = await User.findOne({ id: otherId });
      return {
        date: item.date.toLocaleDateString(),
        amount: item.senderId === req.params.id ? -item.amount : item.amount,
        name: otherUser ? otherUser.name : 'Deleted User',
        id: otherId
      };
    }));
    res.status(200).json({ balance: user.balance, name: user.name, history });
  } catch (err) {
    res.status(500).send();
  }
});

app.post('/transfer', async (req, res) => {
  const { from, to, amount } = req.body;
  try {
    const fromUser = await User.findOne({ id: from });
    const toUser = await User.findOne({ id: to });
    if (!toUser || fromUser.balance < amount) return res.status(400).send();
    fromUser.balance -= amount;
    toUser.balance += amount;
    await fromUser.save();
    await toUser.save();
    const newAction = new Transaction({ senderId: from, receiverId: to, amount });
    await newAction.save();
    res.status(200).json({ newBalance: fromUser.balance });
  } catch (err) {
    res.status(500).send();
  }
});

app.listen(port, () => console.log(`Server running on ${port}`));