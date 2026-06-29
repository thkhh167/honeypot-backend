import mongoose from 'mongoose';

const blockedIpSchema = new mongoose.Schema({
    ip: { type: String, required: true, unique: true },

    strikes: { type: Number, default: 0 },

    blockedUntil: { type: Date, default: null },

    permanentlyBlocked: { type: Boolean, default: false },

    lastAttack: { type: Date, default: Date.now }
});

export default mongoose.model('BlockedIP', blockedIpSchema);