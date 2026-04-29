import mongoose from 'mongoose';

const AttackLogSchema = new mongoose.Schema({
    timestamp: { type: Date, default: Date.now },
    ip: String,
    method: String,
    path: String,
    attackType: String,
    payload: String,
    userAgent: String
});

const AttackLog = mongoose.model('AttackLog', AttackLogSchema);

export default AttackLog;