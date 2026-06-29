import AttackLog from './AttackLog.js';
import BlockedIP from './BlockedIP.js';

// normalizing IP so I don't get duplicates from proxies / ngrok / render
const normalizeIp = (req) => {
    let ip =
        req.headers['x-forwarded-for'] ||
        req.socket.remoteAddress;

    ip = ip.split(',')[0].trim();
    return ip.replace('::ffff:', '');
};

// extracting only string values so I can scan everything safely
const extractStrings = (obj) => {
    const results = [];

    const walk = (o) => {
        if (!o || typeof o !== 'object') return;

        for (const key in o) {
            const value = o[key];

            if (typeof value === 'string') {
                results.push(value);
            } else if (typeof value === 'object') {
                walk(value);
            }
        }
    };

    walk(obj);
    return results;
};

// simple attack detection rules (regex based)
const attackPatterns = [
    /(\bunion\b.*\bselect\b|\bdrop\b|\binsert\b|\bupdate\b|--|#|'|\bor\b\s+\d+=\d+)/i,
    /(\$ne|\$gt|\$lt|\$or|\$in|\$exists|\$where)/i,
    /(<script|<\/script>|onerror=|onload=|javascript:|alert\(|<img)/i,
    /(\.\.\/|\.\.\\|\/etc\/passwd|boot\.ini)/i
];

// checking if request contains any attack pattern
const isAttack = (inputs) => {
    return inputs.some(input =>
        attackPatterns.some(pattern => pattern.test(input))
    );
};

// checking if IP is currently blocked (temp or permanent)
const isCurrentlyBlocked = (record) => {
    if (!record) return false;

    if (record.permanentlyBlocked) return true;

    if (record.blockedUntil && record.blockedUntil > Date.now()) {
        return true;
    }

    return false;
};

// main security middleware
const securityMiddleware = async (req, res, next) => {
    try {
        const ip = normalizeIp(req);

        // load or create IP record
        let record = await BlockedIP.findOne({ ip });

        if (!record) {
            record = await BlockedIP.create({
                ip,
                strikes: 0,
                blockedUntil: null,
                permanentlyBlocked: false,
                lastAttack: null,
                banPhase: 0
            });
        }

        // if IP is already blocked → stop immediately
        if (isCurrentlyBlocked(record)) {
            return res.status(403).json({
                error: 'Your IP is blocked by security system'
            });
        }

        // building request snapshot for scanning
        const requestData = {
            query: req.query,
            body: req.body,
            params: req.params
        };

        // extracting all string inputs
        const inputs = extractStrings(requestData);

        // checking if request is malicious
        const attackDetected = isAttack(inputs);

        // if it's NOT an attack → continue normally
        if (!attackDetected) {
            return next();
        }

        // from here → request is malicious, so I block it immediately
        const now = Date.now();
        console.log(
    `🚨 BLOCKED | IP: ${ip} | PATH: ${req.path}`
);
        // log the attack before doing anything else
        await AttackLog.create({
            ip,
            method: req.method,
            path: req.path,
            payload: JSON.stringify(requestData),
            userAgent: req.headers['user-agent'],
            createdAt: new Date()
        });

        // update last attack time
        record.lastAttack = now;

        // first stage: temporary ban system
        if (record.banPhase === 0) {
            record.strikes += 1;

            // after 3 attacks → temporary ban for 10 minutes
            if (record.strikes >= 3) {
                record.blockedUntil = now + 10 * 60 * 1000;
                record.banPhase = 1;
            }

            await record.save();

            return res.status(403).json({
                error: 'Request blocked by security system'
            });
        }

        // second stage: after temp ban, next attack = permanent ban
        if (record.banPhase === 1) {
            record.permanentlyBlocked = true;
            await record.save();

            return res.status(403).json({
                error: 'Permanently blocked'
            });
        }

        return next();

    } catch (err) {
        console.error('security middleware error:', err);
        return next();
    }
};

export default securityMiddleware;