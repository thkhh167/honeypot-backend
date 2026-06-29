import AttackLog from './AttackLog.js';
import BlockedIP from './BlockedIP.js';

const normalizeIp = (req) => {
    let ip =
        req.headers['x-forwarded-for'] ||
        req.socket.remoteAddress;

    ip = ip.split(',')[0].trim();
    return ip.replace('::ffff:', '');
};

// extracting only string values from request
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

// simple attack detection (boolean only)
const attackPatterns = [
    /(\bunion\b.*\bselect\b|\bdrop\b|\binsert\b|\bupdate\b|--|#|'|\bor\b\s+\d+=\d+)/i,
    /(\$ne|\$gt|\$lt|\$or|\$in|\$exists|\$where)/i,
    /(<script|<\/script>|onerror=|onload=|javascript:|alert\(|<img)/i,
    /(\.\.\/|\.\.\\|\/etc\/passwd|boot\.ini)/i
];

const isAttack = (inputs) => {
    return inputs.some(input =>
        attackPatterns.some(pattern => pattern.test(input))
    );
};

const isCurrentlyBlocked = (record) => {
    if (!record) return false;

    if (record.permanentlyBlocked) return true;

    if (record.blockedUntil && record.blockedUntil.getTime() > Date.now()) {
        return true;
    }

    return false;
};

const securityMiddleware = async (req, res, next) => {
    try {
        const ip = normalizeIp(req);

        let record = await BlockedIP.findOne({ ip });

        const now = Date.now();

        // create record if not exists
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

        // check if currently blocked (temp or perm)
        if (isCurrentlyBlocked(record)) {
            return res.status(403).json({
                error: 'Your IP is blocked'
            });
        }

        const requestData = {
            query: req.query,
            body: req.body,
            params: req.params
        };

        const inputs = extractStrings(requestData);

        const attack = isAttack(inputs);

        // normal request → do nothing
        if (!attack) {
            return next();
        }

        // log attack
        await AttackLog.create({
            ip,
            method: req.method,
            path: req.path,
            payload: JSON.stringify(requestData),
            userAgent: req.headers['user-agent']
        });

        record.lastAttack = new Date();

        // CASE 1: first 3 attacks → temporary ban
        if (record.banPhase === 0) {
            record.strikes += 1;

            if (record.strikes >= 3) {
                record.blockedUntil = new Date(Date.now() + 10 * 60 * 1000);
                record.banPhase = 1;
            }

            await record.save();

            return res.status(403).json({
                error: 'Temporary blocked (10 min)'
            });
        }

        // CASE 2: after temp ban expired → next attack = permanent ban
        if (record.banPhase === 1) {
            record.permanentlyBlocked = true;
            await record.save();

            return res.status(403).json({
                error: 'Permanently blocked'
            });
        }

        return next();

    } catch (err) {
        console.error(err);
        return next();
    }
};

export default securityMiddleware;