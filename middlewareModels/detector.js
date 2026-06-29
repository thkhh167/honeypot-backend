import AttackLog from './AttackLog.js';
import BlockedIP from './BlockedIP.js';

const normalizeIp = (req) => {
    let ip =
        req.headers['x-forwarded-for'] ||
        req.socket.remoteAddress;

    ip = ip.split(',')[0].trim();
    return ip.replace('::ffff:', '');
};

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

const securityMiddleware = async (req, res, next) => {
    try {
        const ip = normalizeIp(req);
        const now = Date.now();

        let record = await BlockedIP.findOne({ ip });

        if (!record) {
            record = await BlockedIP.create({
                ip,
                strikes: 0,
                blockedUntil: null,
                permanentlyBlocked: false,
                lastAttack: null
            });
        }

        // permanent ban
        if (record.permanentlyBlocked) {
            return res.status(403).json({ error: 'Permanently blocked' });
        }

        // temporary ban active
        if (record.blockedUntil && record.blockedUntil.getTime() > now) {
            return res.status(403).json({ error: 'Temporarily blocked' });
        }

        const requestData = {
            query: req.query,
            body: req.body,
            params: req.params
        };

        const inputs = extractStrings(requestData);

        const attack = isAttack(inputs);

        if (!attack) {
            return next();
        }

        await AttackLog.create({
            ip,
            method: req.method,
            path: req.path,
            payload: JSON.stringify(requestData),
            userAgent: req.headers['user-agent']
        });

        record.lastAttack = new Date();

        // CASE 1: first 3 attacks → temp ban
        if (record.strikes < 3) {
            record.strikes += 1;

            if (record.strikes === 3) {
                record.blockedUntil = new Date(Date.now() + 10 * 60 * 1000);
            }

            await record.save();

            return res.status(403).json({ error: 'Temporary blocked (10 min)' });
        }

        // CASE 2: user already had temp ban before AND it expired → next attack = permanent ban
        if (record.strikes >= 3) {
            record.permanentlyBlocked = true;
            await record.save();

            return res.status(403).json({ error: 'Permanently blocked' });
        }

        return next();

    } catch (err) {
        console.error(err);
        return next();
    }
};

export default securityMiddleware;