import AttackLog from './AttackLog.js';
import BlockedIP from './BlockedIP.js';

const ipCache = new Map();

// normalizing the IP so I don’t get duplicates from proxies or ngrok
const normalizeIp = (req) => {
    let ip =
        req.headers['x-forwarded-for'] ||
        req.socket.remoteAddress;

    ip = ip.split(',')[0].trim();
    ip = ip.replace('::ffff:', '');

    return ip;
};

// extracting only string values from the request so I can scan them
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

// attack patterns I check against every request input
const attackSignatures = [
    { name: 'SQL Injection', weight: 5, regex: /(\bunion\b.*\bselect\b|\bdrop\b|\binsert\b|\bupdate\b|--|#|'|\bor\b\s+\d+=\d+)/i },
    { name: 'NoSQL Injection', weight: 5, regex: /(\$ne|\$gt|\$lt|\$or|\$in|\$exists|\$where)/i },
    { name: 'XSS', weight: 5, regex: /(<script|<\/script>|onerror=|onload=|javascript:|alert\(|<img)/i },
    { name: 'Path Traversal', weight: 4, regex: /(\.\.\/|\.\.\\|\/etc\/passwd|boot\.ini)/i }
];

// checking if an IP is already blocked, with cache to avoid DB spam
const isBlocked = async (ip) => {
    if (ipCache.has(ip)) {
        return ipCache.get(ip);
    }

    const record = await BlockedIP.findOne({ ip });

    if (!record) {
        ipCache.set(ip, false);
        return false;
    }

    const now = Date.now();

    const blocked =
        record.permanentlyBlocked ||
        (record.blockedUntil && record.blockedUntil.getTime() > now);

    ipCache.set(ip, blocked);

    return blocked;
};

// getting or creating an IP record only when I actually need to store something
const getOrCreateIpRecord = async (ip) => {
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

    return record;
};

// main security middleware
const securityMiddleware = async (req, res, next) => {
    try {
        const clientIp = normalizeIp(req);

        // first check if the IP is already blocked before doing any heavy work
        const alreadyBlocked = await isBlocked(clientIp);

        if (alreadyBlocked) {
            console.log(`blocked request from ip ${clientIp}`);

            return res.status(403).json({
                error: 'Your IP is blocked by security system'
            });
        }

        // building request snapshot for scanning
        const requestData = {
            query: req.query,
            body: req.body,
            params: req.params,
            headers: {
                userAgent: req.headers['user-agent'],
                referer: req.headers['referer']
            },
            url: req.url
        };

        // extracting all string inputs from request
        const inputs = extractStrings(requestData);

        let score = 0;
        const detectedTypes = new Set();

        // scanning all inputs against attack signatures
        for (const input of inputs) {
            for (const sig of attackSignatures) {
                if (sig.regex.test(input)) {
                    score += sig.weight;
                    detectedTypes.add(sig.name);
                }
            }
        }

        const typesArray = [...detectedTypes];

        const BLOCK_THRESHOLD = 5;

        // if nothing suspicious was found I don’t touch the database at all
        if (score === 0) {
            return next();
        }

        // only now I interact with the database
        const ipRecord = await getOrCreateIpRecord(clientIp);

        ipRecord.lastAttack = new Date();

        // if score is high enough I treat it as an attack
        if (score >= BLOCK_THRESHOLD) {
            ipRecord.strikes += 1;

            // temporary block after repeated strikes
            if (ipRecord.strikes >= 3 && ipRecord.strikes < 5) {
                ipRecord.blockedUntil = new Date(Date.now() + 10 * 60 * 1000);
            }

            // permanent block after too many strikes
            if (ipRecord.strikes >= 5) {
                ipRecord.permanentlyBlocked = true;
            }

            await ipRecord.save();

            ipCache.set(clientIp, true);

            console.log(
                `blocked attack ip ${clientIp} score ${score} types ${typesArray.join(', ')}`
            );

            await AttackLog.create({
                ip: clientIp,
                method: req.method,
                path: req.path,
                attackType: typesArray.join(', '),
                payload: JSON.stringify(requestData),
                userAgent: req.headers['user-agent'],
                score
            });

            return res.status(403).json({
                error: 'Request blocked by security system'
            });
        }

        // suspicious request but not enough to block
        console.log(
            `suspicious request ip ${clientIp} score ${score} types ${typesArray.join(', ')}`
        );

        await AttackLog.create({
            ip: clientIp,
            method: req.method,
            path: req.path,
            attackType: typesArray.join(', '),
            payload: JSON.stringify(requestData),
            userAgent: req.headers['user-agent'],
            score
        });

        return next();

    } catch (err) {
        console.error('security middleware error', err);
        return next();
    }
};

export default securityMiddleware;