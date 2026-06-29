import AttackLog from './AttackLog.js';
import BlockedIP from './BlockedIP.js';

// extract all string values from request
const extractStrings = (obj) => {
    let results = [];

    const walk = (o) => {
        if (!o) return;

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

// check if IP is blocked
const isIpBlocked = (ipRecord) => {
    if (!ipRecord) return false;

    if (ipRecord.permanentlyBlocked) return true;

    if (ipRecord.blockedUntil && ipRecord.blockedUntil > Date.now()) {
        return true;
    }

    return false;
};

// get or create IP record in MongoDB
const getOrCreateIpRecord = async (ip) => {
    let record = await BlockedIP.findOne({ ip });

    if (!record) {
        record = await BlockedIP.create({
            ip,
            strikes: 0,
            blockedUntil: null,
            permanentlyBlocked: false
        });
    }

    return record;
};

// detection rules
const attackSignatures = [
    {
        name: 'SQL Injection',
        weight: 5,
        regex: /(\bunion\b.*\bselect\b|\bdrop\b|\binsert\b|\bupdate\b|--|#|'|\bor\b\s+\d+=\d+)/i
    },
    {
        name: 'NoSQL Injection',
        weight: 5,
        regex: /(\$ne|\$gt|\$lt|\$or|\$in|\$exists|\$where)/i
    },
    {
        name: 'XSS',
        weight: 5,
        regex: /(<script|<\/script>|onerror=|onload=|javascript:|alert\(|<img)/i
    },
    {
        name: 'Path Traversal',
        weight: 4,
        regex: /(\.\.\/|\.\.\\|\/etc\/passwd|boot\.ini)/i
    }
];

const securityMiddleware = async (req, res, next) => {
    try {
        // get client IP (works behind proxy like Render)
        const clientIp =
            req.headers['x-forwarded-for']
                ? req.headers['x-forwarded-for'].split(',')[0]
                : req.socket.remoteAddress;

        // load IP from DB
        const ipRecord = await getOrCreateIpRecord(clientIp);

        // if blocked → stop immediately
        if (isIpBlocked(ipRecord)) {
            return res.status(403).json({
                error: 'Your IP is blocked by security system'
            });
        }

        // build request snapshot
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

        // extract all strings
        const inputs = extractStrings(requestData);

        let score = 0;
        let detectedTypes = [];

        // scan inputs
        for (const input of inputs) {
            for (const sig of attackSignatures) {
                if (sig.regex.test(input)) {
                    score += sig.weight;
                    detectedTypes.push(sig.name);
                }
            }
        }

        detectedTypes = [...new Set(detectedTypes)];

        const BLOCK_THRESHOLD = 5;

        // if attack detected
        if (score >= BLOCK_THRESHOLD) {

            // increase strike
            ipRecord.strikes += 1;
            ipRecord.lastAttack = new Date();

            // temporary ban after 3 strikes
            if (ipRecord.strikes >= 3 && ipRecord.strikes < 5) {
                ipRecord.blockedUntil = new Date(Date.now() + 10 * 60 * 1000);
            }

            // permanent ban after 5 strikes
            if (ipRecord.strikes >= 5) {
                ipRecord.permanentlyBlocked = true;
            }

            await ipRecord.save();

            console.log(
                `🚨 BLOCKED | IP: ${clientIp} | Score: ${score} | Types: ${detectedTypes.join(', ')}`
            );

            // log attack
            await AttackLog.create({
                ip: clientIp,
                method: req.method,
                path: req.path,
                attackType: detectedTypes.join(', '),
                payload: JSON.stringify(requestData),
                userAgent: req.headers['user-agent'],
                score
            });

            return res.status(403).json({
                error: 'Request blocked by security system'
            });
        }

        // suspicious but not blocked
        if (score > 0) {
            console.log(
                `⚠️ SUSPICIOUS | IP: ${clientIp} | Score: ${score} | Types: ${detectedTypes.join(', ')}`
            );

            await AttackLog.create({
                ip: clientIp,
                method: req.method,
                path: req.path,
                attackType: detectedTypes.join(', '),
                payload: JSON.stringify(requestData),
                userAgent: req.headers['user-agent'],
                score
            });
        }

        next();
    } catch (err) {
        next();
    }
};

export default securityMiddleware;