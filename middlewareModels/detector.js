import AttackLog from './AttackLog.js';

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

const patterns = [
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

const detectionEngine = async (req, res, next) => {
    try {
        //Getting the client IP address
        const clientIp =
            req.headers['x-forwarded-for']
                ? req.headers['x-forwarded-for'].split(',')[0]
                : req.socket.remoteAddress;

        //Raw data from the request
        const rawData = {
            query: req.query,
            body: req.body,
            params: req.params,
            headers: {
                'user-agent': req.headers['user-agent'],
                referer: req.headers['referer']
            },
            url: req.url
        };

        //Taking all the strings from the request data
        const inputs = extractStrings(rawData);

        let score = 0;
        let detectedTypes = [];

        //Checking each input against the patterns
        for (const input of inputs) {
            for (const pattern of patterns) {
                if (pattern.regex.test(input)) {
                    score += pattern.weight;
                    detectedTypes.push(pattern.name);
                }
            }
        }

        //Remove duplicates from detectedTypes
        detectedTypes = [...new Set(detectedTypes)];

        //
        const BLOCK_THRESHOLD = 5;

        if (score >= BLOCK_THRESHOLD) {
            console.log(
                `🚨 BLOCKED | IP: ${clientIp} | Score: ${score} | Types: ${detectedTypes.join(', ')}`
            );

            //Logging the attack to the database
            await AttackLog.create({
                ip: clientIp,
                method: req.method,
                path: req.path,
                attackType: detectedTypes.join(', '),
                payload: JSON.stringify(rawData),
                userAgent: req.headers['user-agent'],
                score
            });

            //Block of the request
            return res.status(403).json({
                error: 'Request blocked by security system'
            });
        }

        // לוג התקפה חשודה (אבל לא חסומה)
        if (score > 0) {
            console.log(
                `⚠️ Suspicious | IP: ${clientIp} | Score: ${score} | Types: ${detectedTypes.join(', ')}`
            );

            await AttackLog.create({
                ip: clientIp,
                method: req.method,
                path: req.path,
                attackType: detectedTypes.join(', '),
                payload: JSON.stringify(rawData),
                userAgent: req.headers['user-agent'],
                score
            });
        }

        next();
    } catch (err) {
        next();
    }
};

export default detectionEngine;