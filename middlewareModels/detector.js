import AttackLog from './AttackLog.js';

const detectionEngine = async (req, res, next) => {
    try {
        const clientIp = req.headers['x-forwarded-for'] 
    ? req.headers['x-forwarded-for'].split(',')[0]
    : req.socket.remoteAddress;

        const dataToScan = JSON.stringify({
            query: req.query,
            body: req.body,
            url: req.url,
            headers: {
                "user-agent": req.headers['user-agent'],
                "referer": req.headers['referer']
            }
        });

        const signatures = [
            { name: 'SQL Injection', pattern: /('|--|#|\bOR\b|\bSELECT\b|\bUNION\b|\bDROP\b|\bUPDATE\b)/i },
            { name: 'NoSQL Injection', pattern: /(\$gt|\$lt|\$ne|\$eq|\$in|\$nin|\$exists|\$where)/i },
            { name: 'XSS', pattern: /(<script|alert\(|<img|onerror=|javascript:|eval\(|onload=)/i },
            { name: 'Path Traversal', pattern: /(\.\.\/|\.\.\\|etc\/passwd|boot\.ini)/i }
        ];

        let detectedAttack = null;
        for (let sig of signatures) {
            if (sig.pattern.test(dataToScan)) {
                detectedAttack = sig.name;
                break; 
            }
        }

        if (detectedAttack) {
            console.log(`⚠️ Attack Detected! : ${detectedAttack} | IP: ${clientIp} | Path: ${req.path}`);

            await AttackLog.create({
                ip: clientIp,
                method: req.method,
                path: req.path,
                attackType: detectedAttack,
                payload: dataToScan,
                userAgent: req.headers['user-agent']
            });
        }

        next(); 
    } catch (err) {
        next(); 
    }
};

export default detectionEngine;