require('dotenv').config();
const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const RECAPTCHA_SECRET = process.env.RECAPTCHA_SECRET;
const BOT_TOKEN = process.env.BOT_TOKEN;

if (!RECAPTCHA_SECRET || !BOT_TOKEN) {
    console.error('Missing required environment variables');
    process.exit(1);
}

const VERIFIED_FILE = path.join(__dirname, 'verified.json');
const rateLimit = new Map();

if (!fs.existsSync(VERIFIED_FILE)) {
    fs.writeFileSync(VERIFIED_FILE, JSON.stringify({}));
}

const readVerified = () => {
    try {
        return JSON.parse(fs.readFileSync(VERIFIED_FILE, 'utf8'));
    } catch {
        return {};
    }
};

const writeVerified = (data) => {
    fs.writeFileSync(VERIFIED_FILE, JSON.stringify(data, null, 2));
};

const sendTelegramMessage = async (userId, text) => {
    try {
        const url = `https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`;
        await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                chat_id: userId,
                text: text
            })
        });
    } catch (error) {
        console.error('Telegram send error:', error);
    }
};

const checkRateLimit = (ip) => {
    const now = Date.now();
    const windowMs = 60000;
    const maxRequests = 10;
    
    if (!rateLimit.has(ip)) {
        rateLimit.set(ip, []);
    }
    
    const timestamps = rateLimit.get(ip).filter(t => now - t < windowMs);
    timestamps.push(now);
    rateLimit.set(ip, timestamps);
    
    return timestamps.length <= maxRequests;
};

app.use(express.json());

app.use((req, res, next) => {
    const ip = req.ip || req.connection.remoteAddress;
    if (!checkRateLimit(ip)) {
        return res.status(429).json({ error: 'Too many requests' });
    }
    next();
});

app.post('/verify', async (req, res) => {
    try {
        const { token, userId } = req.body;
        
        if (!token || typeof token !== 'string') {
            return res.status(400).json({ success: false, message: 'Invalid token' });
        }
        
        if (!userId || !/^\d+$/.test(userId)) {
            return res.status(400).json({ success: false, message: 'Invalid user ID' });
        }
        
        const params = new URLSearchParams({
            secret: RECAPTCHA_SECRET,
            response: token
        });
        
        const response = await fetch('https://www.google.com/recaptcha/api/siteverify', {
            method: 'POST',
            body: params
        });
        
        const data = await response.json();
        
        if (data.success) {
            const verified = readVerified();
            verified[userId] = {
                verified: true,
                timestamp: Date.now()
            };
            writeVerified(verified);
            
            await sendTelegramMessage(userId, '✅ Verification successful. You may now continue in the bot.');
            
            return res.json({ success: true });
        } else {
            return res.status(400).json({ 
                success: false, 
                message: 'Verification failed',
                errors: data['error-codes'] || []
            });
        }
    } catch (error) {
        console.error('Verification error:', error);
        return res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

app.get('/check', (req, res) => {
    try {
        const { uid } = req.query;
        
        if (!uid || !/^\d+$/.test(uid)) {
            return res.status(400).json({ verified: false });
        }
        
        const verified = readVerified();
        const userVerified = verified[uid] && verified[uid].verified === true;
        
        return res.json({ verified: userVerified });
    } catch (error) {
        console.error('Check error:', error);
        return res.status(500).json({ verified: false });
    }
});

app.use((req, res) => {
    res.status(404).json({ error: 'Not found' });
});

app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});