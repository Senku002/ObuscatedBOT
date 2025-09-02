const axios = require('axios');
const crypto = require('crypto');
const yts = require('yt-search');
const { v4: uuidv4 } = require('uuid');
const os = require('os');

const commonpass = [
    'admin', 'password', '123456', 'qwerty', 'abc123', 'password123', 'admin123',
    'letmein', 'welcome', 'monkey', 'dragon', '123456789', '12345678', '111111',
    '123123', 'login', 'secret', 'freedom', 'whatever', 'passw0rd', 'trustno1',
    'sunshine', 'shadow', 'baseball', 'football', 'superman', 'batman', 'starwars'
];

function cleanin(input) {
    if (!input || typeof input !== 'string') return null;
    const clean = input.trim().toLowerCase();
    const blocks = [
        /^127\./, /^localhost/, /^0\.0\.0\.0/, /^10\./, /^172\.(1[6-9]|2[0-9]|3[01])\./,
        /^192\.168\./, /^169\.254\./, /^::1/, /^fe80:/, /[;&|`$(){}[\$<>]/,
        /\s*&&\s*/, /\s*\|\|\s*/, /\s*;\s*/, /cat\s+/, /ls\s+/, /pwd/,
        /whoami/, /uname/, /id$/, /passwd/, /shadow/, /etc\//, /proc\//,
        /var\//, /root\//, /home\//, /usr\//, /bin\//, /curl\s+/, /wget\s+/,
        /nc\s+/, /netcat/, /bash/, /sh\s+/, /exec/, /eval/, /system/,
        /rm\s+/, /chmod/, /chown/, /sudo/, /su\s+/, /tor/, /onion/
    ];
    for (const pattern of blocks) {
        if (pattern.test(clean)) return null;
    }
    if (clean.includes('..') || clean.includes('./') || clean.includes('~/')) return null;
    return input.trim();
}

function isip(ip) {
    const ipregex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!ipregex.test(ip)) return false;
    const parts = ip.split('.').map(Number);
    if (parts.some(part => part > 255)) return false;
    if (parts[0] === 127 || parts[0] === 10 || (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
        (parts[0] === 192 && parts[1] === 168) || (parts[0] === 169 && parts[1] === 254) || parts[0] === 0) {
        return false;
    }
    return true;
}

function isdomain(domain) {
    const domainregex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?(\.[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?)*$/;
    if (!domainregex.test(domain)) return false;
    const blocks = ['localhost', 'local'];
    if (blocks.includes(domain.toLowerCase())) return false;
    return true;
}

function normurl(input) {
    if (!input || typeof input !== 'string') return null;
    let clean = input.trim();
    if (!clean.startsWith('http://') && !clean.startsWith('https://')) {
        clean = `https://${clean}`;
    }
    try {
        const url = new URL(clean);
        const hostname = url.hostname.toLowerCase();
        if (hostname === 'localhost' || hostname.startsWith('127.') || hostname.startsWith('192.168.') ||
            hostname.startsWith('10.') || /^172\.(1[6-9]|2[0-9]|3[01])\./.test(hostname)) {
            return null;
        }
        return url.toString().replace(/\/+$/, '');
    } catch (e) {
        return null;
    }
}

function genpass(len = 12) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
    let res = '';
    for (let i = 0; i < len; i++) {
        res += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return res;
}

function getwordlist(type = 'common') {
    const lists = {
        common: commonpass,
        rockyou: ['123456', 'password', '12345678', 'qwerty', '123456789', 'letmein', '1234567'],
        years: Array.from({
            length: 50
        }, (_, i) => (1970 + i).toString())
    };
    return lists[type] || lists.common;
}

function encb64(text) {
    const cleantext = cleanin(text);
    if (!cleantext) return 'invalid input';
    return Buffer.from(cleantext).toString('base64');
}

function decb64(encoded) {
    try {
        const cleanenc = cleanin(encoded);
        if (!cleanenc) return null;
        return Buffer.from(cleanenc, 'base64').toString('utf8');
    } catch (e) {
        return null;
    }
}

function encurl(text) {
    const cleantext = cleanin(text);
    if (!cleantext) return 'invalid input';
    return encodeURIComponent(cleantext);
}

function decurl(encoded) {
    try {
        const cleanenc = cleanin(encoded);
        if (!cleanenc) return null;
        return decodeURIComponent(cleanenc);
    } catch (e) {
        return null;
    }
}

function enchex(text) {
    const cleantext = cleanin(text);
    if (!cleantext) return 'invalid input';
    return Buffer.from(cleantext).toString('hex');
}

function dechex(hex) {
    try {
        const cleanhex = cleanin(hex);
        if (!cleanhex) return null;
        return Buffer.from(cleanhex, 'hex').toString('utf8');
    } catch (e) {
        return null;
    }
}

function genhash(text, algo = 'sha256') {
    const cleantext = cleanin(text);
    if (!cleantext) return 'invalid input';
    return crypto.createHash(algo).update(cleantext).digest('hex');
}

function getsysinfo() {
    return {
        platform: 'Linux',
        arch: 'x64',
        ver: '5.4.0',
        cpus: os.cpus().length,
        mem: `${(os.totalmem() / (1024 ** 3)).toFixed(2)}GB`,
        uptime: `${Math.floor(os.uptime() / 3600)}h`
    };
}

async function searchyt(query) {
    try {
        const res = await yts(query);
        if (res && res.videos.length > 0) {
            return res.videos.slice(0, 3).map(v => `${v.title}: ${v.url}`).join('\n');
        }
        return 'no results';
    } catch (e) {
        return 'yt search error';
    }
}

async function searchgoogle(query) {
    const cleanquery = cleanin(query);
    if (!cleanquery) return 'invalid query';
    try {
        const res = await axios.get(`https://serpapi.com/search.json?q=${encodeURIComponent(cleanquery)}&api_key=YOUR_SERPAPI_KEY`, {
            timeout: 10000
        });
        if (res.data.organic_results && res.data.organic_results.length > 0) {
            const results = res.data.organic_results.slice(0, 3).map(r => `${r.title}: ${r.link}`);
            return `results for "${cleanquery}"\n${results.join('\n')}`;
        }
        return `no results for "${cleanquery}"`;
    } catch (e) {
        return `google search: https://www.google.com/search?q=${encodeURIComponent(cleanquery)}`;
    }
}

async function getcryptoprice(symbol) {
    const map = {
        btc: 'bitcoin',
        eth: 'ethereum',
        ltc: 'litecoin',
        doge: 'dogecoin',
        xrp: 'ripple',
        sol: 'solana',
        ada: 'cardano',
        bnb: 'binancecoin',
        dot: 'polkadot',
        matic: 'polygon',
        link: 'chainlink',
        shib: 'shiba-inu',
        avax: 'avalanche-2',
        trx: 'tron',
        uni: 'uniswap',
        xlm: 'stellar',
        egld: 'elrond-erd-2',
        near: 'near',
        hbar: 'hedera-hashgraph',
        xmr: 'monero',
        bch: 'bitcoin-cash',
        usdt: 'tether'
    };
    const coinid = map[symbol.toLowerCase()];
    if (!coinid) return 'invalid symbol. try BTC ETH DOGE etc';
    try {
        const res = await axios.get(`https://api.coingecko.com/api/v3/simple/price?ids=${coinid}&vs_currencies=usd`, {
            timeout: 10000
        });
        if (res.data && res.data[coinid]) {
            return `${symbol.toUpperCase()}: $${res.data[coinid].usd} USD`;
        }
        return 'price error';
    } catch (e) {
        return 'price error';
    }
}

function genua() {
    const platforms = [
        'Windows NT 10.0; Win64; x64',
        'Macintosh; Intel Mac OS X 10_15_7',
        'X11; Linux x86_64',
        'iPhone; CPU iPhone OS 13_5 like Mac OS X',
        'Android 10; Mobile'
    ];
    const browsers = [
        'Chrome/91.0.4472.124 Safari/537.36',
        'Firefox/89.0',
        'Edge/91.0.864.59',
        'Safari/605.1.15',
        'Opera/77.0.4054.172'
    ];
    const randplat = platforms[Math.floor(Math.random() * platforms.length)];
    const randbrowser = browsers[Math.floor(Math.random() * browsers.length)];
    return `Mozilla/5.0 (${randplat}) AppleWebKit/537.36 (KHTML, like Gecko) ${randbrowser}`;
}

async function passgen(chatid, args, sendmsg) {
    const len = args[1] ? parseInt(args[1]) : 12;
    if (isNaN(len) || len < 4 || len > 50) {
        await sendmsg(chatid, 'invalid length. use 4-50 chars');
        return;
    }
    const pass = genpass(len);
    await sendmsg(chatid, `generated pass: ${pass}`);
}

async function wordlistgen(chatid, args, sendmsg) {
    const type = args[1] || 'common';
    const list = getwordlist(type);
    await sendmsg(chatid, `list ${type}\n${list.join('\n')}`);
}

async function b64enc(chatid, args, sendmsg) {
    if (!args[1]) return sendmsg(chatid, 'text required');
    const text = args.slice(1).join(' ');
    const encoded = encb64(text);
    await sendmsg(chatid, `b64 encoded: ${encoded}`);
}

async function b64dec(chatid, args, sendmsg) {
    if (!args[1]) return sendmsg(chatid, 'text required');
    const text = args.slice(1).join(' ');
    const decoded = decb64(text);
    if (decoded) {
        await sendmsg(chatid, `b64 decoded: ${decoded}`);
    } else {
        await sendmsg(chatid, 'b64 decode failed');
    }
}

async function urlenc(chatid, args, sendmsg) {
    if (!args[1]) return sendmsg(chatid, 'text required');
    const text = args.slice(1).join(' ');
    const encoded = encurl(text);
    await sendmsg(chatid, `url encoded: ${encoded}`);
}

async function urldec(chatid, args, sendmsg) {
    if (!args[1]) return sendmsg(chatid, 'text required');
    const text = args.slice(1).join(' ');
    const decoded = decurl(text);
    if (decoded) {
        await sendmsg(chatid, `url decoded: ${decoded}`);
    } else {
        await sendmsg(chatid, 'url decode failed');
    }
}

async function hexenc(chatid, args, sendmsg) {
    if (!args[1]) return sendmsg(chatid, 'text required');
    const text = args.slice(1).join(' ');
    const encoded = enchex(text);
    await sendmsg(chatid, `hex encoded: ${encoded}`);
}

async function hexdec(chatid, args, sendmsg) {
    if (!args[1]) return sendmsg(chatid, 'text required');
    const text = args.slice(1).join(' ');
    const decoded = dechex(text);
    if (decoded) {
        await sendmsg(chatid, `hex decoded: ${decoded}`);
    } else {
        await sendmsg(chatid, 'hex decode failed');
    }
}

async function hashgen(chatid, args, sendmsg) {
    if (!args[1]) return sendmsg(chatid, 'text required');
    const text = args.slice(1, args.length > 2 ? -1 : undefined).join(' ');
    const algo = args.length > 2 ? args[args.length - 1] : 'sha256';
    if (!['md5', 'sha1', 'sha256', 'sha512'].includes(algo)) {
        await sendmsg(chatid, 'invalid algo. use: md5, sha1, sha256, sha512');
        return;
    }
    const hash = genhash(text, algo);
    await sendmsg(chatid, `hash ${algo}: ${hash}`);
}

async function sysinfo(chatid, sendmsg) {
    const info = getsysinfo();
    const txt = `system:
platform: ${info.platform}
arch: ${info.arch}
ver: ${info.ver}
cpus: ${info.cpus}
mem: ${info.mem}
uptime: ${info.uptime}`;
    await sendmsg(chatid, txt);
}

async function ytsearch(chatid, args, sendmsg) {
    if (!args[1]) return sendmsg(chatid, 'query required');
    const query = args.slice(1).join(' ');
    const results = await searchyt(query);
    await sendmsg(chatid, results);
}

async function googlesearch(chatid, args, sendmsg) {
    if (!args[1]) return sendmsg(chatid, 'query required');
    const query = args.slice(1).join(' ');
    const results = await searchgoogle(query);
    await sendmsg(chatid, results);
}

async function cryptoprice(chatid, args, sendmsg) {
    if (!args[1]) return sendmsg(chatid, 'symbol required');
    const symbol = args[1];
    const price = await getcryptoprice(symbol);
    await sendmsg(chatid, price);
}

async function uuidgen(chatid, sendmsg) {
    const id = uuidv4();
    await sendmsg(chatid, `generated uuid: ${id}`);
}

async function ua(chatid, sendmsg) {
    const useragent = genua();
    await sendmsg(chatid, `generated ua:\n${useragent}`);
}

async function sendmsg(id, txt, opts = {}) {
    try {

        const TelegramBot = require('node-telegram-bot-api');
        const token = process.env.TELEGRAM_TOKEN || 'my-key-api';
        const botInstance = new TelegramBot(token);
        const res = await botInstance.sendMessage(id, txt, opts);
        return res;
    } catch (e) {
        if (e.response && e.response.statusCode === 429) {
            const retry = e.response.body.parameters?.retry_after || 5;
            await new Promise(r => setTimeout(r, retry * 1000));
            try {
                const TelegramBot = require('node-telegram-bot-api');
                const token = process.env.TELEGRAM_TOKEN || 'my-key-api';
                const botInstance = new TelegramBot(token);
                return await botInstance.sendMessage(id, txt, opts);
            } catch (retry_e) {
                console.log('msg err:', retry_e.message);
                return null;
            }
        }
        console.log('msg err:', e.message);
        return null;
    }
}

function isadmin(user, adminsList) {
    return adminsList.includes(user);
}

function reqlimit(id, reqlimiterMap) {
    const now = Date.now();
    const reqs = reqlimiterMap.get(id) || [];
    const validreqs = reqs.filter(time => now - time < 60000);
    if (validreqs.length >= 10) return false;
    validreqs.push(now);
    reqlimiterMap.set(id, validreqs);
    return true;
}

function spamchk(id, spamtrackerMap, antispamStatus) {
    if (!antispamStatus) return 0;
    const now = Date.now();
    const userspam = spamtrackerMap.get(id) || [];
    userspam.push(now);
    const recentspam = userspam.filter(time => now - time < 30000);
    spamtrackerMap.set(id, recentspam);
    return recentspam.length;
}


module.exports = {
    passgen,
    wordlistgen: getwordlist,
    b64enc,
    b64dec,
    urlenc,
    urldec,
    hexenc,
    hexdec,
    hashgen,
    sysinfo,
    ytsearch,
    googlesearch,
    cryptoprice,
    uuidgen,
    ua,
    cleanin,
    isip,
    isdomain,
    normurl,
    sendmsg,
    isadmin,
    reqlimit,
    spamchk,
    getwordlist
};