const axios = require('axios');
const bitcoin = require('bitcoinjs-lib');
const ecpair = require('ecpair');
const tinysecp = require('tiny-secp256k1');
const { ethers } = require('ethers');
const { simpleParser } = require("mailparser");
const crypto = require('crypto');
const cheerio = require('cheerio');

const ECPair = ecpair.ECPairFactory(tinysecp);

const { cleanin, isip, getwordlist, isdomain } = require('./utils');

async function chktor(ip) {
    if (!isip(ip)) return null;
    try {
        const res = await axios.get(`https://check.torproject.org/torbulkexitlist?ip=${ip}`, {
            timeout: 5000
        });
        return res.data.includes(ip);
    } catch (e) {
        return null;
    }
}

function genbtcaddr() {
    const keypair = ECPair.makeRandom();
    const { address } = bitcoin.payments.p2pkh({ pubkey: keypair.publicKey });
    return { address, privkey: keypair.toWIF() };
}

function genethaddr() {
    const wallet = ethers.Wallet.createRandom();
    return { address: wallet.address, privkey: wallet.privateKey };
}

async function analyzeemailhdr(rawhdrs) {
    try {
        const parsed = await simpleParser(rawhdrs);
        let result = 'email header analysis:\n';
        result += `from: ${parsed.from?.text || 'unknown'}\n`;
        result += `to: ${parsed.to?.text || 'unknown'}\n`;
        result += `subject: ${parsed.subject || 'unknown'}\n`;
        result += `date: ${parsed.date || 'unknown'}\n`;
        result += `msg id: ${parsed.messageId || 'unknown'}\n`;
        result += `return-path: ${parsed.headers['return-path'] || 'unknown'}\n`;
        result += `x-mailer: ${parsed.headers['x-mailer'] || 'unknown'}\n`;
        result += `received: ${parsed.headers.received?.join('\n') || 'unknown'}\n`;
        return result;
    } catch (e) {
        return 'email header analysis error. provide full valid headers.';
    }
}

async function brutehash(hash, wordlisttype) {
    const wordlist = getwordlist(wordlisttype);
    const hash_algo = hash.length === 32 ? 'md5' : (hash.length === 40 ? 'sha1' : (hash.length === 64 ? 'sha256' : (hash.length === 128 ? 'sha512' : null)));

    if (!hash_algo) return 'invalid hash. supports md5, sha1, sha256, sha512.';

    for (const word of wordlist) {
        const hashed_word = crypto.createHash(hash_algo).update(word).digest('hex');
        if (hashed_word === hash.toLowerCase()) {
            return `hash cracked! text: ${word}`;
        }
    }
    return 'hash not cracked with given wordlist.';
}

async function searchcve(cveid) {
    const cleancve = cleanin(cveid);
    if (!cleancve || !cleancve.startsWith('cve-')) return 'invalid cve id. example: cve-2021-12345';

    try {
        const res = await axios.get(`https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cleancve.toUpperCase()}`, {
            timeout: 10000
        });
        const $ = cheerio.load(res.data);
        const desc = $('td[colspan="2"]').first().text().trim();
        const refs = [];
        $('a[href^="http"]').each((i, el) => {
            const href = $(el).attr('href');
            if (href && !href.includes('cve.mitre.org')) {
                refs.push(href);
            }
        });

        if (desc && desc !== 'No information is available for this CVE.') {
            let result = `cve info for ${cleancve.toUpperCase()}:\n`;
            result += `desc: ${desc}\n`;
            if (refs.length > 0) {
                result += `refs:\n${refs.slice(0, 5).join('\n')}`;
            }
            return result;
        }
        return `no info for cve id: ${cleancve.toUpperCase()}`;
    } catch (e) {
        return `cve search error: ${e.message}`;
    }
}

async function searchshodan(query) {
    const cleanquery = cleanin(query);
    if (!cleanquery) return 'invalid query.';

    return `shodan search (needs api key): https://www.shodan.io/search?query=${encodeURIComponent(cleanquery)}`;
}

async function monitordomain(domain) {
    const cleandomain = cleanin(domain);
    if (!cleandomain || !isdomain(cleandomain)) return 'invalid domain.';

    return `domain monitor (complex, needs storage and notifications): ${cleandomain}`;
}

async function tortest(chatid, args, sendmsg) {
    if (!args[1]) return sendmsg(chatid, 'ip required');
    const ip = args[1];
    const is_tor = await chktor(ip);
    if (is_tor === true) {
        await sendmsg(chatid, `ip ${ip} is a tor exit node.`);
    } else if (is_tor === false) {
        await sendmsg(chatid, `ip ${ip} is NOT a tor exit node.`);
    } else {
        await sendmsg(chatid, `tor check error for ${ip}.`);
    }
}

async function cryptogen(chatid, args, sendmsg) {
    if (!args[1]) return sendmsg(chatid, 'type required: btc|eth');
    const type = args[1].toLowerCase();
    let result;
    if (type === 'btc') {
        result = genbtcaddr();
        await sendmsg(chatid, `btc addr (demo):\naddr: ${result.address}\nprivkey (DO NOT SHARE!): ${result.privkey}`);
    } else if (type === 'eth') {
        result = genethaddr();
        await sendmsg(chatid, `eth addr (demo):\naddr: ${result.address}\nprivkey (DO NOT SHARE!): ${result.privkey}`);
    } else {
        await sendmsg(chatid, 'invalid crypto type. use btc or eth.');
    }
}

async function emailhdr(chatid, args, sendmsg) {
    if (!args[1]) return sendmsg(chatid, 'email headers text required');
    const rawhdrs = args.slice(1).join(' ');
    const analysis = await analyzeemailhdr(rawhdrs);
    await sendmsg(chatid, analysis);
}

async function hashbrute(chatid, args, sendmsg) {
    if (!args[2]) return sendmsg(chatid, 'hash and wordlist type required: common|rockyou|years');
    const hash = args[1];
    const type = args[2].toLowerCase();
    const result = await brutehash(hash, type);
    await sendmsg(chatid, result);
}

async function cvesearch(chatid, args, sendmsg) {
    if (!args[1]) return sendmsg(chatid, 'cve id required');
    const cveid = args[1];
    const result = await searchcve(cveid);
    await sendmsg(chatid, result);
}

async function shodansearch(chatid, args, sendmsg) {
    if (!args[1]) return sendmsg(chatid, 'query required');
    const query = args.slice(1).join(' ');
    const result = await searchshodan(query);
    await sendmsg(chatid, result);
}

async function domainmon(chatid, args, sendmsg) {
    if (!args[1]) return sendmsg(chatid, 'domain required');
    const domain = args[1];
    const result = await monitordomain(domain);
    await sendmsg(chatid, result);
}

module.exports = {
    tortest,
    cryptogen,
    emailhdr,
    hashbrute,
    cvesearch,
    shodansearch,
    domainmon
};