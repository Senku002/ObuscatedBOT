const axios = require('axios');
const cheerio = require('cheerio');
const libphonenumber = require('google-libphonenumber');
const phoneUtil = libphonenumber.PhoneNumberUtil.getInstance();
const PNF = libphonenumber.PhoneNumberFormat;
const exiftool = require('node-exiftool');
const exiftoolBin = require('dist-exiftool');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');

const ep = new exiftool.ExiftoolProcess(exiftoolBin);

const { cleanin, isdomain, normurl } = require('./utils');

async function searchphone(number) {
    const cleannum = cleanin(number);
    if (!cleannum) return 'invalid phone number';
    try {
        const parsed = phoneUtil.parseAndKeepRawInput(cleannum);
        const isValid = phoneUtil.isValidNumber(parsed);
        if (isValid) {
            const country = phoneUtil.getRegionCodeForNumber(parsed) || 'not found';
            const formatted = phoneUtil.format(parsed, PNF.E164);
            const type = phoneUtil.getNumberType(parsed);

            return `number: ${formatted}
valid: ${isValid}
country: ${country}
operator: type-${type}`;
        }
        return 'invalid or not found';
    } catch (e) {
        return `search ${cleannum} manually on truecaller.com`;
    }
}

async function searchuser(username) {
    const cleanuser = cleanin(username);
    if (!cleanuser) return [];
    const platforms = [
        `https://github.com/${cleanuser}`,
        `https://x.com/${cleanuser}`,
        `https://instagram.com/${cleanuser}`,
        `https://facebook.com/${cleanuser}`,
        `https://linkedin.com/in/${cleanuser}`,
        `https://reddit.com/user/${cleanuser}`,
        `https://youtube.com/@${cleanuser}`,
        `https://tiktok.com/@${cleanuser}`
    ];
    const found = [];
    for (const url of platforms) {
        try {
            const res = await axios.get(url, {
                timeout: 5000
            });
            if (res.status === 200) found.push(url);
        } catch (e) {}
    }
    return found;
}

function googledorks(domain) {
    const cleandomain = cleanin(domain);
    if (!cleandomain || !isdomain(cleandomain)) return [];
    const dorks = [
        `site:${cleandomain} filetype:pdf`,
        `site:${cleandomain} intitle:"index of"`,
        `site:${cleandomain} inurl:(admin | login | dashboard)`,
        `site:${cleandomain} filetype:(sql | bak | zip)`,
        `site:${cleandomain} filetype:log`,
        `site:${cleandomain} intext:(password | confidential)`,
        `site:${cleandomain} filetype:(xls | xlsx | csv)`,
        `"@${cleandomain}" password`
    ];
    return dorks.map(dork => `https://www.google.com/search?q=${encodeURIComponent(dork)}`);
}

async function getexif(imgurl) {
    try {
        const res = await axios.get(imgurl, {
            responseType: 'arraybuffer',
            timeout: 10000
        });
        const buf = Buffer.from(res.data);
        const tmppath = `./temp_img_${uuidv4()}.jpg`;
        fs.writeFileSync(tmppath, buf);

        await ep.open();
        const data = await ep.readMetadata(tmppath, ['-File:all']);
        await ep.close();
        fs.unlinkSync(tmppath);

        if (data.data && data.data.length > 0) {
            let info = 'exif metadata:\n';
            for (const key in data.data[0]) {
                if (typeof data.data[0][key] !== 'object') {
                    info += `${key}: ${data.data[0][key]}\n`;
                }
            }
            return info;
        }
        return 'no exif metadata found.';
    } catch (e) {
        if (ep.isOpen) await ep.close();
        return `exif extract error: ${e.message}`;
    }
}

async function chklink(url) {
    const cleanurl = normurl(url);
    if (!cleanurl) return 'invalid url.';

    let findings = [];

    try {
        const parsed = new URL(cleanurl);
        const host = parsed.hostname;

        if (host.includes('-') && host.split('-').length > 3) {
            findings.push('suspicious domain name (many hyphens).');
        }
        if (host.includes('xn--')) {
            findings.push('punycode domain (homograph attack possible).');
        }
        if (parsed.searchParams.has('redirect') || parsed.searchParams.has('url') || parsed.searchParams.has('next')) {
            findings.push('redirection params (potential open redirect).');
        }
        if (parsed.protocol !== 'https:') {
            findings.push('no https (insecure connection).');
        }

        const res = await axios.get(cleanurl, {
            timeout: 10000,
            validateStatus: status => status >= 200 && status < 500
        });
        const html = res.data.toLowerCase();

        if (html.includes('login') && html.includes('password') && !html.includes('https')) {
            findings.push('insecure login page (no https).');
        }
        if (html.includes('captcha') && html.includes('verify') && res.status === 200) {
            findings.push('captcha/verify present (possible phishing page).');
        }

    } catch (e) {
        findings.push(`link analysis error: ${e.message}`);
    }

    if (findings.length === 0) {
        return 'link seems safe (no suspicious indicators).';
    }
    return `link analysis for ${url}:\n${findings.join('\n')}`;
}

async function chksubtakeover(domain) {
    const cleandomain = cleanin(domain);
    if (!cleandomain || !isdomain(cleandomain)) return 'invalid domain.';

    const vulncnames = [
        'ghs.google.com',
        'pages.github.com',
        'herokudns.com',
        's3-website-us-east-1.amazonaws.com',
        'awsglobalaccelerator.com',
        'cdn.shopify.com',
        'cname.vercel-dns.com',
        'domains.tumblr.com',
        'proxy.webflow.com',
        'cname.zendesk.com'
    ];

    try {
        const cnamerecs = await new Promise((r, rej) => {
            require('dns').resolveCname(cleandomain, (err, addrs) => {
                if (err) rej(err);
                else r(addrs);
            });
        });

        if (cnamerecs && cnamerecs.length > 0) {
            for (const cname of cnamerecs) {
                for (const vuln of vulncnames) {
                    if (cname.includes(vuln)) {
                        return `potential subdomain takeover for ${cleandomain} via cname to ${cname} (vulnerable service: ${vuln}).`;
                    }
                }
            }
        }
        return `no potential subdomain takeover detected for ${cleandomain}.`;
    } catch (e) {
        if (e.code === 'ENODATA' || e.code === 'ENOTFOUND') {
            return `no potential subdomain takeover detected for ${cleandomain} (no cname records).`;
        }
        return `subdomain takeover check error for ${cleandomain}: ${e.message}`;
    }
}

async function discovercloudassets(domain) {
    const cleandomain = cleanin(domain);
    if (!cleandomain || !isdomain(cleandomain)) return 'invalid domain.';

    let assets = [];
    const commoncloudcnames = [
        '.cloudfront.net', '.s3-website-us-east-1.amazonaws.com', '.elb.amazonaws.com',
        '.azurewebsites.net', '.cloudapp.net', '.cdn.azureedge.net',
        '.appspot.com', '.cloudfunctions.net', '.run.app',
        '.cdn.cloudflare.net', '.herokudns.com', '.vercel.app'
    ];

    try {
        const cnamerecs = await new Promise((r, rej) => {
            require('dns').resolveCname(cleandomain, (err, addrs) => {
                if (err) rej(err);
                else r(addrs);
            });
        });

        if (cnamerecs && cnamerecs.length > 0) {
            for (const cname of cnamerecs) {
                for (const pattern of commoncloudcnames) {
                    if (cname.includes(pattern)) {
                        assets.push(`cname to ${cname} (possible ${pattern.split('.')[1].toUpperCase()} asset)`);
                    }
                }
            }
        }
    } catch (e) {}

    try {
        const txtrecs = await new Promise((r, rej) => {
            require('dns').resolveTxt(cleandomain, (err, addrs) => {
                if (err) rej(err);
                else r(addrs);
            });
        });

        if (txtrecs && txtrecs.length > 0) {
            for (const txt of txtrecs) {
                const txtstr = txt.join(' ').toLowerCase();
                if (txtstr.includes('aws') || txtstr.includes('azure') || txtstr.includes('google-site-verification')) {
                    assets.push(`suspicious txt record: ${txtstr}`);
                }
            }
        }
    } catch (e) {}

    if (assets.length === 0) {
        return `no obvious cloud assets for ${cleandomain}.`;
    }
    return `cloud assets for ${cleandomain}:\n${assets.join('\n')}`;
}

async function phonesearch(chatid, args, sendmsg) {
    if (!args[1]) return sendmsg(chatid, 'number required');
    const num = args[1];
    const data = await searchphone(num);
    await sendmsg(chatid, `phone info\n${data}`);
}

async function usernamesearch(chatid, args, sendmsg) {
    if (!args[1]) return sendmsg(chatid, 'username required');
    const user = args[1];
    const profiles = await searchuser(user);
    if (profiles.length > 0) {
        await sendmsg(chatid, `profiles for ${user}\n${profiles.join('\n')}`);
    } else {
        await sendmsg(chatid, `no profiles for ${user}`);
    }
}

async function googledorks(chatid, args, sendmsg) {
    if (!args[1]) return sendmsg(chatid, 'domain required');
    const domain = args[1];
    const links = googledorks(domain);
    await sendmsg(chatid, `google dorks for ${domain}\n${links.join('\n')}`);
}

async function exifdata(chatid, args, sendmsg) {
    if (!args[1]) return sendmsg(chatid, 'image url required');
    const url = args[1];
    const result = await getexif(url);
    await sendmsg(chatid, result);
}

async function linkcheck(chatid, args, sendmsg) {
    if (!args[1]) return sendmsg(chatid, 'url required');
    const url = args[1];
    const result = await chklink(url);
    await sendmsg(chatid, result);
}

async function subtakeover(chatid, args, sendmsg) {
    if (!args[1]) return sendmsg(chatid, 'domain required');
    const domain = args[1];
    const result = await chksubtakeover(domain);
    await sendmsg(chatid, result);
}

async function cloudassets(chatid, args, sendmsg) {
    if (!args[1]) return sendmsg(chatid, 'domain required');
    const domain = args[1];
    const result = await discovercloudassets(domain);
    await sendmsg(chatid, result);
}

module.exports = {
    phonesearch,
    usernamesearch,
    googledorks,
    exifdata,
    linkcheck,
    subtakeover,
    cloudassets
};