const axios = require('axios');
const dns = require('dns');
const net = require('net');
const { Resolver } = require('dns');
const whois = require('whois-json');
const dgram = require('dgram');

const { cleanin, isip, isdomain } = require('./utils');

async function getipinfo(ip) {
    if (!isip(ip)) return null;
    try {
        const res = await axios.get(`http://ip-api.com/json/${ip}?fields=status,message,country,regionName,city,zip,lat,lon,timezone,isp,org,as,query`, {
            timeout: 10000
        });
        return res.data;
    } catch (e) {
        return null;
    }
}

async function pinghost(host) {
    if (!isip(host) && !isdomain(host)) return null;
    return new Promise(r => {
        const start = Date.now();
        const client = new net.Socket();
        client.setTimeout(5000);
        client.connect(80, host, () => {
            const time = Date.now() - start;
            client.destroy();
            r(time);
        });
        client.on('error', () => r(null));
        client.on('timeout', () => {
            client.destroy();
            r(null);
        });
    });
}

async function scanport(host, port) {
    if (!isip(host) && !isdomain(host)) return false;
    return new Promise(r => {
        const sock = new net.Socket();
        sock.setTimeout(3000);
        sock.connect(port, host, () => {
            sock.destroy();
            r(true);
        });
        sock.on('error', () => r(false));
        sock.on('timeout', () => {
            sock.destroy();
            r(false);
        });
    });
}

async function scanports(host, start, end) {
    if (!isip(host) && !isdomain(host)) return [];
    const openports = [];
    const prom = [];
    for (let port = start; port <= end; port++) {
        prom.push(new Promise(async r => {
            const open = await scanport(host, port);
            if (open) openports.push(port);
            r();
        }));
    }
    await Promise.all(prom);
    return openports;
}

async function getdns(domain) {
    if (!isdomain(domain)) return {};
    const recs = {};
    const types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME'];
    for (const type of types) {
        try {
            const res = await new Promise((r, rej) => {
                dns.resolve(domain, type, (err, addrs) => {
                    if (err) rej(err);
                    else r(addrs);
                });
            });
            recs[type] = res.map(e => typeof e === 'object' ? JSON.stringify(e) : e);
        } catch (e) {
            recs[type] = 'not found';
        }
    }
    return recs;
}

async function findsubs(domain) {
    if (!isdomain(domain)) return [];
    const subs = ['www', 'mail', 'ftp', 'admin', 'test', 'dev', 'api', 'blog', 'shop', 'forum', 'secure', 'vpn', 'staging'];
    const found = [];
    for (const sub of subs) {
        try {
            await new Promise((r, rej) => {
                dns.lookup(`${sub}.${domain}`, err => {
                    if (!err) found.push(`${sub}.${domain}`);
                    r();
                });
            });
        } catch (e) {}
    }
    return [...new Set(found)];
}

async function chkdnssec(domain) {
    const res = new Resolver();
    res.setServers(['8.8.8.8', '1.1.1.1']);

    try {
        const dnskeyrecs = await res.resolve(domain, 'DNSKEY');
        if (dnskeyrecs && dnskeyrecs.length > 0) {
            return `dnssec likely enabled for ${domain}. dnskey records found.`;
        }
        return `dnssec NOT enabled for ${domain}. no dnskey records found.`;
    } catch (error) {
        if (error.code === 'ENODATA' || error.code === 'ENOTFOUND') {
            return `dnssec NOT enabled for ${domain} (or domain not exist/no dnskey records).`;
        }
        return `dnssec check error for ${domain}: ${error.message}`;
    }
}

async function scanudp(host, port) {
    if (!isip(host) && !isdomain(host)) return false;
    return new Promise(r => {
        const sock = dgram.createSocket('udp4');
        sock.send('test', port, host, (err) => {
            if (err) {
                sock.close();
                return r(false);
            }
        });
        sock.on('message', () => {
            sock.close();
            r(true);
        });
        sock.on('error', () => {
            sock.close();
            r(false);
        });
        setTimeout(() => {
            sock.close();
            r(false);
        }, 3000);
    });
}

async function dowhoislookup(domain) {
    const cleandomain = cleanin(domain);
    if (!cleandomain || !isdomain(cleandomain)) return 'invalid domain.';

    try {
        const result = await whois(cleandomain);
        let res = `whois info for ${cleandomain}:\n`;
        for (const key in result) {
            if (typeof result[key] === 'string' && result[key].length < 200) {
                res += `${key}: ${result[key]}\n`;
            }
        }
        return res;
    } catch (e) {
        return `whois lookup error: ${e.message}`;
    }
}

async function dodnsrecon(domain) {
    const cleandomain = cleanin(domain);
    if (!cleandomain || !isdomain(cleandomain)) return 'invalid domain.';

    let result = `advanced dns recon for ${cleandomain}:\n`;
    const res = new Resolver();
    res.setServers(['8.8.8.8', '1.1.1.1']);

    try {
        const nsrecs = await res.resolve(cleandomain, 'NS');
        result += `name servers (ns):\n${nsrecs.join('\n')}\n\n`;
    } catch (e) {
        result += `name servers (ns): not found (${e.message})\n\n`;
    }

    try {
        const mxrecs = await res.resolve(cleandomain, 'MX');
        result += `mail servers (mx):\n${mxrecs.map(r => `${r.priority} ${r.exchange}`).join('\n')}\n\n`;
    } catch (e) {
        result += `mail servers (mx): not found (${e.message})\n\n`;
    }

    try {
        const txtrecs = await res.resolve(cleandomain, 'TXT');
        result += `txt records:\n${txtrecs.map(r => r.join(' ')).join('\n')}\n\n`;
    } catch (e) {
        result += `txt records: not found (${e.message})\n\n`;
    }

    return result;
}

async function whoiscmd(chatid, args, sendmsg) {
    if (!args[1]) return sendmsg(chatid, 'ip required');
    const ip = args[1];
    const data = await getipinfo(ip);
    if (data && data.status === 'success') {
        const res = `ip info ${data.query}
country: ${data.country}
region: ${data.regionName}
city: ${data.city}
zip: ${data.zip}
coords: ${data.lat}, ${data.lon}
timezone: ${data.timezone}
isp: ${data.isp}
org: ${data.org}
asn: ${data.as}`;
        await sendmsg(chatid, res);
    } else {
        await sendmsg(chatid, 'ip info error or invalid ip');
    }
}

async function pingcmd(chatid, args, sendmsg) {
    if (!args[1]) return sendmsg(chatid, 'host required');
    const host = args[1];
    const time = await pinghost(host);
    if (time !== null) {
        await sendmsg(chatid, `ping ${host}: ${time}ms`);
    } else {
        await sendmsg(chatid, `ping error ${host}`);
    }
}

async function portscan(chatid, args, sendmsg) {
    if (!args[2]) return sendmsg(chatid, 'host and port required');
    const host = args[1];
    const port = parseInt(args[2]);
    if (isNaN(port) || port < 1 || port > 65535) {
        await sendmsg(chatid, 'invalid port. use 1-65535');
        return;
    }
    const open = await scanport(host, port);
    await sendmsg(chatid, `port ${port} on ${host}: ${open ? 'OPEN' : 'CLOSED'}`);
}

async function portrange(chatid, args, sendmsg) {
    if (!args[3]) return sendmsg(chatid, 'host, start, end ports required');
    const host = args[1];
    const start = parseInt(args[2]);
    const end = parseInt(args[3]);
    if (isNaN(start) || isNaN(end) || start < 1 || end > 65535 || start > end) {
        await sendmsg(chatid, 'invalid port range');
        return;
    }
    if (end - start > 100) {
        await sendmsg(chatid, 'range too big. max 100 ports');
        return;
    }
    await sendmsg(chatid, `scanning ports ${start}-${end} on ${host}`);
    const openports = await scanports(host, start, end);
    if (openports.length > 0) {
        await sendmsg(chatid, `open ports on ${host}: ${openports.join(', ')}`);
    } else {
        await sendmsg(chatid, `no open ports on ${host} in range ${start}-${end}`);
    }
}

async function dnscmd(chatid, args, sendmsg) {
    if (!args[1]) return sendmsg(chatid, 'domain required');
    const domain = args[1];
    const recs = await getdns(domain);
    let res = `dns records for ${domain}\n`;
    for (const [type, rec] of Object.entries(recs)) {
        if (Array.isArray(rec)) {
            res += `${type}: ${rec.join(', ')}\n`;
        } else {
            res += `${type}: ${rec}\n`;
        }
    }
    await sendmsg(chatid, res);
}

async function subdomaincmd(chatid, args, sendmsg) {
    if (!args[1]) return sendmsg(chatid, 'domain required');
    const domain = args[1];
    const subs = await findsubs(domain);
    if (subs.length > 0) {
        await sendmsg(chatid, `subdomains for ${domain}\n${subs.join('\n')}`);
    } else {
        await sendmsg(chatid, `no subdomains for ${domain}`);
    }
}

async function dnssectest(chatid, args, sendmsg) {
    if (!args[1]) return sendmsg(chatid, 'domain required');
    const domain = args[1];
    const result = await chkdnssec(domain);
    await sendmsg(chatid, result);
}

async function udpscan(chatid, args, sendmsg) {
    if (!args[2]) return sendmsg(chatid, 'host and port required');
    const host = args[1];
    const port = parseInt(args[2]);
    if (isNaN(port) || port < 1 || port > 65535) {
        await sendmsg(chatid, 'invalid port. use 1-65535.');
        return;
    }
    const open = await scanudp(host, port);
    await sendmsg(chatid, `udp port ${port} on ${host}: ${open ? 'OPEN (possible)' : 'CLOSED/FILTERED'}`);
}

async function whoislookup(chatid, args, sendmsg) {
    if (!args[1]) return sendmsg(chatid, 'domain required');
    const domain = args[1];
    const result = await dowhoislookup(domain);
    await sendmsg(chatid, result);
}

async function dnsrecon(chatid, args, sendmsg) {
    if (!args[1]) return sendmsg(chatid, 'domain required');
    const domain = args[1];
    const result = await dodnsrecon(domain);
    await sendmsg(chatid, result);
}

module.exports = {
    whoiscmd,
    pingcmd,
    portscan,
    portrange,
    dnscmd,
    subdomaincmd,
    dnssectest,
    udpscan,
    whoislookup,
    dnsrecon
};