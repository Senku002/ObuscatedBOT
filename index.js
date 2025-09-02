require('dotenv').config();
const TelegramBot = require('node-telegram-bot-api');
const os = require('os');
const fs = require('fs');
const networkCommands = require('./commands/network');
const webSecurityCommands = require('./commands/web_security');
const osintCommands = require('./commands/osint');
const darkWebCryptoCommands = require('./commands/dark_web_crypto');
const utilityCommands = require('./commands/utils');
const adminCommands = require('./commands/admin');
const gameCommands = require('./commands/game');
const { sendmsg, isadmin, reqlimit, spamchk } = require('./commands/utils');

const token = process.env.TELEGRAM_TOKEN;
const bot = new TelegramBot(token, {
  polling: {
    interval: 1000,
    autoStart: false
  },
  request: {
    agentOptions: {
      keepAlive: true,
      family: 4
    }
  }
});

const cpulimit = 0.5;
const memlimit = 0.5;
const totalmem = os.totalmem();
let lastcpuchk = Date.now();

const admins = ['admin', 'admin2'];
const bannedusers = new Set();
const spamtracker = new Map();
const reqlimiter = new Map();

const quizq = fs.existsSync('questions.txt') ? fs.readFileSync('questions.txt', 'utf8').split('\n').map(line => {
  const [q, a] = line.split(':');
  return { q, a };
}).filter(e => e.q && e.a) : [];

let usedq = [];
let antispam = false;
let lastproc = 0;
let quizactive = false;
let currentq = null;
let answertime = 0;
let userpts = new Map();
let groups = {
  incepator: new Map(),
  avansat: new Map(),
  coder: new Map(),
  hacker: new Map()
};

function resmon() {
  const now = Date.now();
  if (now - lastcpuchk < 5000) return;
  lastcpuchk = now;
  const cpus = os.cpus();
  let totalidle = 0, totaltick = 0;
  cpus.forEach(cpu => {
    for (let type in cpu.times) {
      totaltick += cpu.times[type];
      if (type === 'idle') totalidle += cpu.times[type];
    }
  });
  const cpuuse = 1 - totalidle / totaltick;
  const usedmem = process.memoryUsage().heapUsed;
  const memuse = usedmem / totalmem;
  if (cpuuse > cpulimit || memuse > memlimit) {
    console.log(`res limit: CPU ${cpuuse * 100}% | Mem ${memuse * 100}%`);
    setTimeout(() => {}, 100);
  }
}

bot.on('message', async (msg) => {
  let chatid;
  try {
    chatid = msg.chat.id;
    const txt = msg.text;
    const user = msg.from.username;
    const userid = msg.from.id;
    if (bannedusers.has(userid)) return;
    if (!reqlimit(userid, reqlimiter)) return;
    const spamcount = spamchk(userid, spamtracker, antispam);
    if (spamcount > 5) {
      bannedusers.add(userid);
      await sendmsg(chatid, 'user banned for spam');
      return;
    }
    resmon();
    if (!txt || txt.length === 0) {
      if (quizactive && currentq && msg.text && msg.text.toLowerCase() === currentq.a.toLowerCase()) {
        let pts = userpts.get(user) || 0;
        pts++;
        userpts.set(user, pts);
        if (!groups.incepator.has(user) && !groups.avansat.has(user) &&
          !groups.coder.has(user) && !groups.hacker.has(user)) {
          groups.incepator.set(user, pts);
        }
        const { newgrp, medal } = gameCommands.updategrp(user, pts, groups);
        let message = `congrats ${user} +1 pt. total: ${pts} in ${newgrp}`;
        if (medal) message += `\nyou got: ${medal}`;
        await sendmsg(chatid, message);
        currentq = null;
        setTimeout(() => gameCommands.startquiz(chatid, quizactive, currentq, quizq, usedq, answertime, sendmsg, (q) => { currentq = q; }, (t) => { answertime = t; }, (a) => { quizactive = a; }), 600000);
      }
      return;
    }
    const args = txt.split(' ');
    let cmd = args[0].toLowerCase();
    if (cmd.includes('@')) return;
    switch (cmd) {
      case '/start':
        await sendmsg(chatid, `welcome to ObuscatedBOT

commands:
/whois - ip info
/ping - ping host
/portscan - scan port
/portrange - scan port range
/dns - dns name domain
/subdomain - find subdomains
/dirbrute - dir brute
/webscan - web vuln scan
/brute - login brute
/server - server detect
/email - find emails
/waf - waf detect
/sslcheck - ssl cert check
/headers - security headers
/cms - cms detect
/phone - phone info
/username - social profiles
/dorks - google dorks
/adminpanel - admin panels
/backup - backup files
/api - api endpoints
/wordpress - wp scan
/git - git exposure
/password - gen password
/wordlist - gen wordlist
/b64enc - b64 encode
/b64dec - b64 decode
/urlenc - url encode
/urldec - url decode
/hexenc - hex encode
/hexdec - hex decode
/hash - hash text
/sysinfo - system info
/youtube - youtube search
/google - google search
/crypto - crypto price
/clear - clear chat (just for admin)
/antispam - toggle antispam (admin)
/ban - ban user (admin)
/unban - unban user (admin)
/startgame - start quiz (admin)
/stopgame - stop quiz (admin)

/tortest - tor exit node check
/cryptogen - crypto address (demo)
/emailhdr - email headers
/hashbrute - hash brute
/webcfg - common web configs
/exifdata - exif metadata
/dnssectest - dnssec check
/ua - gen user-agent
/linkcheck - suspicious link analysis
/uuidgen - gen uuid
/cvesearch - cve info
/shodansearch - shodan search
/domainmon - domain monitor
/payloadgen - gen payloads
/udpscan - udp port scan
/whoislookup - whois lookup
/dnsrecon - advanced dns recon
/subtakeover - subdomain takeover check
/cloudassets - cloud asset discovery`);
        break;
      case '/help':
        await sendmsg(chatid, `ObuscatedBOT help

network:
/whois - ip location
/ping - check ping
/portscan - check open port
/portrange - scan multi ports
/dns - dns info
/udpscan - udp port scan

web security:
/webscan - vulns (sqli, xss, lfi etc)
/brute - common pass login
/server - target server info
/email - find emails on target
/waf - waf detect
/headers - security headers
/cms - cms detect
/adminpanel - admin panel
/backup - exposed backup files
/api - api endpoints
/wordpress - wp scan
/git - git exposure
/webcfg - common web configs
/payloadgen - gen payloads

osint:
/subdomain - find subdomains
/username - search social profile username
/phone - phone info
/dorks - google dorks
/exifdata - exif metadata
/linkcheck - suspicious link analysis
/whoislookup - whois lookup
/dnsrecon - advanced dns recon
/subtakeover - subdomain takeover check
/cloudassets - cloud asset discovery

dark web / crypto:
/tortest - tor exit node check
/cryptogen - crypto address (demo)
/emailhdr - email headers
/hashbrute - hash brute (demo)
/cvesearch - cve info
/shodansearch - shodan search
/domainmon - domain monitor

utils:
/password - gen strong pass
/wordlist - show wordlists
/b64enc/dec - b64 encode/decode
/urlenc/dec - url encode/decode
/hexenc/dec - hex encode/decode
/hash - gen hashes (md5, sha256 etc)
/sysinfo - system info
/youtube - youtube search
/google - google search
/crypto - crypto price
/uuidgen - gen uuid

admin: /clear, /antispam, /ban, /unban
game: /startgame, /stopgame`);
        break;
      case '/whois':
        await networkCommands.whoiscmd(chatid, args, sendmsg);
        break;
      case '/ping':
        await networkCommands.pingcmd(chatid, args, sendmsg);
        break;
      case '/portscan':
        await networkCommands.portscan(chatid, args, sendmsg);
        break;
      case '/portrange':
        await networkCommands.portrange(chatid, args, sendmsg);
        break;
      case '/dns':
        await networkCommands.dnscmd(chatid, args, sendmsg);
        break;
      case '/subdomain':
        await networkCommands.subdomaincmd(chatid, args, sendmsg);
        break;
      case '/dirbrute':
        await webSecurityCommands.dirbrute(chatid, args, sendmsg);
        break;
      case '/webscan':
        await webSecurityCommands.webscan(chatid, args, sendmsg);
        break;
      case '/brute':
        await webSecurityCommands.bruteforce(chatid, args, sendmsg);
        break;
      case '/server':
        await webSecurityCommands.serverdetect(chatid, args, sendmsg);
        break;
      case '/email':
        await webSecurityCommands.emailfind(chatid, args, sendmsg);
        break;
      case '/waf':
        await webSecurityCommands.wafdetect(chatid, args, sendmsg);
        break;
      case '/sslcheck':
        await webSecurityCommands.sslcheck(chatid, args, sendmsg);
        break;
      case '/headers':
        await webSecurityCommands.headerscheck(chatid, args, sendmsg);
        break;
      case '/cms':
        await webSecurityCommands.cmsdetect(chatid, args, sendmsg);
        break;
      case '/phone':
        await osintCommands.phonesearch(chatid, args, sendmsg);
        break;
      case '/username':
        await osintCommands.usernamesearch(chatid, args, sendmsg);
        break;
      case '/dorks':
        await osintCommands.googledorks(chatid, args, sendmsg);
        break;
      case '/adminpanel':
        await webSecurityCommands.adminpanel(chatid, args, sendmsg);
        break;
      case '/backup':
        await webSecurityCommands.backupfiles(chatid, args, sendmsg);
        break;
      case '/api':
        await webSecurityCommands.apiendpoints(chatid, args, sendmsg);
        break;
      case '/wordpress':
        await webSecurityCommands.wordpressscan(chatid, args, sendmsg);
        break;
      case '/git':
        await webSecurityCommands.gitexposure(chatid, args, sendmsg);
        break;
      case '/password':
        await utilityCommands.passgen(chatid, args, sendmsg);
        break;
      case '/wordlist':
        await utilityCommands.wordlistgen(chatid, args, sendmsg);
        break;
      case '/b64enc':
        await utilityCommands.b64enc(chatid, args, sendmsg);
        break;
      case '/b64dec':
        await utilityCommands.b64dec(chatid, args, sendmsg);
        break;
      case '/urlenc':
        await utilityCommands.urlenc(chatid, args, sendmsg);
        break;
      case '/urldec':
        await utilityCommands.urldec(chatid, args, sendmsg);
        break;
      case '/hexenc':
        await utilityCommands.hexenc(chatid, args, sendmsg);
        break;
      case '/hexdec':
        await utilityCommands.hexdec(chatid, args, sendmsg);
        break;
      case '/hash':
        await utilityCommands.hashgen(chatid, args, sendmsg);
        break;
      case '/sysinfo':
        await utilityCommands.sysinfo(chatid, sendmsg);
        break;
      case '/youtube':
        await utilityCommands.ytsearch(chatid, args, sendmsg);
        break;
      case '/google':
        await utilityCommands.googlesearch(chatid, args, sendmsg);
        break;
      case '/crypto':
        await utilityCommands.cryptoprice(chatid, args, sendmsg);
        break;
      case '/clear':
        if (!isadmin(user, admins)) {
          await sendmsg(chatid, 'admin only');
          return;
        }
        await adminCommands.clearchat(chatid, msg.message_id, bot, sendmsg);
        break;
      case '/antispam':
        if (!isadmin(user, admins)) {
          await sendmsg(chatid, 'admin only');
          return;
        }
        antispam = !antispam;
        await sendmsg(chatid, `antispam ${antispam ? 'on' : 'off'}`);
        break;
      case '/ban':
        if (!isadmin(user, admins)) {
          await sendmsg(chatid, 'admin only');
          return;
        }
        await adminCommands.banuser(chatid, args, bannedusers, sendmsg);
        break;
      case '/unban':
        if (!isadmin(user, admins)) {
          await sendmsg(chatid, 'admin only');
          return;
        }
        await adminCommands.unbanuser(chatid, args, bannedusers, sendmsg);
        break;
      case '/startgame':
        if (!isadmin(user, admins)) {
          await sendmsg(chatid, 'admin only');
          return;
        }
        if (quizq.length === 0) {
          await sendmsg(chatid, 'no questions');
          return;
        }
        quizactive = true;
        await sendmsg(chatid, 'quiz started. first question soon');
        setTimeout(() => gameCommands.startquiz(chatid, quizactive, currentq, quizq, usedq, answertime, sendmsg, (q) => { currentq = q; }, (t) => { answertime = t; }, (a) => { quizactive = a; }), 10000);
        break;
      case '/stopgame':
        if (!isadmin(user, admins)) {
          await sendmsg(chatid, 'admin only');
          return;
        }
        quizactive = false;
        currentq = null;
        await sendmsg(chatid, 'quiz stopped');
        break;
      case '/tortest':
        await darkWebCryptoCommands.tortest(chatid, args, sendmsg);
        break;
      case '/cryptogen':
        await darkWebCryptoCommands.cryptogen(chatid, args, sendmsg);
        break;
      case '/emailhdr':
        await darkWebCryptoCommands.emailhdr(chatid, args, sendmsg);
        break;
      case '/hashbrute':
        await darkWebCryptoCommands.hashbrute(chatid, args, sendmsg);
        break;
      case '/webcfg':
        await webSecurityCommands.webcfg(chatid, args, sendmsg);
        break;
      case '/exifdata':
        await osintCommands.exifdata(chatid, args, sendmsg);
        break;
      case '/dnssectest':
        await networkCommands.dnssectest(chatid, args, sendmsg);
        break;
      case '/ua':
        await utilityCommands.ua(chatid, sendmsg);
        break;
      case '/linkcheck':
        await osintCommands.linkcheck(chatid, args, sendmsg);
        break;
      case '/uuidgen':
        await utilityCommands.uuidgen(chatid, sendmsg);
        break;
      case '/cvesearch':
        await darkWebCryptoCommands.cvesearch(chatid, args, sendmsg);
        break;
      case '/shodansearch':
        await darkWebCryptoCommands.shodansearch(chatid, args, sendmsg);
        break;
      case '/domainmon':
        await darkWebCryptoCommands.domainmon(chatid, args, sendmsg);
        break;
      case '/payloadgen':
        await webSecurityCommands.payloadgen(chatid, args, sendmsg);
        break;
      case '/udpscan':
        await networkCommands.udpscan(chatid, args, sendmsg);
        break;
      case '/whoislookup':
        await networkCommands.whoislookup(chatid, args, sendmsg);
        break;
      case '/dnsrecon':
        await networkCommands.dnsrecon(chatid, args, sendmsg);
        break;
      case '/subtakeover':
        await osintCommands.subtakeover(chatid, args, sendmsg);
        break;
      case '/cloudassets':
        await osintCommands.cloudassets(chatid, args, sendmsg);
        break;
    }
  } catch (e) {
    console.log('msg proc err:', e.message);
    if (chatid) {
      await sendmsg(chatid, 'internal error. try again');
    }
  }
});

bot.on('polling_error', err => {
  console.log('polling err:', err.message);
  if (err.message.includes('429')) {
    setTimeout(() => bot.startPolling(), 10000);
  }
});

bot.startPolling();
console.log('bot started');
