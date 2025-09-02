# obfuscatedbot - multi functions tg bot

hello this is telegram bot for osint and security testing i make for my self but maybe other people want use too

## what is this

i was tired to use many different tools for basic security work so i make one bot with all commands i use everyday not perfect but is working good

## commands list

### network commands
- ipinfo - get informations about ip address like location and provider
- ping - check if host is online and how fast respond
- portscan - scan one port to see if open
- portrange - scan many ports same time
- dnsenum - get dns records from domain  
- udpscan - scan udp ports but is more slow

### web security commands  
- webscan - scan website for vulnerabilities like sqli xss lfi and other
- bruteforce - try login with common passwords
- serverinfo - find what web server and technology use
- emailharvest - find email addresses from website
- wafcheck - detect if website have firewall
- sslcheck - check ssl certificate details
- headers - check security headers of website
- cmscheck - detect what cms use like wordpress drupal
- adminpanel - find admin login pages
- backups - look for backup files exposed
- apifind - discover api endpoints
- wpscan - scan wordpress sites
- gitcheck - check for exposed git repositories
- configs - find configuration files exposed
- payload - generate payloads for testing

### osint commands
- subdomains - find subdomains of domain
- phoneinfo - get information about phone number
- usersearch - search social media by username
- dorks - generate google search queries
- exif - extract metadata from images
- linkcheck - analyze suspicious urls
- whois - get domain registration info
- dnsrecon - deep dns reconnaissance 
- takeover - check subdomain takeover possibility
- cloudassets - find cloud resources

### darkweb crypto commands
- torcheck - check if ip is tor exit node
- cryptogen - generate cryptocurrency addresses
- emailheaders - analyze email headers
- hashcrack - crack hashes with wordlist
- cve - search vulnerabilities database
- shodan - search shodan need api key
- monitor - monitor domain changes

### utility commands
- passgen - generate random passwords
- wordlist - create wordlists for testing
- base64 - encode decode base64 strings
- urlencode - encode decode url strings  
- hex - encode decode hex strings
- hash - generate md5 sha1 sha256 hashes
- youtube - search videos on youtube
- google - search on google
- crypto - get cryptocurrency prices
- uuid - generate random uuids

### admin commands only for bot owners
- clear - delete messages in chat
- antispam - enable disable spam protection
- ban - ban user from bot
- unban - unban user  
- startgame - start some game
- stopgame - stop game

## how to install

### what you need first
- nodejs installed on computer
- npm package manager

### installation steps
1. download the code
```
git clone https://github.com/patchloop/ObfuscatedBOT.git
cd ObfuscatedBOT
```

2. install all packages
```
npm install node-telegram-bot-api axios cheerio uuid qs util dns net crypto fs yt-search bitcoinjs-lib ecpair tiny-secp256k1 ethers mailparser node-exiftool dist-exiftool whois-json google-libphonenumber
```

### setup bot
1. get telegram bot token
   - open telegram app
   - search @BotFather
   - send /newbot command
   - choose name for bot
   - botfather give you token

2. put token in bot
   - create .env file in main folder
   ```
   TELEGRAM_TOKEN=put_your_token_here
   ```
   or edit index.js file:
   ```javascript
   const token = process.env.TELEGRAM_TOKEN || 'put_your_token_here'
   ```

3. set admin users
   in index.js find this line:
   ```javascript
   const admins = ['admin1','admin2']
   ```
   change admin1 admin2 with your telegram username

### run the bot
open terminal and type:
```
node index.js
```

## notes
- some commands need api keys like shodan
- bot work better on linux server
- if command not work check if you have all packages installed
- for questions open issue on github

## disclaimer
this tool is for educational and legal security testing only
use only on systems you own or have permission to test
i not responsible for illegal use
