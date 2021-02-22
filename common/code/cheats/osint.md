# +

- https://www.shodan.io/
    - Find GWS (Google Web Server) servers: `"Server: gws" hostname:"google"`
    - Find Cisco devices on a particular subnet: `cisco net:"123.123.123.0/24"`
- https://github.com/nahamsec/Resources-for-Beginner-Bug-Bounty-Hunters/blob/master/assets/tools.md#osint-webpages

# reverse image search

- https://tineye.com/

### facial recognition

- https://pimeyes.com/en
    - Example: https://news.ycombinator.com/item?id=25580701

# asn, whois

```bash
# RIPE - RIR API database
whois -h whois.arin.net -v 1.2.3.4
# ASN, location, organization...
curl -s "https://ipinfo.io/$ip"
# :( Outdated
curl 'https://api.hackertarget.com/aslookup/?q=1.2.3.4'
# Query by number
curl 'https://stat.ripe.net/data/as-overview/data.json?resource=AS1234'
# Query by country
curl 'https://stat.ripe.net/data/country-asns/data.json?resource=de'
# Query all
curl 'https://stat.ripe.net/data/ris-asns/data.json?list_asns=true'
```

- https://bgpview.io/
- http://whoxy.com
- http://viewdns.info/
- https://domainbigdata.com/
- https://www.godaddy.com/whois

- https://web.archive.org/web/*/https://who.is/whois/thomascook.com
- || https://www.apnic.net/static/whowas-ui/

- https://securitytrails.com/blog/asn-lookup

# dns

./net.md#dns-zone-transfer

- https://host.io/
- https://securitytrails.com/domain/0x00sec.org/dns

```bash
# DNS Dumpster
curl -s "http://api.hackertarget.com/hostsearch/?q=$domain" | tee -a recon.out

# DNS Queries
curl -s "http://api.hackertarget.com/dnslookup/?q=$domain" | tee -a recon.out

# DNS records
dnsenum "$domain" | tee -a recon.out

# Domain name permutation
python ~/opt/dnstwist/dnstwist.py -c -r "$domain" | tee -a recon.out

# Uses search engines, key servers, IOT databases...
theharvester -d "$domain" -b all | tee -a recon.out
subfinder -silent -d "$domain" | dnsprobe -silent | tee -a recon.out
```

- https://delta.navisec.io/a-pentesters-guide-part-5-unmasking-wafs-and-finding-the-source/
- https://susam.in/blog/sinkholed/

# redirects

- YouTube => Invidious
- Twitter => Nitter
- Instagram => Bibliogram
- Google Maps => OSM

```javascript
javascript:void(window.open('https://web.archive.org/web/*/'+location.href.replace(/\/$/,%20'')));
```

# blacklists

- https://pulsedive.com/submit/
- https://www.abuseipdb.com/report

# company

- [List of Company Registers Around the World \| AML&\#x2d;CFT](https://aml-cft.net/library/company-registers/)
- [OpenCorporates \- The Open Database Of The Corporate World](http://opencorporates.com)

- state databases
    - [US Corporate Registry Directory](https://www.corpsearch.net/domestic.html)
    - [Business Search \- Business Entities \- Business Programs \| California Secretary of State](https://businesssearch.sos.ca.gov/)

# person

- http://truepeoplesearch.com

### business resources

- linkedin
- [Find Other Websites Owned By The Same Person](http://analyzeid.com/)

### social networks

- [WhatsMyName Web](https://whatsmyname.app/)
- [maltego-teeth](https://tools.kali.org/information-gathering/maltego-teeth)
- [GitHub \- qeeqbox/social\-analyzer: API, CLI &amp; Web App for analyzing &amp; finding a person&\#39;s profile across 350\+ social media websites \(Detections are updated regularly\)](https://github.com/qeeqbox/social-analyzer)
- [GitHub \- sherlock\-project/sherlock: 🔎 Hunt down social media accounts by username across social networks](https://github.com/sherlock-project/sherlock)
- [TweetBeaver \- Home of Really Useful Twitter Tools](http://tweetbeaver.com)

# ssl

- [crt\.sh | Certificate Search](https://crt.sh/)
- http://certdb.com/

# subdomains

- https://findsubdomains.com/
- https://pentest-tools.com/information-gathering/find-subdomains-of-domain
- https://github.com/tomnomnom/waybackurls

# google search dorks

```
inurl:MyOrg.com 'login: *' 'password= *' filetype:xls
site:www.MyOrg.com inurl:administrator_login.asp
https://www.google.com/search?q=intitle:%22index%20of%22

site:http://codepad.co "company"
site:http://scribd.com "company"
site:http://npmjs.com "company"
site:http://npm.runkit.com "company"
site:http://libraries.io "company"
site:http://ycombinator.com "company"
site:http://coggle.it "company"
site:http://papaly.com "company"
site:http://google.com "company"
site:http://trello.com "company"
site:http://prezi.com "company"
site:http://jsdelivr.net "company"
site:http://codepen.io "company"
site:http://codeshare.io "company"
site:http://sharecode.io "company"
site:http://pastebin.com "company"
site:http://repl.it "company"
site:http://productforums.google.com "company"
site:http://gitter.im "company"
site:http://bitbucket.org "company"
site:*.atlassian.net "company"
http://atlassian.net "company"
inurl:gitlab "company"
```

# blog

- https://www.hatena.ne.jp/o/search/top?q=
- https://search.daum.net/search?w=blog&f=section&SA=tistory&lpp=10&nil_profile=vsearch&nil_src=tistory&q=

# email

- [Trumail | Free Email Verification API](https://trumail.io/)

```
telnet mail.abccorp.com 25
HELO example.com
MAIL FROM: testing@example.com
RCPT TO: your_email@somedomain.com
RCPT TO: another_email@somedomain.com
```

```bash
curl emailrep.io/john.smith@gmail.com
```

# exif data

- http://exif.regex.info/exif.cgi

# geo location

- https://extreme-ip-lookup.com/
- https://censys.io/ipv4?q=
- https://shodan.io/search?query=foo.com

```bash
# Ours
curl -4 https://ipinfo.io | jq -r '.ip'
# Theirs
curl ipinfo.io/1.2.3.4
greynoise 1.2.3.4
shodan host 1.2.3.4
```

# software and technology stack lookup

- https://builtwith.com/
- https://www.wappalyzer.com/
- https://stackshare.io/

```bash
# https://github.com/urbanadventurer/WhatWeb
./whatweb "$domain"
```

# source code

- https://publicwww.com/
- https://nerdydata.com/
- https://searchcode.com/?q=
- https://grep.app/

### github

- https://www.gitlogs.com/
- http://gitmostwanted.com/
- http://www.gharchive.org/
- http://10degres.net/github-tools-collection/
- https://codeload.github.com/foo/bar/zip/master

- https://docs.github.com/en/github/searching-for-information-on-github/searching-for-repositories#search-by-repository-name-description-or-contents-of-the-readme-file
    - https://github.com/search?q=user%3Afoo+fork%3Atrue&type=Repositories
    - https://github.com/search?q=filename%3Aconf.py+markdown&type=code
    - https://api.github.com/repos/AdoptOpenJDK/openjdk11-binaries/tags?per_page=100&page=2

# web history

- https://web.archive.org
    - e.g.
    - https://web.archive.org/web/*/https://github.com/HMBSbige/JetBrains-License-Server/*
        - https://hub.docker.com/r/hmbsbige/jetbrains-license-server/dockerfile
    - https://web.archive.org/web/20200810173036if_/https://github.com/jaffarahmed/CREST-Exam-Prep
    - https://web.archive.org/web/*/https://raw.githubusercontent.com/jaffarahmed/CREST-Exam-Prep/*
        - https://raw.githubusercontent.com/jaffarahmed/CREST-Exam-Prep/master/Breakout%201%20%2B%20UNIX1.pdf
- https://archive.is
- hybrid analysis
- google/yandex cache
    - http://webcache.googleusercontent.com/search?q=cache:foo
- wget -r -k -np
- https://github.com/ArchiveTeam/grab-site
- https://github.com/pirate/ArchiveBox/wiki/Configuration
    - CHROME_USER_DATA_DIR
- https://linkchecker.github.io/linkchecker/
- https://www.npmjs.com/package/broken-link-checker-local

- https://delta.navisec.io/author/navisec/
- https://inteltechniques.com/JE/OSINT_Packet_2019.pdf
- https://github.com/jivoi/awesome-osint
- https://github.com/lockfale/osint-framework
- https://github.com/sinwindie/OSINT
- https://osint.link/
- https://twitter.com/OSINTtechniques
- https://0xpatrik.com/osint-domains/
- https://medium.com/@Peter_UXer/osint-how-to-find-information-on-anyone-5029a3c7fd56

# phone contacts

- https://www.bellingcat.com/resources/how-tos/2019/04/08/using-phone-contact-book-apps-for-digital-research/

# cross-reference

- https://aleph.occrp.org/

# +

[DEF CON 15 \- Moore and Valsmith \- Tactical Exploitation \- YouTube](https://www.youtube.com/watch?v=_WebzmDgJ5Q)
smtp bounce discloses ip
application in-memory credentials reused
ip id scanning [sequence analysis] - if large delta between id increments, large count of packets sent (e.g. backups)
    16-bit value that is unique for every datagram for a given source address, destination address, and protocol, such that it does not repeat within the maximum datagram lifetime (MDL)
    https://www.cellstream.com/reference-reading/tipsandtricks/314-the-purpose-of-the-ip-id-field-demystified
    https://tools.ietf.org/html/rfc6864
null-byte in hostname discloses index
authentication relays between protocols (e.g. ntlm to smtp, img src with unc path to trigger smb connection and mitm smb negotiation)
