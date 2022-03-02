# +

- https://github.com/nahamsec/Resources-for-Beginner-Bug-Bounty-Hunters/blob/master/assets/tools.md#osint-webpages

# internet devices, iot

- https://www.shodan.io/
    - Find GWS (Google Web Server) servers: `"Server: gws" hostname:"google"`
    - Find Cisco devices on a particular subnet: `cisco net:"123.123.123.0/24"`
- https://censys.io/
    - Find Certificate Authorities which issue valid TLS\SSL certificates to IP addresses: `443.https.tls.validation.browser_trusted: true and 443.https.tls.certificate.parsed.extensions.subject_alt_name.ip_addresses: [0.0.0.0 TO 255.255.255.255]`
        - https://nbk.sh/tools#censys
- https://spyse.com/
    - Find domains with same A records
- https://www.zoomeye.org/

# reverse image search

- https://tineye.com/
- https://yandex.ru/images/

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

- reverse whois lookups
    - http://whoxy.com
    - https://bgpview.io/
    - http://viewdns.info/
    - https://domainbigdata.com/
    - https://www.godaddy.com/whois
    - https://web.archive.org/web/*/https://who.is/whois/thomascook.com
    - || https://www.apnic.net/static/whowas-ui/
- asn lookups
    - https://securitytrails.com/blog/asn-lookup
    - https://hackertarget.com/as-ip-lookup/
    - https://bgp.he.net/
- reverse ns lookups
    - https://dnslytics.com/reverse-ns
- subdomains
    - https://opendata.rapid7.com/sonar.fdns_v2/
    - https://crt.sh/?q=%25.bishopfox.com
- registrants
    - https://www.riskiq.com/products/passivetotal/
    - e.g. http://ropgadget.com/posts/embracing_failure.html
- https://www.sshell.co/attack-surface-basics/

# dns

./net.md#dns-zone-transfer

- https://host.io/
- https://securitytrails.com/domain/0x00sec.org/dns
- https://www.eurodns.com/domain-name-search
- wordlists
    - https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS

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

### twitter

- [TweetBeaver \- Home of Really Useful Twitter Tools](http://tweetbeaver.com)
- [GitHub \- twintproject/twint: An advanced Twitter scraping &amp; OSINT tool written in Python that doesn&\#39;t use Twitter&\#39;s API, allowing you to scrape a user&\#39;s followers, following, Tweets and more while evading most API limitations\.](https://github.com/twintproject/twint)

# ssl

- [crt\.sh | Certificate Search](https://crt.sh/)
- http://certdb.com/

# subdomains

- https://github.com/aboul3la/Sublist3r
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

# cloud storage

- https://clients6.google.com/drive/v2beta/files/%7Bdoc_id%7D?fields=alternateLink%2CcopyRequiresWriterPermission%2CcreatedDate%2Cdescription%2CdriveId%2CfileSize%2CiconLink%2Cid%2Clabels(starred%2C%20trashed)%2ClastViewedByMeDate%2CmodifiedDate%2Cshared%2CteamDriveId%2CuserPermission(id%2Cname%2CemailAddress%2Cdomain%2Crole%2CadditionalRoles%2CphotoLink%2Ctype%2CwithLink)%2Cpermissions(id%2Cname%2CemailAddress%2Cdomain%2Crole%2CadditionalRoles%2CphotoLink%2Ctype%2CwithLink)%2Cparents(id)%2Ccapabilities(canMoveItemWithinDrive%2CcanMoveItemOutOfDrive%2CcanMoveItemOutOfTeamDrive%2CcanAddChildren%2CcanEdit%2CcanDownload%2CcanComment%2CcanMoveChildrenWithinDrive%2CcanRename%2CcanRemoveChildren%2CcanMoveItemIntoTeamDrive)%2Ckind&supportsTeamDrives=true&enforceSingleParent=true&key=AIzaSyC1eQ1xj69IdTMeii5r7brs3R90eck-m7k

# email

- [Trumail | Free Email Verification API](https://trumail.io/)
- [GitHub \- megadose/holehe: holehe allows you to check if the mail is used on different sites like twitter, instagram and will retrieve information on sites with the forgotten password function\.](https://github.com/megadose/holehe)

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

# webcam

- https://www.shodan.io/explore/tag/webcam

# hardware

- [3633808 program source codes/documents \- pudn\.com](http://en.pudn.com/)
- https://www.mikrocontroller.net/

# software and technology stack lookup

- https://builtwith.com/
- https://www.wappalyzer.com/
- https://stackshare.io/

```bash
# https://github.com/urbanadventurer/WhatWeb
./whatweb -a 3 "$url"
# https://github.com/ShielderSec/webtech
./webtech -u "$url"
```

# source code

- repositories
    - https://grep.app/
        - :) literal match (e.g. `<path:filename>`)
    - https://searchcode.com/?q=
        - :) literal match, but not visible in results
    - https://archive.softwareheritage.org/
- general sites
    - https://nerdydata.com/
    - https://publicwww.com/
        - :( processed match

### git

- regex, signatures
    - [GitHub \- eth0izzle/shhgit: Ah shhgit! Find secrets in your code\. Secrets detection for your GitHub, GitLab and Bitbucket repositories: www\.shhgit\.com](https://github.com/eth0izzle/shhgit/)
    - https://github.com/databricks/security-bucket-brigade/blob/3f25fe0908a3969b325542906bae5290beca6d2f/Tools/s3-secrets-scanner/rules.json
- entropy
    - [GitHub \- dxa4481/truffleHog: Searches through git repositories for high entropy strings and secrets, digging deep into commit history](https://github.com/dxa4481/truffleHog)
- json, yaml
    - [GitHub \- auth0/repo\-supervisor: Scan your code for security misconfiguration, search for passwords and secrets\.](https://github.com/auth0/repo-supervisor)

### github

- https://www.gitlogs.com/
- http://gitmostwanted.com/
- http://www.gharchive.org/
- http://10degres.net/github-tools-collection/
- https://codeload.github.com/foo/bar/zip/master
- https://connectionrequired.com/gitspective/

- https://docs.github.com/en/github/searching-for-information-on-github/searching-for-repositories#search-by-repository-name-description-or-contents-of-the-readme-file
    - https://github.com/search?q=user%3Afoo+fork%3Atrue&type=Repositories
    - https://github.com/search?q=filename%3Aconf.py+markdown&type=code
    - https://api.github.com/repos/AdoptOpenJDK/openjdk11-binaries/tags?per_page=100&page=2
    - https://github.com/github/linguist/commits/master?since=2018-05-31&until=2018-07-01
    - https://github.com/github/linguist/commits?branch=master&since=2018-05-31&until=2018-07-01

### gitlab

- https://gitlab.com/search?utf8=%E2%9C%93&search=&group_id=&project_id=&snippets=false&repository_ref=&nav_source=navbar

# web history

- https://web.archive.org
    - e.g.
    - https://web.archive.org/web/*/https://github.com/HMBSbige/JetBrains-License-Server/*
        - https://hub.docker.com/r/hmbsbige/jetbrains-license-server/dockerfile
    - https://web.archive.org/web/20200810173036if_/https://github.com/jaffarahmed/CREST-Exam-Prep
    - https://web.archive.org/web/*/https://raw.githubusercontent.com/jaffarahmed/CREST-Exam-Prep/*
        - https://raw.githubusercontent.com/jaffarahmed/CREST-Exam-Prep/master/Breakout%201%20%2B%20UNIX1.pdf
- https://archive.is
- https://outline.com
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
