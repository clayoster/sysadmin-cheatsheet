# Contents
- SSL/TLS
  - [SSL Testing](#SSL-Testing)
  - [Validating Certificate Files](#Validating-Certificate-Files)
  - [Generate a private key](#Generate-a-private-key)
  - [Generate a CSR](#Generate-a-CSR)
  - [Request Certificate from an Active Directory CA](#Request-Certificate-from-an-Active-Directory-CA)
  - [How to create a chained cert file](#How-to-create-a-chained-cert-file)
  - [Create PFX/PKCS12 file from PEM cert and key](#Create-PFXPKCS12-file-from-PEM-cert-and-key)
  - [Extract Certificate from PFX/PKCS12 file](#Extract-Certificate-from-PFXPKCS12-file)
  - [Extract Key from PFX/PKCS12 file](#Extract-Key-from-PFXPKCS12-file)
  - [Testing Public-Facing Web Servers](#Testing-Public-Facing-Web-Servers)
  - [HTTPS Testing and Hardening Tools](#HTTPS-Testing-and-Hardening-Tools)
- Storage
  - [Resizing Virtual Disks](#Resizing-virtual-disks)
  - [Finding Disk Usage](#Finding-Disk-Usage)
  - [Securely wiping a disk with Shred](#Securely-wiping-a-disk-with-Shred)
- DNS
  - [Query for Active Directory Domain Controller SRV records](#Query-for-Active-Directory-Domain-Controller-SRV-records)
  - [Clearing DNS records from Active Directory cache](#Clearing-DNS-records-from-Active-Directory-cache)
- Git
  - [Gitlab - Generate list of active users and email addresses from Gitlab API](#Generate-list-of-active-users-and-email-addresses-from-Gitlab-API)
  - [Gitlab - Purging data from Git repositories](#Purging-data-from-Git-repositories)
- SaltStack
  - [Useful Commands](#Useful-Commands)
- MySQL
  - [MySQL Common Commands](#MySQL-Common-Commands)
  - [Extracting a table from a mysqldump file](#Extracting-a-table-from-a-mysqldump-file)
- Networking
  - [Managing TCP Sessions](#Managing-TCP-Sessions)
  - [Clearing ARP cache](#Clearing-ARP-cache)
  - [Gratuitous ARP](#Gratuitous-ARP)
  - [View Network Interface Details (Linux)](#View-Network-Interface-Details-Linux)
- [VMware PowerCLI](#VMware-PowerCLI)
- [Linux - Useful Commands](#Linux---Useful-Commands)
  - [Debian](#Debian)
  - [RHEL](#RHEL)
- [WSL - Windows Subsystem for Linux](#WSL---Windows-Subsystem-for-Linux)
  - [Disable Terminal Beep](#Disable-Terminal-Beep)

---

# SSL/TLS

## SSL Testing

This command will display the TLS/SSL protocols that the web server supports:

`nmap --script ssl-enum-ciphers -p 443 server.example.com`
        
                Starting Nmap 7.40 ( https://nmap.org ) at 2020-11-02 19:53 CST
                Nmap scan report for server.example.com (192.168.50.50)
                Host is up (0.0034s latency).
                PORT    STATE SERVICE
                443/tcp open  https
                | ssl-enum-ciphers:
                |   TLSv1.2:
                |     ciphers:
                |       TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (secp256r1) - A
                |       TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 (secp256r1) - A
                |       TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (secp256r1) - A
                |       TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 (dh 2048) - A
                |       TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 (dh 2048) - A
                |       TLS_DHE_RSA_WITH_AES_256_CBC_SHA (dh 2048) - A
                |     compressors:
                |       NULL
                |     cipher preference: server
                |     warnings:
                |       Key exchange (dh 2048) of lower strength than certificate key
                |       Key exchange (secp256r1) of lower strength than certificate key
                |_  least strength: A
                
                Nmap done: 1 IP address (1 host up) scanned in 0.78 seconds

## Validating Certificate Files

Test connecting using TLSv1.2 and TLSv1.3

        curl -vI --tlsv1.2 https://server.example.com
        curl -vI --tlsv1.3 https://server.example.com

From https://www.sslshopper.com/article-most-common-openssl-commands.html

        Check a Certificate Signing Request (CSR)
                openssl req -text -noout -verify -in CSR.csr
        Check a private key
                openssl rsa -in privateKey.key -check
        Check a certificate
                openssl x509 -in certificate.crt -text -noout
        Check a PKCS#12 file (.pfx or .p12)
                openssl pkcs12 -info -in keyStore.p12
        
If you use the 'openssl' tool, this is one way to get extract the CA cert for a particular server. This will show the certificate and also evaluate the certificate to show it's details. (using webserver.example.com as an example):

        openssl s_client -connect webserver.example.com:443 -servername webserver.example.com </dev/null | openssl x509 -text

The certificate will have "BEGIN CERTIFICATE" and "END CERTIFICATE" markers, and it's details are above the certificate.

If you want to trust the certificate, you can add it to your CA certificate store or use it stand-alone as described. Just remember that the security is no better than the way you obtained the certificate.

-------------------------------------------------------------------------------------------------------------------------------------------
#### Verifying that certificate / private key / certificate signing request all match
(Info taken from https://kb.wisc.edu/page.php?id=4064)

Make sure the output of these 3 commands is the same. If so, then the Certificate / private key / csr match:

        openssl x509 -noout -modulus -in server.crt | openssl md5
        openssl rsa -noout -modulus -in server.key | openssl md5
        openssl req -noout -modulus -in server.csr | openssl md5

#### Info that expands upon the above:
The private key contains a series of numbers. Two of those numbers form the "public key", the others are part of your "private key". The "public key" bits are also embedded in your Certificate (we get them from your CSR). To check that the public key in your cert matches the public portion of your private key, you need to view the cert and the key and compare the numbers. To view the Certificate and the key run the commands:

        openssl x509 -noout -text -in server.crt
        openssl rsa -noout -text -in server.key
        
The 'modulus' and the 'public exponent' portions in the key and the Certificate must match. But since the public exponent is usually 65537 and it's bothering comparing long modulus you can use the following approach:

        openssl x509 -noout -modulus -in server.crt | openssl md5
        openssl rsa -noout -modulus -in server.key | openssl md5

### Generate a private key

        openssl genrsa -out SERVER.key 4096

### Generate a CSR

#### Generating a CSR with a SubjectAlternativeName included in a single line command (This requires that the /etc/ssl/openssl.cnf file exists - Tested on Debian):
        
        openssl req -new -sha256 -key SERVER.key -subj "/C=US/ST=State Name/localityName=City Name/O=Example Inc/emailAddress=youremail@example.com/CN=SERVER.example.com" -reqexts SAN -config <(cat /etc/ssl/openssl.cnf <(printf "[SAN]\nsubjectAltName=DNS:SERVER.example.com,DNS:www.SERVER.example.com,IP:0.0.0.0")) -out SERVER.csr
        
#### Links with related info:
https://bugs.chromium.org/p/chromium/issues/detail?id=700595&desc=2
https://bugs.chromium.org/p/chromium/issues/detail?id=308330
https://security.stackexchange.com/questions/74345/provide-subjectaltname-to-openssl-directly-on-command-line
https://alexanderzeitler.com/articles/Fixing-Chrome-missing_subjectAltName-selfsigned-cert-openssl/

#### Generate a CSR without specifying the SubjectAlternativeName attribute (Fine when submitting a request to a public CA)

`openssl req -new -sha256 -key SERVER.key -out SERVER.csr`

        Country Name (2 letter code) [AU]:US
        State or Province Name (full name) [Some-State]:State Name
        Locality Name (eg, city) []:City name
        Organization Name (eg, company) [Internet Widgits Pty Ltd]:Example Inc
        Organizational Unit Name (eg, section) []:IT Department

### Request Certificate from an Active Directory CA

Active Directory CA (Must use IE/Edge Browser):
https://subordinate-ca.example.com/certsrv

1. Request a Certificate
2. Advanced certificate request
3. "Submit a certificate request by using a base-64-encoded CMC or PKCS #10 file, or submit a renewal request by using a base-64-encoded PKCS #7 file. "
4. Paste CSR and choose the appropriate web server certificate template
    - Additionally….if a SAN attribute is needed and not included in the CSR
Under the "Additional Attributes" section of the certificate request form, you can specify the SAN attributes manually in this format (https://docs.microsoft.com/en-US/troubleshoot/windows-server/windows-security/add-san-to-secure-ldap-certificate)
        - san:dns=server1.example.com&dns=server2.example.com&ipaddress=0.0.0.0
5. Make sure to download the Base64 encoded version. Save as <file>.crt

### How to create a chained cert file
*(order is top down)*
- Server cert (server.example.com)
- Intermediate Cert
- Root CA Cert
  - Not necessary…in fact some applications determine it is improper to include the root CA cert in the chain.

Example:
- server.example.com (Server Certificate)
- OV_NetworkSolutionsOVServerCA2.crt (Intermediate certificate)

### Create PFX/PKCS12 file from PEM cert and key

*The .pfx and .p12 file extensions are used interchangeably*
	
Windows Servers tend to want the cert/key files in a pfx/pkcs12 format. Use these commands to create a pfx/pkcs12 file from PEM format key/cert files.

Create PFX/PKCS12 with friendlyname (-name):

        openssl pkcs12 -export -out filename.p12 -inkey key-filename.key -in cert-filename.crt -name "friendlyname text" 

Create PFX/PKCS12 file with friendlyname (-name) and include cert chain file (-certfile):

        openssl pkcs12 -export -out filename.p12 -inkey key-filename.key -in cert-filename.crt -certfile cacert-filename.crt -name "friendlyname text" 

### Extract Certificate from PFX/PKCS12 file:

        openssl pkcs12 -in filename.p12 -nokeys -out cert-filename.crt

### Extract Key from PFX/PKCS12 file:

        openssl pkcs12 -in filename.p12 -nocerts -nodes -out key-filename.key 

### Testing Public-Facing Web Servers
- Use https://ssllabs.com to test TLS configuration

### HTTPS Testing and Hardening Tools
- https://cipherlist.eu/
- https://sslmonitor.eu/
- https://github.com/sigio/sslmonitor/tree/master
- https://github.com/jumanjihouse/docker-testssl

# Storage

## Finding Disk Usage

#### TUI Utility similar to WinDirStat on Windows

        ncdu

#### Get summary of disk usage of top level directories under / while avoiding paths that will just give undesirable output

        du -hs --exclude=/dev --exclude=/proc --exclude=/run --exclude=/sys /*

#### Check home directories to see what large files were created in the past day:

        find /home -size +100M -mtime -1 -exec du -hs {} \;

#### Disk is filling up, but running 'du -hs' on the directory doesn't show what is using the disk space.
In one case I found that rsyslogd was holding files open that were supposed to be deleted and were filling up the /var partition. To resolve the issue, I just had to restart rsyslog so it would let go of the file handles and allow them to be deleted. I used the following command to find that out:

        lsof | grep "/var" | grep deleted
        
#### If files cannot be written and df -h shows free space, check inode utilization

    df -i

## Resizing Virtual Disks

This command will poke at the SCSI controllers to look for changes. Helpful for detecting resized virtual disks without rebooting the VM.

        for i in /sys/class/scsi_device/*/device/rescan; do echo '- - -' >"$i"; done

## Securely wiping a disk with Shred

The shred command can be used to securely wipe a disk. This command should be available on most systems. This command will make 3 passes of writing random data to the device, then a single pass of writing 0's to the device to hide the fact that it has been wiped.

        shred -vfz /dev/(device name without partition number)

# DNS

## Query for Active Directory Domain Controller SRV records
Example using dig:

`dig srv _ldap._tcp.dc._msdcs.example.com`

        user@workstation:~$ dig +noall +answer srv _ldap._tcp.dc._msdcs.example.com
        _ldap._tcp.dc._msdcs.example.com. 536   IN SRV  0 100 389 dc1.example.com.
        _ldap._tcp.dc._msdcs.example.com. 536   IN SRV  0 100 389 dc2.example.com.

## Clearing DNS records from Active Directory cache

This is useful for DNS environments where Active Directory DNS is configured to perform lookups to another DNS system that is authoritative for internal DNS records. This will describe clearing the cache for individual records rather than the entire DNS cache

#### Run from an AD DNS Server

1. Log into the AD DNS server that you want to clear the cached record from
2. Run the following commands in Powershell depending on the type of record you are working with
    - Repeat for each AD DNS server that holds the cached record

        ### A Record
        Query for the record to see if it exists:

                Get-DnsServerResourceRecord -ZoneName ..cache -RRType A -Name server.example.com
        Remove the record:

                Remove-DnsServerResourceRecord -ZoneName ..cache -RRType A -Name server.example.com

        ### CNAME Record
        Query for the record to see if it exists:

                Get-DnsServerResourceRecord -ZoneName ..cache -RRType CNAME -Name server-cname.example.com
        Remove the record:

                Remove-DnsServerResourceRecord -ZoneName ..cache -RRType CNAME -Name server-cname.example.com

#### Run Remotely from a Workstation (Windows 8 or above REQUIRED)
Alternatively, these commands can be run from a regular workstation as long as Powershell is launched with a user account that has permission to modify the records. The following switch must be appended to the commands, and run once for each AD DNS server (dc1.example.com, dc2.example.com)

        -ComputerName dc1.example.com
        
Remote Server Administration Tools may need to be installed so that the required module is available to Powershell on your workstation.
        https://www.microsoft.com/en-us/download/details.aspx?id=45520

You can see if you have the necessary module by running this command in Powershell.

        Get-Module -ListAvailable DNSServer

Info gathered from:
- https://technet.microsoft.com/en-us/itpro/powershell/windows/dnsserver/get-dnsserverresourcerecord
- https://docs.microsoft.com/en-us/powershell/module/dnsserver/Remove-DnsServerResourceRecord

# Git

## Gitlab Specific

### Generate list of active users and email addresses from Gitlab API
I used this API query once in a while to grab the e-mail addresses of all active users on a Gitlab instance.

        curl -L --header "PRIVATE-TOKEN: <REPLACE WITH VALID TOKEN>" "https://gitlab.example.com/api/v4/users?active=true&per_page=500" | jq -r '.[] | .email' | sort
        
Documentation:
https://docs.gitlab.com/ee/api/users.html

## Purging data from Git repositories

If large binary files or executables have been stored in a git repository and you would like to clean them, this is a good tutorial from Gitlab is helpful:\
https://docs.gitlab.com/14.5/ee/user/project/repository/reducing_the_repo_size_using_git.html

(This requires the git-filter-repo package which is currently only available in the bullseye-backports repo in Debian)

This is the actual command I used to remove the large files from the repo (in step 6 of the Gitlab doc)

        git filter-repo --invert-paths --path path/to/folder --path path/to/file1 --path path/to/file2
        
After running the "git filter-repo" command, there is a file in the project directory under "filiter-repo/commit-map". This file needs to be preserved and uploaded to the Gitlab server during the "Repository cleanup" section at the bottom of the document. Without this, the Gitlab server won't actually reduce the size of the repo.

After running through this process, I was able to drop the repo size from 700MB to 5MB.

**NOTE:** This process can also be used to delete files containing sensitive information from repositories, but it *MAY* not completely remove it.

# SaltStack

### Useful Commands

Watch the Salt Event Bus:

        salt-run state.event pretty=True

Refresh fileserver immediately:

        salt-run fileserver.update
        
View directory list for an environment:

        salt-run fileserver.dir_list saltenv=test

View file list for an environment:

        salt-run fileserver.file_list saltenv=test
        
Troubleshoot a highstate run:

        salt-call -l debug state.apply
        
Look-up job id:

        salt-run jobs.lookup_jid <job id number>

Show currently running jobs:

        salt-run jobs.active

# MySQL

## MySQL Common Commands

Creating a database and assigning a user all privileges:

        CREATE DATABASE exampledb_dev;
        CREATE USER 'exampleuser'@'%' IDENTIFIED BY '$password';        # % means the user can log in from any location
        GRANT ALL PRIVILEGES ON exampledb_dev.* TO 'exampleuser'@'%';
        FLUSH PRIVILEGES;

Checking grants:

        show grants for 'exampledb'@'%';
        FLUSH PRIVILEGES;

Revoke a single privilege from a single database (Database name must be specified):
(note the use of backticks around the database name)

        REVOKE CREATE VIEW on `exampledb\_dev`.* FROM 'exampledb_dev'@'%';

Changing host for a user:

        UPDATE mysql.user SET host = '%' WHERE user = 'exampleuser';

Show all users:

        select user,host from mysql.user;

Drop a database and user:

        DROP DATABASE exampledb_dev;
        DROP USER 'exampleuser'@'%';

Show variables for innodb engine;

        SHOW VARIABLES LIKE 'innodb_file_format%';

Set default character set and collation of a database:

        ALTER DATABASE dbname DEFAULT CHARACTER SET utf8 COLLATE utf8_general_ci;

Look at views that exist on all databases:

        select * FROM information_schema.views;

Remove a single view from a database:

        drop view exampledb_dev.exampleview;

Determine the amount of disk space being used by each database on a server:

        SELECT table_schema AS "Database", SUM(data_length + index_length) / 1024 / 1024 AS "Size (MB)" FROM information_schema.TABLES GROUP BY table_schema;

Show all stored procedures on a database server:

        SHOW PROCEDURE STATUS;
        
Show current connections to a database:

        SHOW PROCESSLIST;
        
Kill off query that is being problematic:

        Determine the "ID" of the query that needs to be killed
                SHOW PROCESSLIST;

        Kill the offending query:
                kill <query ID>;
                
Repair a crashed table:

        repair table table_name;

## Extracting a table from a mysqldump file

Extract the table ‘exampleTable’ from the gzipped database dump file exampledb_12232021.sql (generated from the 'exampledb' database)

        zcat /var/backups/mysql/exampledb_20211223.sql.gz | sed -n -e '/CREATE TABLE.*`exampleTable`/,/CREATE TABLE/p' > exampleTable_12232021.sql
 
Delete the drop/create lines of the next database from the bottom of the file (manually)

    vim exampleTable_12232021.sql
 
Rename the table to something else so it can be re-imported:

        sed -i 's/`exampleTable`/`exampleTable_12232021`/g' exampleTable_12232021.sql
 
Re-import the table to the database with the new name:

    mysql -uroot -p"$(</root/.sql_passwd)" exampledb < exampledb_12232021.sql

- Might need to manually copy the lines from just above the 'CREATE TABLE' line which configure the character set, etc.

# Networking

### Managing TCP Sessions

Managing TCP Connections
To kill a currently established TCP connection, the following command can be used:
(using a destination ip/port of 192.168.50.50 and 389 as an example

        ss -K dst 192.168.50.50 dport = 389

### Clearing ARP cache

**ESXi 5.1**

View ARP cache:

        esxcli network ip neighbor list
Remove an item from ARP cache:

        vsish -e set /net/tcpip/v4/neighbor del IPADDRESS
        
**Debian**

View ARP cache:

        arp
View ARP cache (IP only, don't resolve hostnames):

        arp -n
Remove an item from ARP cache:

        arp -d IPADDRESS

### Gratuitous ARP
Useful when replacing a server and the new one has a new MAC address. This will announce the new MAC address that is associated with the IP address to devices on the local network:

        arping -A -I eth0 IPADDRESS

### View Network Interface Details (Linux)

Using ethtool to view the "ens18" interface:

	[root@server ~]# ethtool ens18
	Settings for ens18:
		Supported ports: [ TP ]
		Supported link modes:   10baseT/Half 10baseT/Full
								100baseT/Half 100baseT/Full
								1000baseT/Full
		Supported pause frame use: No
		Supports auto-negotiation: Yes
		Supported FEC modes: Not reported
		Advertised link modes:  10baseT/Half 10baseT/Full
								100baseT/Half 100baseT/Full
								1000baseT/Full
		Advertised pause frame use: No
		Advertised auto-negotiation: Yes
		Advertised FEC modes: Not reported
		Speed: 1000Mb/s
		Duplex: Full
		Auto-negotiation: on
		Port: Twisted Pair
		PHYAD: 0
		Transceiver: internal
		MDI-X: off (auto)
		Supports Wake-on: umbg
		Wake-on: d
			Current message level: 0x00000007 (7)
								drv probe link
		Link detected: yes

## VMware PowerCLI

Gather VM names that have snapshots from VMware with a powershell module (requires vmware powercli)
connect-viserver vcenter.example.com

        get-vm | get-snapshot | format-list vm, name, description, created, sizegb | out-file snapshots.csv

# Linux - Useful Commands

## Debian

List files within a Deb package

- Downloaded Deb Package:\
`dpkg --contents <rpmname>.deb`
- Installed Deb Package:\
`dpkg -L <packagename>`

Determine the package a file comes from:

        dpkg -S /path/to/file

## RHEL 

View file/folder permissions set by package (NGINX as an example)

        rpm -q --queryformat="[%{FILEMODES:perms} %{FILENAMES}\n]" nginx
        
Clean up old kernels (Preserving the current and 1 previous version):\
*https://access.redhat.com/solutions/1227*

- RHEL 5/6/7 (requires yum-utils package):

  `package-cleanup --oldkernels --count=2`
		
- RHEL 8/9:

	`dnf remove $(dnf repoquery --installonly --latest-limit=-2 -q)`

List enabled/disabled/all repositories

        yum repolist enabled
        yum repolist disabled
        yum repolist all

Disable a repository for a single yum transaction
*Useful if the repository is being problematic*

        yum --disablerepo="reponame" info openssh

        Alternatively, a repo can be enabled for a single yum transaction by using the --enablerepo option

Show all available versions of a package

        yum --showduplicates list <packagename>

Install specific version of a package

        yum install <packagename>-<versionnumber>

List files within an RPM package

- Downloaded RPM Package:\
`rpm -qlp <rpmname>.rpm`
- Installed RPM Package:\
`rpm -ql <packagename>`

Determine the package a file comes from:

        rpm -qf /path/to/file
        yum whatprovides /path/to/file
        dnf provides /bin/ps

Fix Yum if the command "hangs" and does not return output

		Check for processes holding the RPM database open. Kill any processes that are listed
			lsof | grep /var/lib/rpm
		Delete the rpm db lock files
			rm -f /var/lib/rpm/__*
		Rebuild the RPM indexes
			rpm -vv --rebuilddb
		Verify the RPM database
			cd /var/lib/rpm
			/usr/lib/rpm/rpmdb_verify Packages
		
		More Info Here
		https://access.redhat.com/solutions/6903

# WSL - Windows Subsystem for Linux

### Disable Terminal Beep
#### Disable the source of the beeps
*from https://stackoverflow.com/a/36726662/5145596*

*Note: These only apply to the local terminal and will not apply to SSH sessions*

1. To disable the beep in bash you need to uncomment (or add if not already there) the line set bell-style none in your /etc/inputrc file.

2. To disable the beep and the visual bell also in vim you need to add the following to your ~/.vimrc file:

		set visualbell
		set t_vb=
	
3. To disable the beep also in less (i.e. also in man pages and when using "git diff") you need to add `export LESS="$LESS -R -Q"` in your ~/.profile file.

#### Disable the terminal beep sound in Windows - Possibly a better approach
The "Critical Stop" sound in Windows is what is played when terminal beeps occur. Setting the sound to "(none)" doesn't disable the sound, but instead causes a different default sound to be played.
A better option is to generate a slient WAV format file and set that as the sound for "Critical Stop"
1. Install the `sox` package (Swiss army knife of sound processing)
2. Run this command to generate a file named "silence.wav" that contains .5 seconds of silence: `sox -n -r 44100 -c 2 slience.wav trim 0.0 0.5`
3. Move the file to a location where Windows can access it
4. Open "Change system sounds" from the control panel, locate the "Critical Stop" sound and set it to the silence.wav file that was created. Click Apply
