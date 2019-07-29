# methods

Portmirroring / SPAN, arp poisoning

# zone transfer

nmap gateway_ip_or_host
port 53 domain

### linux
host -t axfr domain.name dns-server
dig axfr @dns-server domain.name

### windows
nslookup
> set type=any
> ls -d wayne.net > dns.wayne.net
> ls -t wayne.net > list.wayne.net
> exit

# sqlserver trace

Microsoft Message Analyzer
    https://www.microsoft.com/en-us/download/details.aspx?id=44226

1. New Session
2. New Data Source > Live Trace
3. Scenario > Select:
    If AppFoo and SQL on same system: Loopback and Unencrypted IPsec
    If AppFoo and SQL on separate systems: Local Network Interfaces
4. Start
5. Message Table > Column Header > Add Columns > TDS > SQLBatch > SqlBatchPacketData > Right Click: SQLText > Add as column
    -- https://stackoverflow.com/questions/2023589/how-can-i-decode-sql-server-traffic-with-wireshark

clear log
    restart session

mma
    TDS
    *SQLText contains "a"
    ```
    Fail to start live consumer 
    Please reinstall Message Analyzer to correct the problem. If the PEF-WFP-MessageProvider continues to fail, you may have a conflict with a third party filter driver or your computer might have reached the maximum number of drivers allowed, for example, on a Windows 7 machine. To resolve this issue, you can try increasing the filter driver limit in the registry.
    ```

test
    sqlcmd without `-N` (encrypt connection)

validate TDS packets are sent
    Transact-SQL session > Query menu > Include Client Statistics

https://dragos.com/blog/industry-news/threat-hunting-with-python-part-4-examining-microsoft-sql-based-historian-traffic/
https://www.anitian.com/hacking-microsoft-sql-server-without-a-password/
https://cqureacademy.com/blog/secure-server/tabular-data-stream
https://docs.microsoft.com/en-us/message-analyzer/applying-and-managing-filters

|| dump tables and diff before and after action on app

---

tshark -i lo -d tcp.port==1433,tds -T fields -e tds.query
    https://www.wireshark.org/docs/dfref/t/tds.html

tcpdump -i any -s 0 -l -vvv -w - dst port 3306 | strings

# +

SYN and ACK bits sent and received in both directions
"I hear your bytes"

DynDNS
https://dyn.com/
