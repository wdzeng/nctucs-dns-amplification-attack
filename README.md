# DNS Amplifaction Attack
This is my homework in NCTU. Input the victim's ip, domain queried, the DNS server's ip and type of DNS, seeing the effects via wireshark.

In this program DNS querying message is sent via UDP (port 53); hence raw sockets are applied. The opt and EDNS0 is used to make size of reply greater.

## DNS Type
You can see the whole list on [wiki](https://en.wikipedia.org/wiki/List_of_DNS_record_types).

| Code (input) | Type name  | Descriptyion  | 
| ---          | ---        | --- |
|   1 | **A**      | Returns a 32-bit IPv4 address, **most commonly used** to map hostnames to an IP address of the host. | 
|  26 | AAAA   | Returns a 128-bit IPv6 address. |
|  48 | DNSKEY | The key record used in **DNSSEC**. Uses the same format as the KEY record. |
|  12 | PTR    | Pointer to a canonical name. Unlike a CNAME, DNS processing stops and just the name is returned. The most common use is for implementing reverse DNS lookups, but other uses include such things as DNS-SD. |
|  16 | TXT    | Originally for arbitrary human-readable text in a DNS record. Since the early 1990s, however, this record more often carries machine-readable data, such as specified by RFC 1464, opportunistic encryption, Sender Policy Framework, DKIM, DMARC, DNS-SD, etc. In some cases this returns lots of data resulting in good DNS amplification. |
| 255 | **ANY**   | Returns all records of all types known to the name server. In most cases this returns lots of data resulting in good DNS amplification; however, a good dns server may ignore this type of request. |

## Reference (DNS)
* [DNS Brief Introduction (Chinese)](http://www.pcnet.idv.tw/pcnet/network/network_ip_dns.htm)
* [Deep Inside a DNS Amplification DDoS Attack](https://blog.cloudflare.com/deep-inside-a-dns-amplification-ddos-attack/)
* [Better than Best Practices for DNS Amplification Attacks](https://www.nanog.org/sites/default/files/mon_general_weber_defeat_23.pdf)
* [DENSEC](http://www.myhome.net.tw/2011_03/p03.htm)

## Reference (IP and UDP)
* [IP Packet Header](http://www.cs.miami.edu/home/burt/learning/Csc524.092/notes/ip_example.html)
* [How to calculate UDP Checksum (Chinese)](https://www.ptt.cc/bbs/NTUE-CS100/M.1262621627.A.945.html)
* [Raw Socket](https://www.tenouk.com/Module43a.html)
* [A Guide to Using Raw Sockets](https://opensourceforu.com/2015/03/a-guide-to-using-raw-sockets/)
* [TCP Socket Programming](http://zake7749.github.io/2015/03/17/SocketProgramming/)
* [Introduction to OSI (Chinese)](http://linux.vbird.org/linux_server/0110network_basic.php#whatisnetwork_osi)