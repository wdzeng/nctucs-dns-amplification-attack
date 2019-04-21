#ifndef hpbl_raw
#define hpbl_raw

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdint.h>
#include <stdlib.h>
#include "./dns.h"
#define PROTOCOL_UDP 17
#define IPV4 4
#define IP_ID 16023  // 0x0000 ~ 0xffff

// UDP pseudo header. 96 bits.
struct psh {
    uint32_t srcip;
    uint32_t destip;
    uint8_t zeros;
    uint8_t ptc;
    uint16_t len;
};

// Given an udp packet with data and pseudo header, calculates the checksum. The
// size of udp packet is unknown and hence should be given.
uint16_t udpChecksum(uint16_t *ptr, int len) {
    unsigned int sum = 0;
    while (len >= 2) {
        sum += *ptr++;
        len -= 2;
    }
    // Still a byte, padding width zeros
    if (len /* == 1 */) {
        uint16_t odd = *((uint8_t *)ptr);
        odd <<= 8;
        sum += htons(odd);
    }
    sum += (sum >> 16);
    return ~((uint16_t)sum);
}

// Given ip header, calculates the checksum. The init checksum should
// have been set to zeros. The ip hedaer should be 20 bytes = 160 bits.
uint16_t ipChecksum(uint16_t *ptr) {
    unsigned int sum = 0;
    int n = 10;
    while (n--) sum += *ptr++;
    sum += (sum >> 16);
    return ~((uint16_t)sum);
}

// Fills the udp header and returns its length, which must be 8 bytes. This does
// not append data behind udp header.
int fillUdpHeader(uint8_t *buff, const uint32_t srcIp, const uint32_t destIp,
                  const uint16_t srcPort, const uint8_t *data,
                  const int dataSize) {
    uint8_t tmpbuf[sizeof(psh) + sizeof(udphdr) + dataSize];

    // Create pseudo header. For consistences, change to net byte order.
    struct psh *p = (struct psh *)tmpbuf;
    p->srcip = htonl(srcIp);
    p->destip = htonl(destIp);
    p->zeros = 0;
    p->ptc = PROTOCOL_UDP;
    p->len = htons(sizeof(udphdr) + dataSize);

    // Create udp header
    struct udphdr *u = (struct udphdr *)(tmpbuf + sizeof(psh));
    u->source = htons(srcPort);
    u->dest = htons(PORT_DNS);
    u->len = htons(sizeof(udphdr) + dataSize);
    u->check = 0;
    // Fill data
    memcpy((char *)u + sizeof(udphdr), data, dataSize);

    // Check sum
    // No need to htons
    u->check =
        udpChecksum((uint16_t *)p, sizeof(psh) + sizeof(udphdr) + dataSize);

    // Copy only udp header to buff, pseudo header and data are not copied
    memcpy(buff, tmpbuf + sizeof(psh), sizeof(udphdr));
    return sizeof(udphdr);
}

// Fills the ip header and return its length, which must be 20 bytes. Noted the
// udp header or dns query message or any other characters are not filled. The
// arg dataSize should put udp header and dns query packet into consideration,
// excluding the ip header.
int fillIpHeader(uint8_t *buff, const uint32_t srcIp, const uint32_t destIp,
                 const int dataSize) {
    // Clear
    memset(buff, 0, sizeof(iphdr));

    // Fill header
    struct iphdr *h = (struct iphdr *)buff;
    h->version = IPV4;
    h->ihl = 5;
    h->tot_len = htons(sizeof(iphdr) + dataSize);
    h->id = htons(IP_ID);
    h->ttl = 64;
    h->protocol = PROTOCOL_UDP;
    h->saddr = htonl(srcIp);
    h->daddr = htonl(destIp);
    h->check = 0;
    // Check sum
    // Already in net byte order
    h->check = ipChecksum((uint16_t *)h);
    return sizeof(iphdr);
}

// Creates a dns query packet then returns its length (bytes).
int createPacket(uint8_t *buff, uint32_t srcIp, const uint32_t destIp,
                 const uint16_t srcPort, const char *domain, uint16_t dnstyp,
                 uint16_t dnsclz) {
    // Build the entire dns query message packet
    uint8_t dnsPacket[2048];
    const int ssdns = createDnsPacket(dnsPacket, domain, dnstyp, dnsclz);

    // Prepend ip header and udp header
    int cur = 0;
    cur += fillIpHeader(buff, srcIp, destIp, sizeof(udphdr) + ssdns);
    cur += fillUdpHeader(buff + cur, srcIp, destIp, srcPort, dnsPacket, ssdns);
    memcpy(buff + cur, dnsPacket, ssdns);  // Fill dns query message

    return cur + ssdns;
}

#endif