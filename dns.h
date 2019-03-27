#ifndef hpbl_dns
#define hpbl_dns

#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#define PORT_DNS 53
#define DNSH_ID 16023  // 0 ~ 65536
#define DNS_QTYPE_A 1
#define DNS_QTYPE_PTR 12
#define DNS_QTYPE_TXT 16
#define DNS_QTYPE_AAAA 28
#define DNS_QTYPE_RRSIG 46
#define DNS_QTYPE_DNSKEY 48
#define DNS_QTYPE_ANY 255
#define DNS_QCLZ_STD 1
#define DNSRR_ROOT 0
#define DNSRR_TYPE_OPT 41
#define DNSRR_PAYLOAD_SIZE 0x7FFF
#define DNSRR_Z 0x8000

// Dns query header. The header takes 96 bits.
struct dnsh {
    // Id of this message.
    uint16_t id;
    // Flags. 16 bits. Should be 0000 0001 0000 0000.
    // Bit   0: Query or Reply (0 = Query; 1 = Reply). Set to 0.
    // Bit 1-4: 4 bit field that specifies the query type. We’re sending a
    // standard query, so we’ll set this to 0 (0000 = Standard query; 0001 =
    // Inverse query;  0010 = Server status request; Others = Reserved for
    // future use).
    // Bit   5: AA. For reply.
    // Bit   6: Message has been truncated. Our message is short. Set this to 0.
    // Bit   7: Recursion is desired. SET TO 1!!!
    // Bit   8: RA. For reply.
    // Bit 9-B: Reserved. Zeros.
    // Bit C-F: Rcode(Response Code). Error message. For reply.
    uint16_t flags;
    // Number of question. We’ll be sending 1 question.
    // More to perform an amplification?
    uint16_t nq;
    // 16 bits. Number of answers. Used in reply.
    uint16_t na;
    // 16 bits. Number of authority records.
    uint16_t natr;
    // 16 bits. Number of additional records..
    uint16_t nadr;
};

// Dns query type.
struct dnstyp {
    // We look for an A records = 1.
    uint16_t typ;
    // We look for internet = 1.
    uint16_t clz;
};

// Fills dns header and returns the length which must be 12bytes.
int fillDnsHeader(uint8_t* buff) {
    dnsh* h = (dnsh*)buff;
    h->id = htons(DNSH_ID);
    h->flags = htons(0x0100);
    h->nq = htons(1);
    h->na = 0;
    h->natr = 0;
    h->nadr = htons(1);  // We use opt
    return sizeof(dnsh);
}

// Fills dns query message width ending 0. Does not contain query type
// message. Domain messages only. Returns the length (bytes) of message body,
// including the ending 0.
int fillDnsMsg(uint8_t* buff, const char* domain) {
    // Example for example.com
    // 07 65 - 'example' has length 7, e
    // 78 61 - x, a
    // 6D 70 - m, p
    // 6C 65 - l, e
    // 03 63 - 'com' has length 3, c
    // 6F 6D - o, m
    // 00    - zero byte to end the QNAME
    strcpy((char*)buff + 1, domain);
    const int len = strlen(domain);

    int count = 0;
    for (int cur = len; cur /* >0 */; cur--) {
        // Replace dot width length
        if (buff[cur] == '.') {
            buff[cur] = count;
            count = 0;
        }
        // domain character count ++
        else {
            count++;
        }
    }
    buff[0] = count;
    return len + 2;
}

// Fills dns qtype and q and returns the length which must be 2 bytes.
int fillDnsType(uint8_t* buff, uint16_t type, uint16_t clazz) {
    dnstyp* t = (dnstyp*)buff;
    t->typ = htons(type);
    t->clz = htons(clazz);
    return sizeof(dnstyp);
}

// Using __attrubute((__packed__))__ to force canceling align
struct __attribute__((__packed__)) dnsrr {
    uint8_t name;     // Root = 0
    uint16_t type;    // Option = 41
    uint16_t plsize;  // Pay load size = 3xxxx
    uint8_t higher;   // No effect here
    uint8_t ednsv;    // Edns version = 0
    uint16_t zcode;   // .000 0000 0000 0000 (1/0: can/cannot handle dnssec)
    uint16_t addlen;  // Additional data (i.e. cookies); length = 0
};

int fillDnsRr(uint8_t* buff) {
    dnsrr* rr = (dnsrr*)buff;
    rr->name = DNSRR_ROOT;
    rr->type = htons(DNSRR_TYPE_OPT);
    rr->plsize = htons(DNSRR_PAYLOAD_SIZE);
    rr->higher = 0;
    rr->ednsv = 0;
    rr->zcode = htons(DNSRR_Z);
    rr->addlen = 0;
    return sizeof(dnsrr);
}

// Creates a dns query package. Returns the length of packet.
int createDnsPacket(uint8_t* buff, const char* domain, uint16_t type,
                    uint16_t clazz) {
    int cur = 0;
    cur += fillDnsHeader(buff);
    cur += fillDnsMsg(buff + cur, domain);
    cur += fillDnsType(buff + cur, type, clazz);
    cur += fillDnsRr(buff + cur);
    return cur;
}

#endif