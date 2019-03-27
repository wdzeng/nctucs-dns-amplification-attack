#ifndef hpbl_cs_util
#define hpbl_cs_util

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h> /* for strncpy */
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

// Converts ip xx.xx.xxx.xxx to integer.
uint32_t stoip(const char* ip) {
    uint32_t a = 0, b = 0, c = 0, d = 0;
    sscanf(ip, "%u.%u.%u.%u", &a, &b, &c, &d);
    return (a << 24) | (b << 16) | (c << 8) | d;
}

// Converts int to xxx.xxx.xxx.xxx addres
std::string iptos(uint32_t ip) {
    char buff[16];
    unsigned int a = ip >> 24;
    unsigned int b = (ip >> 16) & 0xff;
    unsigned int c = (ip >> 8) & 0xff;
    unsigned int d = ip & 0xff;
    snprintf(buff, 16, "%d.%d.%d.%d", a, b, c, d);
    return buff;
}

// Prints a packet.
void viewPacket(unsigned char* p, int len) {
    const int odd = len % 2;
    if (odd) len--;

    int cur = 0;
    while (cur < len) {
        for (int i = 0; i < 8 && cur < len; i++) {
            printf("%02x", p[cur++]);
            printf("%02x", p[cur++]);
            printf(" ");
        }
        if (cur < len) printf("\n");
    }

    if (odd) {
        if (len % 16 == 0) printf("\n");
        printf("%02x..", p[cur]);
    }
    printf("\n");
}

// Gets current ip.
std::string myip(const char* itfc = "enp0s3") {
    char buff[16];
    int fd;
    struct ifreq ifr;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, itfc, IFNAMSIZ - 1);
    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);
    strcpy(buff, inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr));
    return buff;
}

#endif
