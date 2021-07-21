#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>
#define ETH_ALEN 6 // Ethernet Address Length

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param  = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

void ethernet_sub_print(struct libnet_ethernet_hdr *eth, char host){
    for(int i = 0; i < ETH_ALEN; i++){
        switch(host){
        //inet_ntoa: Interconversion function between NBO(big-endian) and Dotted-Decimal Notation
        case 's': printf("%02x", eth->ether_shost[i]); break;//source mac print
        case 'd': printf("%02x", eth->ether_dhost[i]); break;//destination mac print
        }

        if(i < (ETH_ALEN-1))
            printf(":");
    }
}
void ethernet_print(struct libnet_ethernet_hdr *eth){
    printf("[Ethernet Header]\t");
    printf("src mac: ");
    ethernet_sub_print(eth, 's');
    printf("\t");

    printf("dst mac: ");
    ethernet_sub_print(eth, 'd');
    printf("\n");
}
void ip_print(struct libnet_ethernet_hdr *eth, struct libnet_ipv4_hdr *ip){
    if(ntohs(eth->ether_type) == ETHERTYPE_IP){
        printf("[IP Header]\t");
        //inet_ntoa: Interconversion function between NBO(big-endian) and Dotted-Decimal Notation
        printf("\tsrc ip: %s\t", inet_ntoa(ip->ip_src));//source ip print
        printf("\tdst ip: %s\n", inet_ntoa(ip->ip_dst));//destination ip print
    }
}
void tcp_print(struct libnet_ipv4_hdr *ip, struct libnet_tcp_hdr *tcp){
    if(ip->ip_p == IPPROTO_TCP){
        printf("[TCP Header]\t");
        printf("\tsrc port: %d\t", ntohs(tcp->th_sport));//source port print
        printf("\t\tdst port: %d\n", ntohs(tcp->th_dport));//destination port print
    }
}
void data_print(const u_char* data){
    printf("[Data]\t\t\t");
    for(int i = 0; i < 8; i++){
        printf("%02x\t",*(data+i));//data 8byte print
    }
    printf("\n");
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        printf("%u bytes captured\n", header->caplen);

        struct libnet_ethernet_hdr *Eth = (struct libnet_ethernet_hdr *) packet;
        struct libnet_ipv4_hdr *Ip = (struct libnet_ipv4_hdr *)(packet + sizeof(struct libnet_ethernet_hdr));
        struct libnet_tcp_hdr *Tcp = (struct libnet_tcp_hdr *)(packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr));
        const u_char* Data = packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr) + sizeof(struct libnet_tcp_hdr);

        printf("=======================================================================================\n");
        ethernet_print(Eth);//mac address print
        ip_print(Eth, Ip);//ip address print
        tcp_print(Ip, Tcp);//tcp port print
        data_print(Data);//data print
    }

    pcap_close(pcap);

    return 0;
}
