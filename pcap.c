#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ether.h>

// Ethernet Header
struct etheader {
    u_char dst_mac[6];               // destinatin mac address
    u_char src_mac[6];               // source mac address
    u_short type;                    // type of header
};

// IP Header
struct ipheader {
    unsigned char       iph_ihl:4,    // ip header length
                        iph_ver:4;    // ip version
    unsigned char       iph_tos;      // type of service
    unsigned short int  iph_len;      // ip packet length (data + header)
    unsigned short int  iph_ident;    // identification
    unsigned short int  iph_flag:3,   // ip header flags
                        iph_fos:13;   // ip fragment offset
    unsigned char       iph_ttl;      // ip time to live
    unsigned char       iph_protocal; // ip protocal
    unsigned short int  iph_checksum; // ip header checksum
    struct   in_addr    iph_src;      // source ip address
    struct   in_addr    iph_dst;      // destination ip address
};

//TCP Header
struct tcpheader {
    unsigned short int src_port;      // tcp source port
    unsigned short int dst_port;      // tcp destination port
    unsigned int tcp_seq;             // tcp sequence number
    unsigned int tcp_ack;             // tcp acknowledgement number
    unsigned char tcp_offx2;          // data offset, reserved
#define TH_OFF(th) (((th)->tcp_offx2 & 0xf0) >> 4)
    unsigned char tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS  (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    unsigned short int tcp_win;        // tcp window
    unsigned short int tcp_chk;        // tcp checksum
    unsigned short int tcp_urp;        // tcp urgent pointer
};

void mac_capture(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    struct etheader *eth = (struct etheader *)packet;

    printf("SRC MAC : %s\n", ether_ntoa(eth->src_mac));
    printf("DST MAC : %s\n", ether_ntoa(eth->dst_mac));
}

void ip_capture(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    struct etheader *eth = (struct etheader *)packet;
    struct ipheader *iph = (struct ipheader *)(packet + sizeof(struct etheader));

    printf("SRC IP Address : %s\n", inet_ntoa(iph->iph_src));
    printf("DST IP Address : %s\n", inet_ntoa(iph->iph_dst));
}

void tcp_capture(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct etheader *eth = (struct etheader *)packet;
    struct ipheader *iph = (struct ipheader *)(packet + sizeof(struct etheader));
    struct tcpheader *tcph = (struct tcpheader *)(packet + sizeof(struct etheader) + (iph->iph_ihl * 4));

    printf("SRC Port Number : %d\n", ntohs(tcph->src_port));
    printf("DST Port Number : %d\n", ntohs(tcph->dst_port));
}

void packet_capture(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct etheader *eth = (struct etheader *)packet;
    struct ipheader *iph = (struct ipheader *)(packet + sizeof(struct etheader));
    struct tcpheader *tcph = (struct tcpheader *)(packet + sizeof(struct etheader) + (iph->iph_ihl * 4));

    printf("SRC MAC : %s\n", ether_ntoa(eth->src_mac));
    printf("DST MAC : %s\n", ether_ntoa(eth->dst_mac));

    printf("SRC IP Address : %s\n", inet_ntoa(iph->iph_src));
    printf("DST IP Address : %s\n", inet_ntoa(iph->iph_dst));

    printf("SRC Port Number : %d\n", ntohs(tcph->src_port));
    printf("DST Port Number : %d\n", ntohs(tcph->dst_port));
    printf("\n");
    printf("\n");
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "디바이스 열기 실패: %s\n",errbuf);
        return 1;
    }
    pcap_loop(handle, 0, packet_capture, NULL);

    pcap_close(handle);

    return 0;
}