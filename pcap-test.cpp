#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <map>

#include "p_headers.h"

std::map<int, const char*> ip_protocols = {
    {0, "HOPOPT"},
    {1, "ICMP"},
    {2, "IGMP"},
    {3, "GGP"},
    {4, "IP-in-IP"},
    {5, "ST"},
    {6, "TCP"},
    {7, "CBT"},
    {8, "EGP"},
    {9, "IGP"},
    {10, "BBN-RCC-MON"},
    {11, "NVP-II"},
    {12, "PUP"},
    {13, "ARGUS"},
    {14, "EMCON"},
    {15, "XNET"},
    {16, "CHAOS"},
    {17, "UDP"},
    {18, "MUX"},
    {19, "DCN-MEAS"},
    {20, "HMP"},
    {21, "PRM"},
    {22, "XNS-IDP"},
    {23, "TRUNK-1"},
    {24, "TRUNK-2"},
    {25, "LEAF-1"},
    {26, "LEAF-2"},
    {27, "RDP"},
    {28, "IRTP"},
    {29, "ISO-TP4"},
    {30, "NETBLT"},
    {31, "MFE-NSP"},
    {32, "MERIT-INP"},
    {33, "DCCP"},
    {34, "3PC"},
    {35, "IDPR"},
    {36, "XTP"},
    {37, "DDP"},
    {38, "IDPR-CMTP"},
    {39, "TP++"},
    {40, "IL"},
    {41, "IPv6"},
    {42, "SDRP"},
    {43, "IPv6-Route"},
    {44, "IPv6-Frag"},
    {45, "IDRP"},
    {46, "RSVP"},
    {47, "GRE"},
    {48, "DSR"},
    {49, "BNA"},
    {50, "ESP"},
    {51, "AH"},
    {52, "I-NLSP"},
    {53, "SWIPE"},
    {54, "NARP"},
    {55, "MOBILE"},
    {56, "TLSP"},
    {57, "SKIP"},
    {58, "IPv6-ICMP"},
    {59, "IPv6-NoNxt"},
    {60, "IPv6-Opts"},
    {61, "Any host internal protocol"},
    {62, "CFTP"},
    {63, "Any local network"},
    {64, "SAT-EXPAK"},
    {65, "KRYPTOLAN"},
    {66, "RVD"},
    {67, "IPPC"},
    {68, "Any distributed file system"},
    {69, "SAT-MON"},
    {70, "VISA"},
    {71, "IPCU"},
    {72, "CPNX"},
    {73, "CPHB"},
    {74, "WSN"},
    {75, "PVP"},
    {76, "BR-SAT-MON"},
    {77, "SUN-ND"},
    {78, "WB-MON"},
    {79, "WB-EXPAK"},
    {80, "ISO-IP"},
    {81, "VMTP"},
    {82, "SECURE-VMTP"},
    {83, "VINES"},
    {84, "TTP"},
    {85, "NSFNET-IGP"},
    {86, "DGP"},
    {87, "TCF"},
    {88, "EIGRP"},
    {89, "OSPFIGP"},
    {90, "Sprite-RPC"},
    {91, "LARP"},
    {92, "MTP"},
    {93, "AX.25"},
    {94, "IPIP"},
    {95, "MICP"},
    {96, "SCC-SP"},
    {97, "ETHERIP"},
    {98, "ENCAP"},
    {99, "Any private encryption scheme"},
    {100, "GMTP"},
    {101, "IFMP"},
    {102, "PNNI"},
    {103, "PIM"},
    {104, "ARIS"},
    {105, "SCPS"},
    {106, "QNX"},
    {107, "A/N"},
    {108, "IPComp"},
    {109, "SNP"},
    {110, "Compaq-Peer"},
    {111, "IPX-in-IP"},
    {112, "VRRP"},
    {113, "PGM"},
    {114, "Any 0-hop protocol"},
    {115, "L2TP"},
    {116, "DDX"},
    {117, "IATP"},
    {118, "STP"},
    {119, "SRP"},
    {120, "UTI"},
    {121, "SMP"},
    {122, "SM"},
    {123, "PTP"},
    {124, "ISIS over IPv4"},
    {125, "FIRE"},
    {126, "CRTP"},
    {127, "CRUDP"},
    {128, "SSCOPMCE"},
    {129, "IPLT"},
    {130, "SPS"},
    {131, "PIPE"},
    {132, "SCTP"},
    {133, "FC"},
    {134, "RSVP-E2E-IGNORE"},
    {135, "Mobility Header"},
    {136, "UDPLite"},
    {137, "MPLS-in-IP"},
    {138, "manet"},
    {139, "HIP"},
    {140, "Shim6"},
    {141, "WESP"},
    {142, "ROHC"}
};


std::map<int, const char*> ether_types = {
    {0x0000, "Reserved"},
    {0x0101, "Xerox PUP"},
    {0x0200, "Xerox PUP Addr Trans"},
    {0x0600, "Xerox NS IDP"},
    {0x0800, "Internet Protocol version 4 (IPv4)"},
    {0x0805, "X.75 Internet"},
    {0x0806, "Address Resolution Protocol (ARP)"},
    {0x0808, "Frame Relay ARP"},
    {0x0842, "Wake-on-LAN"},
    {0x086D, "Reverse ARP"},
    {0x0888, "ITU-T T.802.3ad Slow Protocols"},
    {0x088A, "MPLS Unicast"},
    {0x088B, "MPLS Multicast"},
    {0x08A1, "Link Layer Discovery Protocol (LLDP)"},
    {0x08CC, "HomePlug 1.0 MME"},
    {0x0900, "Ethernet Configuration Testing Protocol"},
    {0x0A00, "Xerox Network Systems (XNS) IDP"},
    {0x0BAD, "CCITT X.25 PLP"},
    {0x6000, "DEC MOP Dump/Load"},
    {0x6001, "DEC MOP Remote Console"},
    {0x6002, "DECnet Phase IV"},
    {0x6003, "DEC LAT"},
    {0x6004, "DEC Diagnostic Protocol"},
    {0x6005, "DEC Customer Use"},
    {0x6006, "DEC Local Area Transport (LAT)"},
    {0x8035, "Reverse Address Resolution Protocol (RARP)"},
    {0x8037, "AppleTalk (Ethertalk)"},
    {0x809B, "AppleTalk AARP"},
    {0x80F3, "AppleTalk AARP"},
    {0x8100, "VLAN-tagged frame (IEEE 802.1Q) and Shortest Path Bridging IEEE 802.1aq"},
    {0x8137, "IPX"},
    {0x814C, "SNMP"},
    {0x86DD, "Internet Protocol Version 6 (IPv6)"},
    {0x8808, "Ethernet flow control"},
    {0x8809, "IEEE 802.3 Slow Protocols"},
    {0x8819, "CobraNet"},
    {0x8847, "MPLS unicast"},
    {0x8848, "MPLS multicast"},
    {0x8863, "PPPoE Discovery Stage"},
    {0x8864, "PPPoE Session Stage"},
    {0x886D, "Intel Advanced Networking Services (ANS)"},
    {0x8870, "Jumbo Frames (Obsoleted Draft)"},
    {0x887B, "HomePlug AV MME"},
    {0x888E, "EAP over LAN (IEEE 802.1X)"},
    {0x8892, "PROFINET Protocol"},
    {0x889A, "HyperSCSI (SCSI over Ethernet)"},
    {0x88A2, "ATA over Ethernet"},
    {0x88A4, "EtherCAT Protocol"},
    {0x88A8, "Provider Bridging (IEEE 802.1ad) & Shortest Path Bridging IEEE 802.1aq"},
    {0x88AB, "Ethernet Powerlink"},
    {0x88B8, "GOOSE (Generic Object Oriented Substation event)"},
    {0x88B9, "GSE (Generic Substation Events) Management Services"},
    {0x88BA, "SV (Sampled Value Transmission)"},
    {0x88CC, "Link Layer Discovery Protocol (LLDP)"},
    {0x88CD, "SERCOS III"},
    {0x88E1, "HomePlug Green PHY"},
    {0x88E3, "Media Redundancy Protocol (IEC62439-2)"},
    {0x88E5, "MAC Security (IEEE 802.1AE)"},
    {0x88E7, "Provider Backbone Bridges (PBB) (IEEE 802.1ah)"},
    {0x88F7, "Precision Time Protocol (PTP) over Ethernet (IEEE 1588)"},
    {0x8902, "IEEE 802.21 Media Independent Handover Protocol"},
    {0x8906, "Fibre Channel over Ethernet (FCoE)"},
    {0x8914, "FCoE Initialization Protocol"},
    {0x8915, "RDMA over Converged Ethernet (RoCE)"},
    {0x891D, "TTEthernet Protocol Control Frame (TTE)"},
    {0x892F, "High-availability Seamless Redundancy (HSR)"},
    {0x9000, "Ethernet Configuration Testing Protocol"},
    {0x9100, "VLAN-tagged frame with double tagging (Q-in-Q)"},
    {0x9200, "IEEE 802.1ad Service VLAN"},
    {0xF1C1, "Redundancy Tag (IEEE 802.1CB Frame Replication and Elimination for Reliability)"}
};


void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
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

u_int16_t print_ethernet_header(const u_char* packet) {
    struct libnet_ethernet_hdr* eth = (struct libnet_ethernet_hdr*)packet;
    u_int16_t type = ntohs(eth->ether_type);

    printf("Ethernet II header:\n");
    printf("  Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
    printf("  Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    printf("  Type: 0x%04x-%s\n", type, ether_types.find(type) != ether_types.end() ? ether_types[type] : "N/A");
    printf("\n");
    return type;
}

u_int8_t print_ip_header(const u_char* packet) {
    struct libnet_ipv4_hdr* ip = (struct libnet_ipv4_hdr*)packet;
    u_int8_t protocol = ip->ip_p;
    printf("IPv4 header:\n");
    printf("  Protocol: %s(%d)\n", ip_protocols.find(protocol) != ip_protocols.end() ? ip_protocols[protocol] : "N/A", protocol);
    printf("  Source IP: %s\n", inet_ntoa(ip->ip_src));
    printf("  Destination IP: %s\n", inet_ntoa(ip->ip_dst));
    printf("\n");

    return protocol;
}

void print_tcp_header(const u_char* packet) {
    struct libnet_tcp_hdr* tcp = (struct libnet_tcp_hdr*)(packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr));
    printf("TCP header:\n");
    printf("  Source Port: %d\n", ntohs(tcp->th_sport));
    printf("  Destination Port: %d\n", ntohs(tcp->th_dport));
    printf("  Sequence Number: %u\n", ntohs(tcp->th_seq));
    printf("  Acknowledgment Number: %u\n", ntohs(tcp->th_ack));
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		exit(EXIT_FAILURE);

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		exit(EXIT_FAILURE);
	}
    int32_t idx = 0;
	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
        printf("[Packet No. %d]\n", ++idx);
		printf("%u bytes captured\n", header->caplen);
        printf("Timestamp: %s", ctime((const time_t*)&header->ts.tv_sec));
        printf("--------------------\n");
        print_ethernet_header(packet);

        const u_char* ip_packet = packet + sizeof(struct libnet_ethernet_hdr);
        print_ip_header(ip_packet);
        const u_char* tcp_packet = ip_packet + sizeof(struct libnet_ipv4_hdr);  
        print_tcp_header(tcp_packet);
        printf("====================\n");
	}

	pcap_close(pcap);
}
