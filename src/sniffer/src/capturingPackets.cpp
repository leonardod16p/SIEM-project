#include "../include/packet_handler.h"

/*

Application Layer

*/



/*

Transport Layer

*/

void quicHandler(){
    std::cout << "This is an QUIC protocol!" << std::endl;
}

void udpHandler(){
    std::cout << "This is an UDP protocol!" << std::endl;
}
void tcpHandler(){
    std::cout << "This is an TCP protocol!" << std::endl;
}


/*

Network Layer

*/

void icmpHandler(){
    std::cout << "This is an ICMP protocol!" << std::endl;
}
void igmpHandler(){
    std::cout << "This is an IGMP protocol!" << std::endl;

}

void ipv4Handler(const u_char *packet){
    std::cout << "This is an IPv4 packet!" << std::endl;
        // Proceed to process as an IPv4 packet
        const ipv4_header *ip = (const ipv4_header *)(packet + sizeof(ethernet_header));
        
        // Print source and destination IP addresses
        std::cout << "Source IP: "
                  << (ip->src_ip & 0xFF) << "."
                  << ((ip->src_ip >> 8) & 0xFF) << "."
                  << ((ip->src_ip >> 16) & 0xFF) << "."
                  << ((ip->src_ip >> 24) & 0xFF) << std::endl;

        std::cout << "Destination IP: "
                  << (ip->dest_ip & 0xFF) << "."
                  << ((ip->dest_ip >> 8) & 0xFF) << "."
                  << ((ip->dest_ip >> 16) & 0xFF) << "."
                  << ((ip->dest_ip >> 24) & 0xFF) << std::endl;

        uint8_t protocolType = ip->protocol;
            
        switch(protocolType) {
            case 0x1:   //ICMP
                icmpHandler();
                break;
            case 0x2:   //IGMP
                igmpHandler();        
                break;
            case 0x6:   //TCP
                tcpHandler();
                break;
            case 0x11:  //UDP
                udpHandler();
                break;
            default:
                std::cout << "Non-ICMP, IGMP, TCP or UDP packet (protocolType: 0x" << std::hex << protocolType << ")" << std::endl;;
        }

}

void ipv6Handler(const u_char *packet){
    std::cout << "This is an IPv6 packet!" << std::endl;

    const ipv6_header *ip = (const ipv6_header *)(packet + sizeof(ethernet_header));

    uint8_t nextHeader = ip->next_header;
            
        //Valores sao os mesmos que os do IPv4
        switch(nextHeader) {
            case 0x1:   //ICMP
                icmpHandler();
                break;
            case 0x2:   //IGMP
                igmpHandler();
                break;
            case 0x6:   //TCP
                tcpHandler();
                break;
            case 0x11:  //UDP
                udpHandler();
                break;
            default:
                std::cout << "Non-ICMP, IGMP, TCP or UDP packet (nextHeader: 0x" << std::hex << nextHeader << ")" << std::endl;;
        }

}

void arpHandler(const u_char *packet){
    std::cout << "This is an ARP Frame!" << std::endl;
}


/*

Data Link Layer

*/

void frameHandler(){}

void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    const ethernet_header *eth = (const ethernet_header *)packet;

    // Convert EtherType from network to host byte order
    uint16_t etherType = ntohs(eth->eth_type);
    
    switch(etherType) {
        case 0x0800:
            ipv4Handler(packet);
            break;
        case 0x86DD:
            ipv6Handler(packet);
            break;
        case 0x806:
            arpHandler(packet);
        default:
            std::cout << "Non-IPv4, IPv6 or ARP packet (EtherType: 0x" << std::hex << etherType << ")" << std::endl;;
    }

    //Show header in every frame

    std::cout << "Endereço MAC de Origem: ";
    for (int i = 0; i < 6; i++) {
        printf("%02x", eth->src_mac[i]);
        if (i < 5) std::cout << ":";
    }
    std::cout << std::endl;

    std::cout << "Endereço MAC de Destino: ";
    for (int i = 0; i < 6; i++) {
        printf("%02x", eth->dest_mac[i]);
        if (i < 5) std::cout << ":";
    }
    std::cout << std::endl;

    //std::cout << "Tipo/EtherType: " << ntohs(eth->eth_type) << std::endl;
    
    std::cout << "Captured a packet with length: " << pkthdr->len << " bytes" << std::endl;
    
    // Opcional: você pode iterar sobre os bytes do pacote aqui
    for (u_int i = 0; i < pkthdr->len; i++) {
        std::cout << std::hex << (unsigned int)packet[i] << " ";
        if ((i + 1) % 16 == 0)
            std::cout << std::endl;
    }
    std::cout << std::endl;
    std::cout << pkthdr->len << std::endl;
    std::cout << pkthdr->caplen << std::endl;
    std::cout << std::endl;
    
}