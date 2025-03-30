#ifndef PACKET_HANDLER_H
#define PACKET_HANDLER_H

#include <pcap.h>
#include <iostream>

// Definindo as flags TCP
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PUSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20

// Estruturas dos cabeçalhos

//DataLink
struct ethernet_header {
    u_char dest_mac[6];
    u_char src_mac[6];
    u_short eth_type;
};


//Network
struct ipv4_header {
    uint8_t ihl : 4;
    uint8_t version : 4;
    uint8_t tos;
    uint16_t total_length;
    uint16_t id;
    uint16_t fragment_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dest_ip;
};

//Network
struct ipv6_header {
    uint32_t version : 4;          // Versão (IPv6 é 6)
    uint32_t traffic_class : 8;    // Classe de tráfego
    uint32_t flow_label : 20;      // Rótulo de fluxo
    
    uint32_t payload_length : 16;       // Comprimento do payload
    uint32_t next_header : 8;           // Próximo cabeçalho (protocolo, como TCP, UDP, etc.)
    uint32_t hop_limit : 8;             // Limite de saltos (TTL equivalente)
    
    uint32_t src_ip[4];            // Endereço de origem (128 bits)
    uint32_t dest_ip[4];           // Endereço de destino (128 bits)
};



//Gostei nao. EStudar
struct icmp_header {
    uint8_t type;         // Tipo de mensagem ICMP
    uint8_t code;         // Código para o tipo
    uint16_t checksum;    // Somatório de verificação
    union {
        struct {
            uint16_t id;      // Identificador
            uint16_t sequence; // Número de sequência
        } echo;              // Para mensagens Echo
        uint32_t gateway;    // Para mensagens de redirecionamento
        struct {
            uint16_t unused;
            uint16_t mtu;
        } frag;              // Para mensagens de fragmentação
    } data;
};


struct igmp_header {
    uint8_t type;         // Tipo de mensagem IGMP
    uint8_t max_resp_time; // Tempo máximo de resposta (em decisegundos)
    uint16_t checksum;    // Somatório de verificação
    uint32_t group_address; // Endereço do grupo (multicast)
};

//Transport
struct udp_header {
    uint16_t src_port;       // Porta de origem
    uint16_t dest_port;      // Porta de destino
    uint16_t length;         // Comprimento do datagrama UDP (cabeçalho + dados)
    uint16_t checksum;       // Somatório de verificação
};


//Transport
struct tcp_header {
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t data_offset:4;
    uint8_t reserved:3;
    uint8_t ns:1;
    uint8_t flags:8;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_ptr;
};

// Funções para processar pacotes
void etherTypeChecker(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet);

#endif // PACKET_HANDLER_H
