#include <iostream>
#include <pcap.h>
#include "../include/packet_handler.h"


int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    
    pcap_if_t *alldevs;
    // Obter dispositivos de rede disponíveis
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Erro ao obter dispositivos de rede: " << errbuf << std::endl;
        return 1;
    }

    std::cout << "Dispositivos disponíveis:" << std::endl;
    
    int i = 0;
    for (pcap_if_t *d = alldevs; d != nullptr; d = d->next) {
        std::cout << ++i << ": " << d->name;
        if (d->description)
            std::cout << " (" << d->description << ")";
        std::cout << std::endl;
    }

    // Selecionar dispositivo
    std::cout << "Selecione um dispositivo pelo número: ";
    
    int devNum;
    std::cin >> devNum;

    pcap_if_t *selectedDev = alldevs;
    for (int j = 1; j < devNum && selectedDev->next != nullptr; j++) {
        selectedDev = selectedDev->next;
    }

    if (!selectedDev) {
        std::cerr << "Dispositivo inválido." << std::endl;
        pcap_freealldevs(alldevs);
        return 1;
    }

    // Abrir o dispositivo para captura
    pcap_t *handle = pcap_open_live(selectedDev->name, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << "Erro ao abrir o dispositivo: " << errbuf << std::endl;
        pcap_freealldevs(alldevs);
        return 1;
    }

    std::cout << "Capturando pacotes em " << selectedDev->name << "..." << std::endl;

    // Capturar pacotes (loop infinito)
    pcap_loop(handle, 0, packetHandler, nullptr);

    // Encerrar
    pcap_close(handle);
    pcap_freealldevs(alldevs);
    return 0;
}
