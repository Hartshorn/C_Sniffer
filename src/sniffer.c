#include "../include/sniffer.h"

void show_devicelist_info(pcap_if_t *alldevices) {
    
    pcap_if_t *device;
    int i = 0;
    
    for (device = alldevices; device; device=device->next)
    {
        show_device_info(device, ++i);
    }
}

void show_device_info(pcap_if_t *device, int num) {
    
    fprintf(stdout, "%d: %s\n", num, device->name);

    if(device->description) {
        fprintf(stdout, " (%s)\n", device->description);
    } else {
        fprintf(stdout, " (No description)\n");
    }
}

pcap_if_t* interface_handler(pcap_if_t *alldevices, unsigned char *errbuf) {
    int i, interface_num;
    pcap_if_t *device;
    
    if (pcap_findalldevs(&alldevices, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
    }
    
    fprintf(stdout, "Available Interfaces:\n");
    show_devicelist_info(alldevices);
    fprintf(stdout, "\n");
    
    fprintf(stdout, "Enter the interface to use: ");
    scanf("%d", &interface_num);
    for (device = alldevices, i = 0; i < interface_num - 1; device = device->next, i++);
    
    fprintf(stdout, "\nUsing: \n");
    show_device_info(device, interface_num);
    fprintf(stdout, "\n");
    
    return device;
}
