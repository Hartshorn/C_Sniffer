#include "../include/sniffer.h"

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);


int main(int argc, char** argv) {

    int tcp = 0, udp = 0, icmp = 0, igmp = 0, others = 0, total = 0, i, j;
    
    unsigned int res;
    unsigned char errbuf[PCAP_ERRBUF_SIZE], buffer[100];
    const u_char *pkt_data;
    char hex[2];
    pcap_if_t *alldevices, *device;
    pcap_t *adhandle;
    time_t seconds;
    const time_t tbreak;
    
    
    struct ethernet_header *ethhdr;
    struct pcap_pkthdr *header;
    
    device = interface_handler(alldevices, errbuf);
    
    if ((adhandle = pcap_open_live(device->name,
                                65536,                      //100,
                                1,                          //PCAP_OPENFLAG_PROMISCUOUS,
                                2000,                       //20,
                                errbuf)) == NULL) 
    {
        fprintf(stderr, "\nError opening adapter\n");
        return (EXIT_FAILURE);
    }
    
    
    fprintf(stdout, "\nlistening on %s...\n", device->description);
    
    pcap_loop(adhandle, 0, packet_handler, NULL);
    
    pcap_freealldevs(alldevices);
    pcap_close(adhandle);
    
    return (EXIT_SUCCESS);
}


void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
    
    struct tm *ltime;
    char timestr[16];
    time_t local_tv_sec;
    int n;
    
    (void) (param);
    (void) (pkt_data);
    
    local_tv_sec = header->ts.tv_sec;
    ltime = localtime(&local_tv_sec);
    strftime(timestr, sizeof(timestr), "%I:%M:%S", ltime);
    
    fprintf(stdout, "%s, %.6d len:%d caplen:%d\n", 
            timestr, header->ts.tv_usec, header->len, header->caplen);
    
    for (int i = 0; i < (header->caplen > 113 ? 113 : header->caplen + 1); i++) {
        
        fprintf(stdout, "%.2x", pkt_data[i]);
        
        n = i + 1;
        
        if((n % LINE_LEN) == 0) {
            fprintf(stdout, "\n");
        } else if((n % 4) == 0) {
            fprintf(stdout, "  ");
        } else {
            fprintf(stdout, " ");
        }
    }
    fprintf(stdout, "\n\n");
}
