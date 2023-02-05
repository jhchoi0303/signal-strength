#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <vector>
#include <string>
#include <cstring>
#include "radiotap.h"
#include "ieee80211.h"

void usage() {
	printf("syntax: signal-strength <interface>\n");
	printf("sample: signal-strength mon0 00:11:22:33:44:55\n");
}

typedef struct {
   char* dev_;
} Param;

Param param = {
   .dev_ = NULL
};




int main(int argc, char* argv[]) {
	if (3 != argc) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char *trans_mac = argv[2];

 
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev, errbuf);
        return -1;
  }

  MacAddr trans_macaddr;
  trans_macaddr.set_mac_addr(trans_mac);

while (true)
	{

		struct pcap_pkthdr *header;
		const u_char *packet;

		int res = pcap_next_ex(pcap, &header, &packet);

            if (res == 0) return -1;
	    if (res == -1 || res == -2) {
		    fprintf(stderr, "pcap_sendpacket return %d\n", res);
            break;
	    }


        radiotap_header* radio_hdr = (radiotap_header*)packet;
    	IEEE80211_beacon_frame* ieee_hdr = (IEEE80211_beacon_frame*)(packet+radio_hdr->len);




	
	    if ((ieee_hdr->subtype & 0b00001100 == 0b00001000) && (ieee_hdr->bss_id == trans_macaddr)) {
	            		
        printf("\nSignal_Strength\t\t\tdestination\t\tsource\t\tbssid\n");
            printf("%d\t\t\t",radio_hdr->signal-0xff);

            printf("\t\t");
            ieee_hdr->receiver_address.print_mac_addr();
            printf("\t\t");
            ieee_hdr->transmitter_address.print_mac_addr();
            printf("\t\t");
            ieee_hdr->bss_id.print_mac_addr();
            printf("\n");


	    } else if ((ieee_hdr->subtype & 0b00001100 == 0b00000000) && (ieee_hdr->transmitter_address == trans_macaddr)) {
	    printf("\nSignal_Strength\t\t\tdestination\t\tsource\t\tbssid\n");
            printf("%d\t\t\t",radio_hdr->signal-0xff);

            printf("\t\t");
            ieee_hdr->receiver_address.print_mac_addr();
            printf("\t\t");
            ieee_hdr->transmitter_address.print_mac_addr();
            printf("\t\t");
            ieee_hdr->bss_id.print_mac_addr();
            printf("\n");

	    }

    

	}
		pcap_close(pcap);  

  }