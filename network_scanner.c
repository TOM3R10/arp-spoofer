#include "network_scanner.h"

#include <stdlib.h>
#include <netinet/in.h>

#include "spoofer.h"


// ----COMPLETE FUNCTION

host_t* scan_network_for_hosts() {
	int num_of_hosts = 0;
	host_t *hosts_array;

	struct in_addr first_ip, last_ip, current_ip;

	int sock_fd = create_raw_socket(ETH_P_ALL);
	if (sock_fd == -1) {
		perror("create_raw_socket");
		return NULL;
	}

	inet_aton(FIRST_IP, &first_ip);
	inet_aton(LAST_IP, &last_ip);

	// Loop through IPs
	for (uint32_t ip = ntohl(first_ip.s_addr); ip <= ntohl(last_ip.s_addr); ip++) {

		// Get current IP
		current_ip.s_addr = htonl(ip);
		in_addr_t curr_ip = current_ip.s_addr;

		// Craft the arp packet
		arp_packet_t arp_packet = craft_arp_packet_for_ip(curr_ip);

		// Send arp packet
		if (!send(sock_fd, &arp_packet, sizeof(arp_packet_t), 0)) {
			return NULL;
		}

		// Listen for arp reply
		listen(sock_fd, )

		// If arp reply recieved store in hosts_array

		// Else, continue;;

	}


	return hosts_array;
}

// ----COMPLETE FUNCTION

arp_packet_t craft_arp_packet_for_ip(ip_addr_t ip_addr) {
	arp_packet_t packet;

	ethernet_header_t eth;
	arp_header_t arp;

	memcpy(eth.dest_mac, MAC_BROADCAST, 6);
	memcpy(eth.src_mac, , 6);
	eth.ethertype = htons(ETH_P_ARP);

	arp.hw_type = htons(1);
	arp.proto_type = htons(0x0800);
	arp.hw_size = 6;
	arp.proto_size = 4;
	arp.opcode = htons(ARP_REQUEST);
	memcpy(arp.sender_mac, args->spoofed_mac, 6);
	memcpy(arp.sender_ip, args->spoofed_ip, 4);
	memcpy(arp.target_mac, args->target_mac, 6);
	memcpy(arp.target_ip, args->target_ip, 4);

	return NULL;
}

int create_raw_socket(int protocol) {
	int sock_fd = socket(AF_PACKET, SOCK_RAW, htons(protocol));
	if (sock_fd == -1) {
		perror("socket");
		return -1;
	}

	return sock_fd;
}
