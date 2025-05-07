#include "network_scanner.h"

#include <stdlib.h>
#include <netinet/in.h>

#include "spoofer.h"
#include "config.h"

int num_hosts = 0;
host_t *hosts_array = NULL;

pthread_mutex_t num_hosts_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t hosts_array_mutex = PTHREAD_MUTEX_INITIALIZER;


// Update hosts
void* pthread_add_host(void* args) {
	pthread_mutex_lock(&num_hosts_mutex);
	pthread_mutex_lock(&hosts_array_mutex);
	printf("Thread created number of hosts %d\n", num_hosts);
	host_t host = *(host_t*) args;

	if (num_hosts == 0) {
		num_hosts++;
		snprintf(host.name, sizeof(host.name), "machine %d", num_hosts);
		printf("Trying to add host %s\n", host.name);


		hosts_array = malloc(sizeof(host_t) * (num_hosts));
		if (!hosts_array) {
			perror("malloc");
			pthread_mutex_unlock(&num_hosts_mutex);
			pthread_mutex_unlock(&hosts_array_mutex);
			return NULL;
		}
	}
	else {
		num_hosts++;
		snprintf(host.name, sizeof(host.name), "machine %d", num_hosts);
		printf("Trying to add host %s\n", host.name);

		// Reallocate and store the new host
		hosts_array = realloc(hosts_array, sizeof(host_t) * (num_hosts));
		if (!hosts_array) {
			perror("realloc");
			pthread_mutex_unlock(&num_hosts_mutex);
			pthread_mutex_unlock(&hosts_array_mutex);
			return NULL;
		}
	}

	// Save to array
	hosts_array[num_hosts - 1] = host;
	printf("Added host %s\n", host.name);

	pthread_mutex_unlock(&num_hosts_mutex);
	pthread_mutex_unlock(&hosts_array_mutex);
	return NULL;
}


// Sender thread
void* thread_send_arp_req() {
	int sock_fd = create_raw_socket(ETH_P_ALL);

	if (sock_fd == -1) {
		perror("create_raw_socket");
		return NULL;
	}

	struct in_addr first_ip, last_ip, current_ip;

	inet_aton(FIRST_IP, &first_ip);
	inet_aton(LAST_IP, &last_ip);

	// Loop through IPs
	printf("Starting scan\n");


	for (uint32_t ip = ntohl(first_ip.s_addr); ip <= ntohl(last_ip.s_addr); ip++) {
		// Get current IP
		current_ip.s_addr = htonl(ip);
		uint32_t curr_ip = current_ip.s_addr;

		char str_ip[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &current_ip.s_addr , str_ip, INET_ADDRSTRLEN);

		// Craft the arp packet
		uint8_t *arp_bytes = malloc(ARP_PACKET_LEN);
		if (arp_bytes == NULL) {
			perror("malloc");
			return NULL;
		}

		craft_arp_req_for_ip(curr_ip, arp_bytes); // Request

		/*// Print raw
		printf("ARP Packet Bytes:\n");
		for (int i = 0; i < ARP_PACKET_LEN; i++) {
			printf("%02x ", arp_bytes[i]);
			if ((i + 1) % 16 == 0) printf("\n");
		}
		printf("\n");*/

		// Send arp packet
		struct sockaddr_ll sa = {0};
		sa.sll_ifindex = if_nametoindex("wlp2s0");
		sa.sll_halen = ETH_ALEN;
		memcpy(sa.sll_addr, MAC_BROADCAST, 6);

		ssize_t sent = sendto(sock_fd, arp_bytes, ARP_PACKET_LEN, 0, (struct sockaddr *)&sa, sizeof(sa));
		if (sent == -1) {
			perror("sendto failed");
			free(arp_bytes);
			continue; // skip to next IP
		}

		free(arp_bytes);
		printf("ARP request sent to %s\n", str_ip);
	}
}

// Recciever thread
void* thread_listen_for_arp_req() {
	int sock_fd = create_raw_socket(ETH_P_ARP);
	if (sock_fd == -1) {
		perror("create_raw_socket");
		return NULL;
	}

	pthread_t add_host_thread;

	struct in_addr first_ip, last_ip, current_ip;

	inet_aton(FIRST_IP, &first_ip);
	inet_aton(LAST_IP, &last_ip);

	// Loop through IPs
	printf("Starting scan\n");
	sleep(1);

	while (1) {
		uint8_t buffer[ARP_PACKET_LEN];
		ssize_t len = recv(sock_fd, buffer, sizeof(buffer), 0);
		if (len <= 0) continue;

		struct ether_header *eth = (struct ether_header *)buffer;
		if (ntohs(eth->ether_type) != ETHERTYPE_ARP)
			continue;  // skip non-ARP packets

		struct ether_arp *arp = (struct ether_arp *)(buffer + ETH_HDR_LEN);

		if (is_arp_rep(arp)) {
			host_t args;
			memcpy(&args.ip_addr, arp->arp_spa, 4);
			memcpy(&args.mac_addr, arp->arp_sha, ETH_ALEN);

			struct in_addr addr;
			addr.s_addr = args.ip_addr;
			printf("Got ARP reply from %s\n", inet_ntoa(addr));

			// Call add_host thread
			if (pthread_create(&add_host_thread, NULL, pthread_add_host, &args) != 0) {
				perror("pthread_create failed");
				return NULL;
			}

		}
	}
	return hosts_array;
}

int is_arp_rep(struct ether_arp *arp) {
	if (!arp) return 0;

	// Check if opcode is ARP reply
	return ntohs(arp->ea_hdr.ar_op) == ARP_REPLY;
}

// returns the sender ip from an arp packet
uint32_t get_src_from_arp(const arp_packet_t pkt) {
	return ntohl(pkt.arp.sender_ip);
}

// ----COMPLETE FUNCTION

void scan_network_for_hosts() {

	pthread_t recv_thread, send_thread;

	// Call arp recv thread
	if (pthread_create(&recv_thread, NULL, thread_listen_for_arp_req, NULL) != 0) {
		perror("pthread_create failed");
		return;
	}

	// Call arp send thread
	if (pthread_create(&send_thread, NULL, thread_send_arp_req, NULL) != 0) {
		perror("pthread_create failed");
		return;
	}
}

// ----COMPLETE FUNCTION

void craft_arp_req_for_ip(in_addr_t target_ip, uint8_t* buf) {
	if (!buf) return;

	// === Ethernet Header ===
	struct ether_header *eth = (struct ether_header *)buf;
	memcpy(eth->ether_dhost, MAC_BROADCAST, 6);
	memcpy(eth->ether_shost, LOCAL_MAC_HEX, 6);
	eth->ether_type = htons(ETHERTYPE_ARP);

	// === ARP Header ===
	struct ether_arp *arp = (struct ether_arp *)(buf + ETH_HDR_LEN);
	arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);     // Ethernet
	arp->ea_hdr.ar_pro = htons(ETHERTYPE_IP);     // IPv4
	arp->ea_hdr.ar_hln = 6;                        // MAC length
	arp->ea_hdr.ar_pln = 4;                        // IPv4 length
	arp->ea_hdr.ar_op = htons(ARP_REQUEST);       // ARP request

	memcpy(arp->arp_sha, LOCAL_MAC_HEX, 6);        // Sender MAC
	memcpy(arp->arp_spa, LOCAL_IP, 4);             // Sender IP
	memset(arp->arp_tha, 0x00, 6);                 // Target MAC (unknown)
	memcpy(arp->arp_tpa, &target_ip, 4);           // Target IP
}

int create_raw_socket(int protocol) {
	int sock_fd = socket(AF_PACKET, SOCK_RAW, htons(protocol));
	if (sock_fd == -1) {
		perror("socket");
		return -1;
	}

	return sock_fd;
}