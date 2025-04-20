#ifndef SPOOFER_H
#define SPOOFER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <pthread.h>

#define BUFFER_SIZE 1024
#define MAC_BROADCAST (uint8_t[6]){0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
#define ARP_PROTOCOL 0x0806
#define ARP_REQUEST 0x01
#define ARP_REPLY 0x02
#define SEND_TRIES 30
#define SEND_INTERVAL 500000 // 500ms
#define STR_FAKE_MAC "04:BF:1B:89:09:8A"

// General structs
typedef struct __attribute__((packed)) {
	uint8_t dest_mac[6];
	uint8_t src_mac[6];
	uint16_t ethertype;
} ethernet_header_t;

typedef struct __attribute__((packed)) {
	uint16_t hw_type;
	uint16_t proto_type;
	uint8_t hw_size;
	uint8_t proto_size;
	uint16_t opcode;
	uint8_t sender_mac[6];
	uint8_t sender_ip[4];
	uint8_t target_mac[6];
	uint8_t target_ip[4];
} arp_header_t;

//  Thread arguments
typedef struct {
	int sock_fd;
	unsigned int ifindex;
	uint8_t target_mac[6];
	uint8_t target_ip[4];
	uint8_t spoofed_ip[4];
	uint8_t spoofed_mac[6];
} thread_spoof_args_t;

// Functions

/**@brief Builds the custom arp reply packet
 *
 * @param packet Target struct to hold the custom packet
 * @param args Fields to contain in the custom packet
 */
void build_arp_packet(uint8_t *packet, thread_spoof_args_t *args);

/**@brief Sends TRIES_AMOUNT spoofed packets to target IP
 *
 * @param arg Fields of the custom packet
 * @return NULL
 */
void *spoof_thread(void *arg);

#endif //SPOOFER_H
