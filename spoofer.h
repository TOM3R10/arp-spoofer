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

#include "network_scanner.h"

#define BUFFER_SIZE 1024
#define ARP_PROTOCOL 0x0806
#define ARP_REQUEST 0x01
#define ARP_REPLY 0x02
#define SEND_TRIES 30
#define SEND_INTERVAL 500000 // 500ms
#define STR_FAKE_MAC "04:BF:1B:89:09:8A"


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
