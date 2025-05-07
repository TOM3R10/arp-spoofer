#ifndef NETWORK_SCANNER_H
#define NETWORK_SCANNER_H

#include <stdint.h>
#include <sys/socket.h>
#include <stdio.h>
#include <net/ethernet.h>
#include <string.h>
#include <math.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#include "spoofer.h"


#define MACHINE_MAX_NAME_LENGTH 20
#define MAXIMUM_MACHINES 50
#define CIDR 24
#define HOST_BITS 8
#define ETH_HDR_LEN 14
#define ARP_HDR_LEN 28
#define ARP_PACKET_LEN (ETH_HDR_LEN + ARP_HDR_LEN)

#define MAC_BROADCAST (uint8_t[6]){0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
#define FIRST_IP "192.168.1.1"
#define LAST_IP "192.168.1.254"

// Fields structs
typedef uint8_t mac_addr_t[6];

// General structs
typedef uint8_t mac_addr_t[6];

typedef struct __attribute__((packed)) {
	mac_addr_t dest_mac;
	mac_addr_t src_mac;
	uint16_t ethertype;
} ethernet_header_t;

typedef struct __attribute__((packed)) {
	uint16_t hw_type;
	uint16_t proto_type;
	uint8_t hw_size;
	uint8_t proto_size;
	uint16_t opcode;
	mac_addr_t sender_mac;
	uint32_t sender_ip;
	mac_addr_t target_mac;
	uint32_t target_ip;
} arp_header_t;

typedef struct __attribute__((packed)) {
	ethernet_header_t eth;
	arp_header_t arp;
} arp_packet_t;



// Struct to hold a description for a machine on the network
typedef struct {
	char name[MACHINE_MAX_NAME_LENGTH];
	mac_addr_t mac_addr;
	uint32_t ip_addr;
}host_t;

extern int num_hosts;
extern host_t* hosts_array;

extern pthread_mutex_t num_hosts_mutex;
extern pthread_mutex_t hosts_array_mutex;

/** Scan the network for hosts
 *	Call recv_thread and send_thread
 *
 */
void scan_network_for_hosts();


/** Creates a raw socket
 *
 * @param protocol Defines the protocol
 * @return Socket fd
 */
int create_raw_socket(int protocol);


/** Get the router information
 *
 * @return A struct containing the router information
 */
host_t get_router_information();


/** Craft an arp request packet for a given IP
 *
 * @param ip_addr An IP address
 * @return A crafted arp request packet for a given IP
 */
void craft_arp_req_for_ip(in_addr_t ip_addr, uint8_t* buf);

int  is_arp_rep(struct ether_arp *arp);

#endif //NETWORK_SCANNER_H
