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


#define MACHINE_MAX_NAME_LENGTH 20
#define MAXIMUM_MACHINES 50
#define CIDR 24
#define HOST_BITS 8

#define MAC_BROADCAST (uint8_t[6]){0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
#define FIRST_IP "192.168.1.1"
#define LAST_IP "192.168.1.254"

// Fields structs
typedef uint8_t mac_addr_t[6];

// General structs
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
	mac_addr_t sender_mac[6];
	ip_addr_t sender_ip[4];
	mac_addr_t target_mac[6];
	ip_addr_t target_ip[4];
} arp_header_t;


typedef struct __attribute__((packed)) {
	ethernet_header_t ethernet_header;
	arp_header_t arp_header;
}arp_packet_t;


// Struct to hold a description for a machine on the network
typedef struct {
	char name[MACHINE_MAX_NAME_LENGTH];
	mac_addr_t mac_addr;
	ip_addr_t ip_addr;
}host_t;


/** Scan the network for hosts
 *
 * @return A pointer to an array of all the hosts on the network
 */
host_t* scan_network_for_hosts();


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
arp_packet_t craft_arp_packet_for_ip(ip_addr_t ip_addr);

#endif //NETWORK_SCANNER_H
