#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
//#include <linux/bpf.h>
//#include <bpf/libbpf.h>
#include <linux/if_ether.h>  // For ETH_ALEN
#include <netinet/in.h>
#include <string.h>

// Define the same structure as in your BPF program.
struct packet_info {
    unsigned char src_mac[ETH_ALEN];
    __u8 ip_proto;
};

int main(void)
{
    // Open the pinned map (adjust the path if necessary)
    int map_fd = bpf_obj_get("/sys/fs/bpf/packet_dict");
    if (map_fd < 0) {
        perror("bpf_obj_get");
        return 1;
    }

    __u32 key, next_key;
    struct packet_info info;
    char ip_str[INET_ADDRSTRLEN];
    char mac_str[18];  // Format: "xx:xx:xx:xx:xx:xx"

    // Get the first key by passing NULL as the key pointer
    if (bpf_map_get_next_key(map_fd, NULL, &key) != 0) {
        printf("No keys in map\n");
        return 0;
    }

    // Loop over the keys in the map
    do {
        if (bpf_map_lookup_elem(map_fd, &key, &info) == 0) {
            // Convert the key (source IP) to dotted-decimal string.
            struct in_addr addr;
            addr.s_addr = key;  // May need ntohl() if stored in network order.
            inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));

            // Format the MAC address as "xx:xx:xx:xx:xx:xx".
            snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                     info.src_mac[0], info.src_mac[1], info.src_mac[2],
                     info.src_mac[3], info.src_mac[4], info.src_mac[5]);

            // Print the source IP, MAC, and IP protocol.
            printf("Source IP: %s, MAC: %s, Protocol: %u\n", ip_str, mac_str, info.ip_proto);
        } else {
            perror("bpf_map_lookup_elem");
        }
    } while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0 && (key = next_key, 1));
