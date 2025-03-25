zorro@routerKubecp0001:~/xdp_prog$ cat xdp_power.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

// Define a struct to hold packet metadata.
struct packet_info {
    unsigned char src_mac[ETH_ALEN]; // Source MAC address from the Ethernet header.
    __u8 ip_proto;                   // Protocol from the IP header.
};

// This map holds per-packet info keyed by the source IP.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);                // Source IP as the key.
    __type(value, struct packet_info); // Packet information as the value.
    __uint(max_entries, 256);
} packet_dict SEC(".maps");

// New: Block list map.
// The key is the IP address (as __u32) that should be blocked.
// The value can be a dummy value (for example, an 8-bit flag) if needed.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);  // IP to block.
    __type(value, __u8); // A flag (e.g., 1 means block).
    __uint(max_entries, 256);
} block_list SEC(".maps");

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Parse Ethernet header.
    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return XDP_PASS;

    // Only handle IPv4 packets.
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    // Parse IP header.
    struct iphdr *ip = data + sizeof(*eth);
    if ((void*)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = ip->saddr;

    // Check if this source IP is in the block list.
    __u8 *block = bpf_map_lookup_elem(&block_list, &src_ip);
    if (block) {
        // If the IP exists in the block list, drop the packet.
        return XDP_DROP;
    }

    // Otherwise, proceed to update the packet_dict map.
    struct packet_info info = {};

    // Copy source MAC from Ethernet header.
    __builtin_memcpy(info.src_mac, eth->h_source, ETH_ALEN);
    // Save IP protocol field.
    info.ip_proto = ip->protocol;

    // Update or add this entry to the packet_dict map.
    bpf_map_update_elem(&packet_dict, &src_ip, &info, BPF_ANY);

    return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";
