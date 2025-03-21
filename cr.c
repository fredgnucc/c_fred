#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>         // for htons(), inet_pton()
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>            // for if_nametoindex()
#include <linux/if_link.h>     // for ifinfomsg, IFLA_LINKINFO, etc.
#include <linux/if_arp.h>      // for ARPHRD_ETHER


// VXLAN constants.
#define VXLAN_ID 42
#define VXLAN_PORT 4789

// Default VXLAN interface name if needed.
#define DEFAULT_VXLAN_IF "vxlan0"

// ---------------------------------------------------------------------------
// send_netlink_request: Sends the Netlink message using sendmsg().
void send_netlink_request(int sockfd, struct nlmsghdr *nlh) {
    struct sockaddr_nl addr;
    struct iovec iov = { nlh, nlh->nlmsg_len };
    struct msghdr msg;

    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &addr;
    msg.msg_namelen = sizeof(addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    printf("[DEBUG] Sending Netlink request...\n");
    if (sendmsg(sockfd, &msg, 0) < 0) {
        perror("[ERROR] sendmsg");
        exit(EXIT_FAILURE);
    }
    printf("[DEBUG] Netlink request sent successfully.\n");
}
// Converts a buffer to a hex string and prints it.
void print_netlink_message(struct nlmsghdr *nlh) {
    unsigned char *ptr = (unsigned char *) nlh;
    int total = nlh->nlmsg_len;
    int i, pos = 0;
    // Allocate a buffer to hold the hex string.
    // Each byte becomes two hex digits plus a space (3 characters per byte).
    // Adjust the size if needed.
    char hex_str[total * 3 + 1];
    memset(hex_str, 0, sizeof(hex_str));

    for (i = 0; i < total; i++) {
        pos += snprintf(hex_str + pos, sizeof(hex_str) - pos, "%02x ", ptr[i]);
    }
    printf("[DEBUG] Netlink message as hex string:\n%s\n", hex_str);
}




// ---------------------------------------------------------------------------
// receive_netlink_response: Receives a Netlink response.
// If no response is received within timeout, a debug message is printed.
void receive_netlink_response(int sockfd) {
    char buffer[4096];
    struct iovec iov = { buffer, sizeof(buffer) };
    struct sockaddr_nl addr;
    struct msghdr msg;

    memset(&addr, 0, sizeof(addr));
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &addr;
    msg.msg_namelen = sizeof(addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    ssize_t recv_len = recvmsg(sockfd, &msg, 0);
    if (recv_len < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            printf("[DEBUG] No netlink response received within timeout (this may be normal for interface creation).\n");
            return;
        }
        perror("[ERROR] recvmsg");
        exit(EXIT_FAILURE);
    }

    struct nlmsghdr *nlh = (struct nlmsghdr *)buffer;
    if (nlh->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nlh);
        if (err->error != 0) {
            printf("[ERROR] Netlink response: %s\n", strerror(-err->error));
            exit(EXIT_FAILURE);
        } else {
            printf("[DEBUG] Netlink request succeeded (error code 0).\n");
        }
    } else {
        printf("[DEBUG] Received Netlink response of type %d.\n", nlh->nlmsg_type);
    }
}

// ---------------------------------------------------------------------------
// create_vxlan_interface: Creates a VXLAN interface using a Netlink RTM_NEWLINK message.
// 'parent_if' is the parent interface (e.g., "dummy0") and 'vxlan_if' is the desired VXLAN name.
void create_vxlan_interface(int sockfd, const char *parent_if, const char *vxlan_if) {
    struct {
        struct nlmsghdr nlh;
        struct ifinfomsg ifi;
        char buf[4096];  // Buffer for nested attributes.
    } req;
    memset(&req, 0, sizeof(req));

    // --- Top-level Netlink header ---
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    req.nlh.nlmsg_type = RTM_NEWLINK;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;

    // --- ifinfomsg: Set basic interface properties ---
    req.ifi.ifi_family = AF_UNSPEC;       // Allows both IPv4 & IPv6.
    req.ifi.ifi_type = ARPHRD_ETHER;        // Ethernet-like interface.
    req.ifi.ifi_flags = IFF_UP;             // Bring the interface up.
    req.ifi.ifi_change = 0xFFFFFFFF;        // Allow all flag changes.

    // --- Build Nested Attributes ---
    int attrlen = 0;
    char *attrbuf = req.buf;

    // 1. IFLA_IFNAME: Set the new interface name.
    struct rtattr *rta = (struct rtattr *)(attrbuf + attrlen);
    rta->rta_type = IFLA_IFNAME;
    rta->rta_len = RTA_LENGTH(strlen(vxlan_if) + 1);
    strcpy((char *)RTA_DATA(rta), vxlan_if);
    attrlen += RTA_ALIGN(rta->rta_len);

    // 2. IFLA_LINKINFO: Begin nested block.
    int linkinfo_start = attrlen;
    struct rtattr *linkinfo = (struct rtattr *)(attrbuf + attrlen);
    linkinfo->rta_type = IFLA_LINKINFO;
    linkinfo->rta_len = RTA_LENGTH(0);  // Placeholder.
    attrlen += RTA_ALIGN(linkinfo->rta_len);

    // 2a. IFLA_INFO_KIND: Specify "vxlan".
    struct rtattr *info_kind = (struct rtattr *)(attrbuf + attrlen);
    info_kind->rta_type = IFLA_INFO_KIND;
    info_kind->rta_len = RTA_LENGTH(strlen("vxlan") + 1);
    strcpy((char *)RTA_DATA(info_kind), "vxlan");
    attrlen += RTA_ALIGN(info_kind->rta_len);

    // 2b. IFLA_INFO_DATA: Begin nested block for VXLAN parameters.
    int info_data_start = attrlen;
    struct rtattr *info_data = (struct rtattr *)(attrbuf + attrlen);
    info_data->rta_type = IFLA_INFO_DATA;
    info_data->rta_len = RTA_LENGTH(0);  // Placeholder.
    attrlen += RTA_ALIGN(info_data->rta_len);

    // 2b(i). IFLA_VXLAN_LINK: Parent interface index.
    struct rtattr *vxlan_link = (struct rtattr *)(attrbuf + attrlen);
    vxlan_link->rta_type = IFLA_VXLAN_LINK;
    vxlan_link->rta_len = RTA_LENGTH(sizeof(int));
    *(int *)RTA_DATA(vxlan_link) = if_nametoindex(parent_if);
    attrlen += RTA_ALIGN(vxlan_link->rta_len);

    // 2b(ii). IFLA_VXLAN_ID: VXLAN Network Identifier.
    struct rtattr *vxlan_id = (struct rtattr *)(attrbuf + attrlen);
    vxlan_id->rta_type = IFLA_VXLAN_ID;
    vxlan_id->rta_len = RTA_LENGTH(sizeof(__u32));
    *(__u32 *)RTA_DATA(vxlan_id) = VXLAN_ID;  // You might use htonl(VXLAN_ID) if needed.
    attrlen += RTA_ALIGN(vxlan_id->rta_len);

    // 2b(iii). IFLA_VXLAN_PORT: VXLAN UDP port.
    struct rtattr *vxlan_port = (struct rtattr *)(attrbuf + attrlen);
    vxlan_port->rta_type = IFLA_VXLAN_PORT;
    vxlan_port->rta_len = RTA_LENGTH(sizeof(__u16));
    *(__u16 *)RTA_DATA(vxlan_port) = htons(VXLAN_PORT);
    attrlen += RTA_ALIGN(vxlan_port->rta_len);

    // Update the lengths of nested blocks.
    info_data->rta_len = attrlen - info_data_start;
    linkinfo->rta_len = attrlen - linkinfo_start;
    req.nlh.nlmsg_len += attrlen;
    printf("[DEBUG] Total Netlink message length: %d\n", req.nlh.nlmsg_len);
    print_netlink_message(&req.nlh);
    send_netlink_request(sockfd, &req.nlh);
    receive_netlink_response(sockfd);
}

// ---------------------------------------------------------------------------
// assign_ip_address: Assigns an IPv4 address to an interface using RTM_NEWADDR.
void assign_ip_address(int sockfd, const char *ifname, const char *ip_addr, int prefixlen) {
    struct {
        struct nlmsghdr nlh;
        struct ifaddrmsg ifa;
        char buf[4096];  // Buffer for nested attributes.
    } req;
    memset(&req, 0, sizeof(req));

    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
    req.nlh.nlmsg_type = RTM_NEWADDR;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE;

    req.ifa.ifa_family = AF_INET;
    req.ifa.ifa_index = if_nametoindex(ifname);
    if (req.ifa.ifa_index == 0) {
        fprintf(stderr, "Interface %s not found.\n", ifname);
        exit(EXIT_FAILURE);
    }
    req.ifa.ifa_prefixlen = prefixlen;
    req.ifa.ifa_scope = 0;
    req.ifa.ifa_flags = 0;

    int attrlen = 0;
    char *attrbuf = req.buf;

    // IFA_LOCAL: The IP address to assign.
    struct rtattr *rta = (struct rtattr *)(attrbuf + attrlen);
    rta->rta_type = IFA_LOCAL;
    rta->rta_len = RTA_LENGTH(4);  // IPv4 address is 4 bytes.

    struct in_addr addr;
    if (inet_pton(AF_INET, ip_addr, &addr) != 1) {
        perror("inet_pton");
        exit(EXIT_FAILURE);
    }
    memcpy(RTA_DATA(rta), &addr, 4);

    attrlen += RTA_ALIGN(rta->rta_len);
    req.nlh.nlmsg_len += attrlen;

    send_netlink_request(sockfd, &req.nlh);
    receive_netlink_response(sockfd);
}

// ---------------------------------------------------------------------------
// read_config_file: Reads a configuration file where each line has the format:
// vxlan_if::parent_if::ip_addr/prefix
void read_config_file(const char *filename, int sockfd) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    char *line = NULL;
    size_t len = 0;
    ssize_t nread;

    while ((nread = getline(&line, &len, fp)) != -1) {
        // Remove newline character if present.
        if (line[nread - 1] == '\n') {
            line[nread - 1] = '\0';
        }

        // Parse the line. Expected format: vxlan_if::parent_if::ip_addr/prefix
        char *vxlan_if = strtok(line, "::");
        if (!vxlan_if) continue;
        char *parent_if = strtok(NULL, "::");
        if (!parent_if) continue;
        char *ip_and_prefix = strtok(NULL, "::");
        if (!ip_and_prefix) continue;

        // Parse ip address and prefix from the string "ip_addr/prefix"
        char *ip_addr = strtok(ip_and_prefix, "/");
        char *prefix_str = strtok(NULL, "/");
        if (!ip_addr || !prefix_str) {
            fprintf(stderr, "Invalid IP address format: %s\n", ip_and_prefix);
            continue;
        }
        int prefix = atoi(prefix_str);

        printf("[DEBUG] Config: vxlan_if=%s, parent_if=%s, ip_addr=%s, prefix=%d\n",
               vxlan_if, parent_if, ip_addr, prefix);

        // Check if the VXLAN interface already exists.
        if (if_nametoindex(vxlan_if) != 0) {
            printf("[DEBUG] Interface %s already exists. Skipping creation.\n", vxlan_if);
        } else {
            // Create the VXLAN interface.
            create_vxlan_interface(sockfd, parent_if, vxlan_if);
            assign_ip_address(sockfd, vxlan_if, ip_addr, prefix);
        }

    }

    free(line);
    fclose(fp);
}

// ---------------------------------------------------------------------------
// Main function: Reads configuration from a file and creates interfaces accordingly.
int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <config_file>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *config_file = argv[1];
    int sockfd;
    struct sockaddr_nl addr;
    struct timeval tv;

    // Create a Netlink socket.
    sockfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sockfd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    printf("[DEBUG] Socket file descriptor: %d\n", sockfd);

    // Set a 5-second receive timeout.
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("setsockopt");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_pid = getpid();
    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // Read the configuration file and process each line.
    read_config_file(config_file, sockfd);

    printf("[DEBUG] Done processing config file. Verify interfaces with: ip addr show\n");

    // Optionally, sleep for a bit so you can inspect the created interfaces.
    sleep(10);

    close(sockfd);
    return 0;
}
