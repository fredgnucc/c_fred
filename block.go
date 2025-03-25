zorro@routerKubecp0001:~/go-ebpf-demo/block$ cat main.go
package main

import (
        "encoding/binary"
        "flag"
        "fmt"
        "log"
        "net"
        "github.com/cilium/ebpf"
)

func main() {
        // Define command-line flags.
        action := flag.String("action", "", "add or remove")
        ipStr := flag.String("ip", "", "give ip")
        flag.Parse()

        // Validate flags.
        if *action != "add" && *action != "remove" {
                log.Fatalf("Invalid action. Use -action add or -action remove")
        }
        if *ipStr == "" {
                log.Fatalf("Please provide an IP address using -ip flag")
        }

        // Parse the IP address.
        ip := net.ParseIP(*ipStr).To4()
        if ip == nil {
                log.Fatalf("Invalid IPv4 address: %s", *ipStr)
        }

        // Our eBPF program stores the key as __u32.
        // On a little-endian machine, the raw 4 bytes are interpreted in little-endian order.
        key := binary.LittleEndian.Uint32(ip)
        fmt.Printf("Computed key: %d (0x%x) for IP: %s\n", key, key, ip.String())

        // Load the pinned block_list map.
        m, err := ebpf.LoadPinnedMap("/sys/fs/bpf/block_list", nil)
        if err != nil {
                log.Fatalf("Failed to load pinned map: %v", err)
        }
        defer m.Close()

        // Perform the action.
        if *action == "add" {
                var value uint8 = 1
                if err := m.Update(&key, &value, ebpf.UpdateAny); err != nil {
                        log.Fatalf("Failed to add IP %s to block_list: %v", *ipStr, err)
                }
                fmt.Printf("IP %s added to block_list\n", *ipStr)
        } else if *action == "remove" {
                if err := m.Delete(&key); err != nil {
                        log.Fatalf("Failed to remove IP %s from block_list: %v", *ipStr, err)
                }
                fmt.Printf("IP %s removed from block_list\n", *ipStr)
        }
}
