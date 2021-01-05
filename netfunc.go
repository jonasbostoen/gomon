package main

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// PrintPacketInfo is
func PrintPacketInfo(packet gopacket.Packet) {
	// Check if packet is ethernet
	ethernet := packet.Layer(layers.LayerTypeEthernet)
	if ethernet != nil {
		fmt.Println("Ethernet Info===========================")
		ethernetPacket, _ := ethernet.(*layers.Ethernet)
		fmt.Println("Source MAC:", ethernetPacket.SrcMAC)
		fmt.Println("Destination MAC:", ethernetPacket.DstMAC)
		fmt.Println()
	}

	ipv4 := packet.Layer(layers.LayerTypeIPv4)
	if ipv4 != nil {
		fmt.Println("IPv4 Info===============================")
		ipv4Packet, _ := ipv4.(*layers.IPv4)
		fmt.Println("Source IP:", ipv4Packet.SrcIP)
		fmt.Println("Destination IP:", ipv4Packet.DstIP)
		fmt.Println("Protocol:", ipv4Packet.Protocol)
		fmt.Println()
	}
}

// TCPScan is the fastest scanner, since it reuses memory to store packets
// 0 for ad infinitum
func TCPScan(source *gopacket.PacketSource, max int) {
	pcount := 0
	for packet := range source.Packets() {
		parser := gopacket.NewDecodingLayerParser(
			layers.LayerTypeEthernet,
			&eth,
			&ipv4,
			&ipv6,
			&tcp,
		)
		decoded := []gopacket.LayerType{}

		// NOTE: this will always return an error, since it
		// only knows how to decode TCP (up to TCP/IP layer 3)
		parser.DecodeLayers(packet.Data(), &decoded)

		for _, layerType := range decoded {
			switch layerType {
			case layers.LayerTypeEthernet:
				fmt.Printf("Ethernet: %s -> %s\n", eth.SrcMAC, eth.DstMAC)
			case layers.LayerTypeIPv4:
				fmt.Printf("IPv4: %s -> %s\n", ipv4.SrcIP, ipv4.DstIP)
			case layers.LayerTypeIPv6:
				fmt.Printf("IPv6: %s -> %s\n", ipv6.SrcIP, ipv6.DstIP)
			case layers.LayerTypeTCP:
				fmt.Printf("TCP: %d -> %d\n", tcp.SrcPort, tcp.DstPort)
			default:
				fmt.Println(layerType)
			}
		}
		if max != 0 {
			pcount++

			if pcount >= max {
				break
			}
		}
	}
}

// GetDevices gets all devices
func GetDevices() {
	devices, err := pcap.FindAllDevs()
	die(err, "Problem finding devices")

	for _, dev := range devices {
		if addrs := dev.Addresses; len(addrs) > 0 {
			fmt.Println(dev.Name)
			for _, addr := range addrs {
				fmt.Println("\t", addr.IP)
			}
		}
	}
}
