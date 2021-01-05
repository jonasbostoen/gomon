package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	// Gopacket parameters
	device      string = "eth0"
	snapshotLen int32  = 1024
	promiscuous bool   = false
	err         error
	timeout     time.Duration = pcap.BlockForever
	handle      *pcap.Handle

	// Layers to decode
	eth  layers.Ethernet
	ipv4 layers.IPv4
	ipv6 layers.IPv6
	tcp  layers.TCP
)

var (
	// Command line flags
	iface    = flag.String("i", "eth0", "Interface to listen on")
	protocol = flag.String("p", "", "Protocol filter")
	listDevs = flag.Bool("list-interfaces", false, "List available devices")
)

func main() {
	flag.Parse()

	if *listDevs {
		fmt.Println("Listing devices")
		GetDevices()
		os.Exit(0)
	}

	// Open the device
	handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	die(err, "Can't open device for capture")

	defer handle.Close()

	// Use handle as packet source to capture all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	TCPScan(packetSource, 0)
}

func die(err error, message string) {
	if err != nil {
		fmt.Println(message)
		log.Fatal(err)
	}
}
