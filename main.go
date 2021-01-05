package main

import (
	"fmt"
	"log"

	"github.com/google/gopacket/pcap"
)

func main() {
	// Find all devices
	devices, err := pcap.FindAllDevs()
	die(err)

	fmt.Println("Devices found:")
	for _, dev := range devices {
		fmt.Println(dev.Name)
		for _, addr := range dev.Addresses {
			fmt.Println("\t", addr.IP)
			fmt.Println("\t", addr.Netmask)
		}
	}
}

func die(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
